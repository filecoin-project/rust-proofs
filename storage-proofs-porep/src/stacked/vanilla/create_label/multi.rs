use std::convert::TryInto;
use std::marker::PhantomData;
use std::mem::{self, size_of};
use std::sync::{
    atomic::{AtomicU64, Ordering::SeqCst},
    Arc, MutexGuard,
};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use byte_slice_cast::{AsByteSlice, AsMutSliceOf};
use filecoin_hashers::Hasher;
use generic_array::{
    typenum::{Unsigned, U64},
    GenericArray,
};
use log::{debug, info};
use mapr::MmapMut;
use merkletree::store::{DiskStore, Store, StoreConfig};
use storage_proofs_core::{
    api_version::ApiVersion,
    cache_key::CacheKey,
    drgraph::{Graph, BASE_DEGREE},
    merkle::MerkleTreeTrait,
    settings::SETTINGS,
    util::NODE_SIZE,
};

use crate::stacked::vanilla::{
    cache::ParentCache,
    cores::{bind_core, checkout_core_group, CoreIndex},
    create_label::{prepare_layers, read_layer, write_layer},
    graph::{StackedBucketGraph, DEGREE, EXP_DEGREE},
    memory_handling::{setup_create_label_memory, CacheReader},
    params::{Labels, LabelsCache},
    proof::LayerState,
    utils::{memset, prepare_block, BitMask, RingBuf, UnsafeSlice},
};

const MIN_BASE_PARENT_NODE: u64 = 2000;

const NODE_WORDS: usize = NODE_SIZE / size_of::<u32>();
const SHA_BLOCK_SIZE: usize = 64;

const SHA256_INITIAL_DIGEST: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

#[inline]
fn fill_buffer(
    cur_node: u64,
    parents_cache: &CacheReader<u32>,
    cur_parent: &[u32], // parents for this node
    layer_labels: &UnsafeSlice<'_, u32>,
    exp_labels: Option<&UnsafeSlice<'_, u32>>, // None for layer0
    buf: &mut [u8],
    base_parent_missing: &mut BitMask,
) {
    let cur_node_swap = cur_node.to_be_bytes(); // Note switch to big endian
    buf[36..44].copy_from_slice(&cur_node_swap); // update buf with current node

    // Perform the first hash
    let cur_node_ptr =
        unsafe { &mut layer_labels.as_mut_slice()[cur_node as usize * NODE_WORDS as usize..] };

    cur_node_ptr[..8].copy_from_slice(&SHA256_INITIAL_DIGEST);
    compress256!(cur_node_ptr, buf, 1);

    // Fill in the base parents
    // Node 5 (prev node) will always be missing, and there tend to be
    // frequent close references.
    if cur_node > MIN_BASE_PARENT_NODE {
        // Mark base parent predecessor node as missing
        let (predecessor_index, other_drg_parents) = match parents_cache.api_version() {
            ApiVersion::V1_0_0 => (BASE_DEGREE - 1, (0..BASE_DEGREE - 1)),
            ApiVersion::V1_1_0 => (0, (1..BASE_DEGREE)),
        };

        base_parent_missing.set(predecessor_index);

        // Skip the last base parent - it always points to the preceding node,
        // which we know is not ready and will be filled in the main loop
        for k in other_drg_parents {
            unsafe {
                if cur_parent[k] as u64 >= parents_cache.get_consumer() {
                    // Node is not ready
                    base_parent_missing.set(k);
                } else {
                    let parent_data = {
                        let offset = cur_parent[k] as usize * NODE_WORDS;
                        &layer_labels.as_slice()[offset..offset + NODE_WORDS]
                    };
                    let a = SHA_BLOCK_SIZE + (NODE_SIZE * k);
                    buf[a..a + NODE_SIZE].copy_from_slice(parent_data.as_byte_slice());
                };
            }
        }
    } else {
        base_parent_missing.set_upto(BASE_DEGREE as u8);
    }

    if let Some(exp_labels) = exp_labels {
        let exp_parents = BASE_DEGREE..DEGREE;
        // Read from each of the expander parent nodes
        for k in exp_parents {
            let parent_data = unsafe {
                let offset = cur_parent[k] as usize * NODE_WORDS;
                &exp_labels.as_slice()[offset..offset + NODE_WORDS]
            };
            let a = SHA_BLOCK_SIZE + (NODE_SIZE * k);
            buf[a..a + NODE_SIZE].copy_from_slice(parent_data.as_byte_slice());
        }
    }
}

// This implements a producer, i.e. a thread that pre-fills the buffer
// with parent node data.
// - cur_consumer - The node currently being processed (consumed) by the
//                  hashing thread
// - cur_producer - The next node to be filled in by producer threads. The
//                  hashing thread can not yet work on this node.
// - cur_awaiting - The first not not currently being filled by any producer
//                  thread.
// - stride       - Each producer fills in this many nodes at a time. Setting
//                  this too small with cause a lot of time to be spent in
//                  thread synchronization
// - lookahead    - ring_buf size, in nodes
// - base_parent_missing - Bit mask of any base parent nodes that could not
//                         be filled in. This is an array of size lookahead.
// - is_layer0    - Indicates first (no expander parents) or subsequent layer
#[allow(clippy::too_many_arguments)]
fn create_label_runner(
    parents_cache: &CacheReader<u32>,
    layer_labels: &UnsafeSlice<'_, u32>,
    exp_labels: Option<&UnsafeSlice<'_, u32>>, // None for layer 0
    num_nodes: u64,
    cur_producer: &AtomicU64,
    cur_awaiting: &AtomicU64,
    stride: u64,
    lookahead: u64,
    ring_buf: &RingBuf,
    base_parent_missing: &UnsafeSlice<'_, BitMask>,
) {
    info!("created label runner");
    // Label data bytes per node
    loop {
        // Get next work items
        let work = cur_awaiting.fetch_add(stride, SeqCst);
        if work >= num_nodes {
            break;
        }
        let count = if work + stride > num_nodes {
            num_nodes - work
        } else {
            stride
        };

        // Do the work of filling the buffers
        for cur_node in work..work + count {
            // Determine which node slot in the ring_buffer to use
            // Note that node 0 does not use a buffer slot
            let cur_slot = (cur_node - 1) % lookahead;

            // Don't overrun the buffer
            while cur_node > (parents_cache.get_consumer() + lookahead - 1) {
                thread::sleep(Duration::from_micros(10));
            }

            let buf = unsafe { ring_buf.slot_mut(cur_slot as usize) };
            let bpm = unsafe { base_parent_missing.get_mut(cur_slot as usize) };

            let pc = unsafe { parents_cache.slice_at(cur_node as usize * DEGREE as usize) };
            fill_buffer(
                cur_node,
                parents_cache,
                pc,
                &layer_labels,
                exp_labels,
                buf,
                bpm,
            );
        }

        // Wait for the previous node to finish
        while work > (cur_producer.load(SeqCst) + 1) {
            thread::sleep(Duration::from_micros(10));
        }

        // Mark our work as done
        cur_producer.fetch_add(count, SeqCst);
    }
}

fn create_layer_labels(
    parents_cache: &CacheReader<u32>,
    replica_id: &[u8],
    layer_labels: &mut MmapMut,
    exp_labels: Option<&mut MmapMut>,
    num_nodes: u64,
    cur_layer: u32,
    core_group: Arc<Option<MutexGuard<'_, Vec<CoreIndex>>>>,
) {
    info!("Creating labels for layer {}", cur_layer);
    // num_producers is the number of producer threads
    let (lookahead, num_producers, producer_stride) = {
        let settings = &SETTINGS;
        let lookahead = settings.multicore_sdr_lookahead;
        let num_producers = settings.multicore_sdr_producers;
        // NOTE: Stride must not exceed the number of nodes in parents_cache's window. If it does, the process will deadlock
        // with producers and consumers waiting for each other.
        let producer_stride = settings
            .multicore_sdr_producer_stride
            .min(parents_cache.window_nodes() as u64);

        (lookahead, num_producers, producer_stride)
    };

    const BYTES_PER_NODE: usize = (NODE_SIZE * DEGREE) + SHA_BLOCK_SIZE;

    let mut ring_buf = RingBuf::new(BYTES_PER_NODE, lookahead);
    let mut base_parent_missing = vec![BitMask::default(); lookahead];

    // Fill in the fixed portion of all buffers
    for buf in ring_buf.iter_slot_mut() {
        prepare_block(replica_id, cur_layer, buf);
    }

    // Highest node that is ready from the producer
    let cur_producer = AtomicU64::new(0);
    // Next node to be filled
    let cur_awaiting = AtomicU64::new(1);

    // These UnsafeSlices are managed through the 3 Atomics above, to minimize any locking overhead.
    let layer_labels = UnsafeSlice::from_slice(
        layer_labels
            .as_mut_slice_of::<u32>()
            .expect("failed as mut slice of"),
    );
    let exp_labels = exp_labels.map(|m| {
        UnsafeSlice::from_slice(m.as_mut_slice_of::<u32>().expect("failed as mut slice of"))
    });
    let base_parent_missing = UnsafeSlice::from_slice(&mut base_parent_missing);

    crossbeam::thread::scope(|s| {
        let mut runners = Vec::with_capacity(num_producers);

        for i in 0..num_producers {
            let layer_labels = &layer_labels;
            let exp_labels = exp_labels.as_ref();
            let cur_producer = &cur_producer;
            let cur_awaiting = &cur_awaiting;
            let ring_buf = &ring_buf;
            let base_parent_missing = &base_parent_missing;

            let core_index = if let Some(cg) = &*core_group {
                cg.get(i + 1)
            } else {
                None
            };
            runners.push(s.spawn(move |_| {
                // This could fail, but we will ignore the error if so.
                // It will be logged as a warning by `bind_core`.
                debug!("binding core in producer thread {}", i);
                // When `_cleanup_handle` is dropped, the previous binding of thread will be restored.
                let _cleanup_handle = core_index.map(|c| bind_core(*c));

                create_label_runner(
                    parents_cache,
                    layer_labels,
                    exp_labels,
                    num_nodes,
                    cur_producer,
                    cur_awaiting,
                    producer_stride,
                    lookahead as u64,
                    ring_buf,
                    base_parent_missing,
                )
            }));
        }

        let mut cur_node_ptr = unsafe { layer_labels.as_mut_slice() };
        let mut cur_parent_ptr = unsafe { parents_cache.consumer_slice_at(DEGREE) };
        let mut cur_parent_ptr_offset = DEGREE;

        // Calculate node 0 (special case with no parents)
        // Which is replica_id || cur_layer || 0
        // TODO - Hash and save intermediate result: replica_id || cur_layer
        let mut buf = [0u8; (NODE_SIZE * DEGREE) + 64];
        prepare_block(replica_id, cur_layer, &mut buf);

        cur_node_ptr[..8].copy_from_slice(&SHA256_INITIAL_DIGEST);
        compress256!(cur_node_ptr, buf, 2);

        // Fix endianess
        cur_node_ptr[..8].iter_mut().for_each(|x| *x = x.to_be());

        cur_node_ptr[7] &= 0x3FFF_FFFF; // Strip last two bits to ensure in Fr

        // Keep track of which node slot in the ring_buffer to use
        let mut cur_slot = 0;
        let mut _count_not_ready = 0;

        // Calculate nodes 1 to n

        // Skip first node.
        parents_cache.store_consumer(1);
        let mut i = 1;
        while i < num_nodes {
            // Ensure next buffer is ready
            let mut printed = false;
            let mut producer_val = cur_producer.load(SeqCst);

            while producer_val < i {
                if !printed {
                    debug!("PRODUCER NOT READY! {}", i);
                    printed = true;
                    _count_not_ready += 1;
                }
                thread::sleep(Duration::from_micros(10));
                producer_val = cur_producer.load(SeqCst);
            }

            // Process as many nodes as are ready
            let ready_count = producer_val - i + 1;
            for _count in 0..ready_count {
                // If we have used up the last cache window's parent data, get some more.
                if cur_parent_ptr.is_empty() {
                    // Safety: values read from `cur_parent_ptr` before calling `increment_consumer`
                    // must not be read again after.
                    unsafe {
                        cur_parent_ptr = parents_cache.consumer_slice_at(cur_parent_ptr_offset);
                    }
                }

                cur_node_ptr = &mut cur_node_ptr[8..];
                // Grab the current slot of the ring_buf
                let buf = unsafe { ring_buf.slot_mut(cur_slot) };
                // Fill in the base parents
                let bpm = unsafe { base_parent_missing.get_mut(cur_slot) };
                for k in 0..BASE_DEGREE {
                    if bpm.get(k) {
                        let source = unsafe {
                            let start = cur_parent_ptr[0] as usize * NODE_WORDS;
                            let end = start + NODE_WORDS;
                            &layer_labels.as_slice()[start..end]
                        };

                        buf[64 + (NODE_SIZE * k)..64 + (NODE_SIZE * (k + 1))]
                            .copy_from_slice(source.as_byte_slice());
                    }
                    cur_parent_ptr = &cur_parent_ptr[1..];
                    cur_parent_ptr_offset += 1;
                }
                *bpm = BitMask::default();

                // Expanders are already all filled in (layer 1 doesn't use expanders)
                cur_parent_ptr = &cur_parent_ptr[EXP_DEGREE..];
                cur_parent_ptr_offset += EXP_DEGREE;

                if cur_layer == 1 {
                    // Six rounds of all base parents
                    for _j in 0..6 {
                        compress256!(cur_node_ptr, &buf[64..], 3);
                    }

                    // round 7 is only first parent
                    memset(&mut buf[96..128], 0); // Zero out upper half of last block
                    buf[96] = 0x80; // Padding
                    buf[126] = 0x27; // Length (0x2700 = 9984 bits -> 1248 bytes)
                    compress256!(cur_node_ptr, &buf[64..], 1);
                } else {
                    // Two rounds of all parents
                    let blocks = [
                        *GenericArray::<u8, U64>::from_slice(&buf[64..128]),
                        *GenericArray::<u8, U64>::from_slice(&buf[128..192]),
                        *GenericArray::<u8, U64>::from_slice(&buf[192..256]),
                        *GenericArray::<u8, U64>::from_slice(&buf[256..320]),
                        *GenericArray::<u8, U64>::from_slice(&buf[320..384]),
                        *GenericArray::<u8, U64>::from_slice(&buf[384..448]),
                        *GenericArray::<u8, U64>::from_slice(&buf[448..512]),
                    ];
                    sha2::compress256(
                        (&mut cur_node_ptr[..8])
                            .try_into()
                            .expect("compress failed"),
                        &blocks,
                    );
                    sha2::compress256(
                        (&mut cur_node_ptr[..8])
                            .try_into()
                            .expect("compress failed"),
                        &blocks,
                    );

                    // Final round is only nine parents
                    memset(&mut buf[352..384], 0); // Zero out upper half of last block
                    buf[352] = 0x80; // Padding
                    buf[382] = 0x27; // Length (0x2700 = 9984 bits -> 1248 bytes)
                    compress256!(cur_node_ptr, &buf[64..], 5);
                }

                // Fix endianess
                cur_node_ptr[..8].iter_mut().for_each(|x| *x = x.to_be());

                cur_node_ptr[7] &= 0x3FFF_FFFF; // Strip last two bits to fit in Fr

                // Safety:
                // It's possible that this increment will trigger moving the cache window.
                // In that case, we must not access `parents_cache` again but instead replace it.
                // This will happen above because `parents_cache` will now be empty, if we have
                // correctly advanced it so far.
                unsafe {
                    parents_cache.increment_consumer();
                }
                i += 1;
                cur_slot = (cur_slot + 1) % lookahead;
            }
        }

        for runner in runners {
            runner.join().expect("join failed");
        }
    })
    .expect("crossbeam scope failure");
}

#[allow(clippy::type_complexity)]
pub fn create_labels_for_encoding<Tree: 'static + MerkleTreeTrait, T: AsRef<[u8]>>(
    graph: &StackedBucketGraph<Tree::Hasher>,
    parents_cache: &ParentCache,
    layers: usize,
    replica_id: T,
    config: StoreConfig,
) -> Result<(Labels<Tree>, Vec<LayerState>)> {
    info!("create labels");

    let layer_states = prepare_layers::<Tree>(graph, &config, layers);

    let sector_size = graph.size() * NODE_SIZE;
    let node_count = graph.size() as u64;
    let cache_window_nodes = SETTINGS.sdr_parents_cache_size as usize;

    let default_cache_size = DEGREE * 4 * cache_window_nodes;

    let core_group = Arc::new(checkout_core_group());

    // When `_cleanup_handle` is dropped, the previous binding of thread will be restored.
    let _cleanup_handle = (*core_group).as_ref().map(|group| {
        // This could fail, but we will ignore the error if so.
        // It will be logged as a warning by `bind_core`.
        debug!("binding core in main thread");
        group.get(0).map(|core_index| bind_core(*core_index))
    });

    // NOTE: this means we currently keep 2x sector size around, to improve speed
    let (parents_cache, mut layer_labels, mut exp_labels) = setup_create_label_memory(
        sector_size,
        DEGREE,
        Some(default_cache_size as usize),
        &parents_cache.path,
        parents_cache.api_version,
    )?;

    for (layer, layer_state) in (1..=layers).zip(layer_states.iter()) {
        info!("Layer {}", layer);

        if layer_state.generated {
            info!("skipping layer {}, already generated", layer);

            // load the already generated layer into exp_labels
            read_layer(&layer_state.config, &mut exp_labels)?;
            continue;
        }

        // Cache reset happens in two parts.
        // The second part (the finish) happens before each layer but the first.
        if layers != 1 {
            parents_cache.finish_reset()?;
        }

        create_layer_labels(
            &parents_cache,
            &replica_id.as_ref(),
            &mut layer_labels,
            if layer == 1 {
                None
            } else {
                Some(&mut exp_labels)
            },
            node_count,
            layer as u32,
            core_group.clone(),
        );

        // Cache reset happens in two parts.
        // The first part (the start) happens after each layer but the last.
        if layer != layers {
            parents_cache.start_reset()?;
        }

        mem::swap(&mut layer_labels, &mut exp_labels);
        {
            let layer_config = &layer_state.config;

            info!("  storing labels on disk");
            write_layer(&exp_labels, layer_config).context("failed to store labels")?;

            info!(
                "  generated layer {} store with id {}",
                layer, layer_config.id
            );
        }
    }

    Ok((
        Labels::<Tree> {
            labels: layer_states.iter().map(|s| s.config.clone()).collect(),
            _h: PhantomData,
        },
        layer_states,
    ))
}

#[allow(clippy::type_complexity)]
pub fn create_labels_for_decoding<Tree: 'static + MerkleTreeTrait, T: AsRef<[u8]>>(
    graph: &StackedBucketGraph<Tree::Hasher>,
    parents_cache: &ParentCache,
    layers: usize,
    replica_id: T,
    config: StoreConfig,
) -> Result<LabelsCache<Tree>> {
    info!("create labels");

    // For now, we require it due to changes in encodings structure.
    let mut labels: Vec<DiskStore<<Tree::Hasher as Hasher>::Domain>> = Vec::with_capacity(layers);
    let mut label_configs: Vec<StoreConfig> = Vec::with_capacity(layers);

    let sector_size = graph.size() * NODE_SIZE;
    let node_count = graph.size() as u64;
    let cache_window_nodes = (&SETTINGS.sdr_parents_cache_size / 2) as usize;

    let default_cache_size = DEGREE * 4 * cache_window_nodes;

    let core_group = Arc::new(checkout_core_group());

    // When `_cleanup_handle` is dropped, the previous binding of thread will be restored.
    let _cleanup_handle = (*core_group).as_ref().map(|group| {
        // This could fail, but we will ignore the error if so.
        // It will be logged as a warning by `bind_core`.
        debug!("binding core in main thread");
        group.get(0).map(|core_index| bind_core(*core_index))
    });

    // NOTE: this means we currently keep 2x sector size around, to improve speed
    let (parents_cache, mut layer_labels, mut exp_labels) = setup_create_label_memory(
        sector_size,
        DEGREE,
        Some(default_cache_size as usize),
        &parents_cache.path,
        parents_cache.api_version,
    )?;

    for layer in 1..=layers {
        info!("Layer {}", layer);

        // Cache reset happens in two parts.
        // The second part (the finish) happens before each layer but the first.
        if layers != 1 {
            parents_cache.finish_reset()?;
        }

        create_layer_labels(
            &parents_cache,
            &replica_id.as_ref(),
            &mut layer_labels,
            if layer == 1 {
                None
            } else {
                Some(&mut exp_labels)
            },
            node_count,
            layer as u32,
            core_group.clone(),
        );

        // Cache reset happens in two parts.
        // The first part (the start) happens after each layer but the last.
        if layer != layers {
            parents_cache.start_reset()?;
        }

        {
            let layer_config =
                StoreConfig::from_config(&config, CacheKey::label_layer(layer), Some(graph.size()));

            info!("  storing labels on disk");
            // Construct and persist the layer data.
            let layer_store: DiskStore<<Tree::Hasher as Hasher>::Domain> =
                DiskStore::new_from_slice_with_config(
                    graph.size(),
                    Tree::Arity::to_usize(),
                    &layer_labels,
                    layer_config.clone(),
                )?;
            info!(
                "  generated layer {} store with id {}",
                layer, layer_config.id
            );

            mem::swap(&mut layer_labels, &mut exp_labels);

            // Track the layer specific store and StoreConfig for later retrieval.
            labels.push(layer_store);
            label_configs.push(layer_config);
        }
    }
    assert_eq!(
        labels.len(),
        layers,
        "Invalid amount of layers encoded expected"
    );

    Ok(LabelsCache::<Tree> { labels })
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::bls::{Fr, FrRepr};
    use ff::PrimeField;
    use filecoin_hashers::poseidon::PoseidonHasher;
    use generic_array::typenum::{U0, U2, U8};
    use storage_proofs_core::{api_version::ApiVersion, merkle::LCTree};
    use tempfile::tempdir;

    #[test]
    fn test_create_labels() {
        let layers = 11;
        let nodes_2k = 1 << 11;
        let nodes_4k = 1 << 12;
        let replica_id = [9u8; 32];

        // These PoRepIDs are only useful to distinguish legacy/new sectors.
        // They do not correspond to registered proofs of the sizes used here.
        let legacy_porep_id = [0; 32];
        let new_porep_id = [123; 32];
        test_create_labels_aux(
            nodes_2k,
            layers,
            replica_id,
            legacy_porep_id,
            ApiVersion::V1_0_0,
            Fr::from_repr(FrRepr([
                0xd3faa96b9a0fba04,
                0xea81a283d106485e,
                0xe3d51b9afa5ac2b3,
                0x0462f4f4f1a68d37,
            ]))
            .expect("create_labels_aux failed"),
        );
        test_create_labels_aux(
            nodes_4k,
            layers,
            replica_id,
            legacy_porep_id,
            ApiVersion::V1_0_0,
            Fr::from_repr(FrRepr([
                0x7e191e52c4a8da86,
                0x5ae8a1c9e6fac148,
                0xce239f3b88a894b8,
                0x234c00d1dc1d53be,
            ]))
            .expect("create_labels_aux failed"),
        );

        test_create_labels_aux(
            nodes_2k,
            layers,
            replica_id,
            new_porep_id,
            ApiVersion::V1_1_0,
            Fr::from_repr(FrRepr([
                0xabb3f38bb70defcf,
                0x777a2e4d7769119f,
                0x3448959d495490bc,
                0x06021188c7a71cb5,
            ]))
            .expect("create_labels_aux failed"),
        );

        test_create_labels_aux(
            nodes_4k,
            layers,
            replica_id,
            new_porep_id,
            ApiVersion::V1_1_0,
            Fr::from_repr(FrRepr([
                0x22ab81cf68c4676d,
                0x7a77a82fc7c9c189,
                0xc6c03d32c1e42d23,
                0x0f777c18cc2c55bd,
            ]))
            .expect("create_labels_aux failed"),
        );
    }

    fn test_create_labels_aux(
        sector_size: usize,
        layers: usize,
        replica_id: [u8; 32],
        porep_id: [u8; 32],
        api_version: ApiVersion,
        expected_last_label: Fr,
    ) {
        let nodes = sector_size / NODE_SIZE;

        let cache_dir = tempdir().expect("tempdir failure");
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            nodes.trailing_zeros() as usize,
        );

        let graph = StackedBucketGraph::<PoseidonHasher>::new(
            None,
            nodes,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            api_version,
        )
        .expect("stacked bucket graph new failed");
        let cache = graph.parent_cache().expect("parent_cache failed");

        let labels = create_labels_for_decoding::<LCTree<PoseidonHasher, U8, U0, U2>, _>(
            &graph, &cache, layers, replica_id, config,
        )
        .expect("create_labels_for_decoding failed");

        let final_labels = labels
            .labels_for_last_layer()
            .expect("labels_for_last_layer failed");
        let last_label = final_labels
            .read_at(final_labels.len() - 1)
            .expect("read_at");
        dbg!(&last_label);
        assert_eq!(expected_last_label.into_repr(), last_label.0);
    }
}
