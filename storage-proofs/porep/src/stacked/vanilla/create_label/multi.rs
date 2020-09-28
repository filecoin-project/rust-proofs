use std::convert::TryInto;
use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

use anyhow::Result;
use byte_slice_cast::*;
use crossbeam::thread;
use digest::generic_array::{
    typenum::{Unsigned, U64},
    GenericArray,
};
use log::*;
use mapr::MmapMut;
use merkletree::store::{DiskStore, StoreConfig};
use storage_proofs_core::{
    cache_key::CacheKey,
    drgraph::{Graph, BASE_DEGREE},
    hasher::Hasher,
    merkle::*,
    settings,
    util::NODE_SIZE,
};

use super::super::{
    cache::ParentCache,
    graph::{StackedBucketGraph, DEGREE, EXP_DEGREE},
    memory_handling::{setup_create_label_memory, CacheReader},
    params::{Labels, LabelsCache},
    utils::*,
    proof::LayerState,
};

const NODE_WORDS: usize = NODE_SIZE / size_of::<u32>();

const SHA256_INITIAL_DIGEST: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6_ef372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

#[inline]
fn fill_buffer(
    cur_node: u64,
    cur_consumer: &AtomicU64,
    mut cur_parent: &[u32], // parents for this node
    layer_labels: &UnsafeSlice<u32>,
    exp_labels: Option<&UnsafeSlice<u32>>, // None for layer0
    buf: &mut [u8],
    base_parent_missing: &mut BitMask,
) {
    const MIN_BASE_PARENT_NODE: u64 = 2000;

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
        // Mark base parent 5 as missing
        // base_parent_missing.set_all(0x20);
        base_parent_missing.set(5);

        // Skip the last base parent - it always points to the preceding node,
        // which we know is not ready and will be filled in the main loop
        for k in 0..BASE_DEGREE - 1 {
            if cur_parent[0] as u64 >= cur_consumer.load(SeqCst) {
                // Node is not ready
                base_parent_missing.set(k);
            } else {
                let parent_data = unsafe {
                    let offset = cur_parent[0] as usize * NODE_WORDS;
                    &layer_labels.as_slice()[offset..offset + NODE_WORDS]
                };
                let a = 64 + (NODE_SIZE * k);
                buf[a..a + NODE_SIZE].copy_from_slice(parent_data.as_byte_slice());
            }
            cur_parent = &cur_parent[1..];
        }
        // Advance pointer for the last base parent
        cur_parent = &cur_parent[1..];
    } else {
        base_parent_missing.set_upto(BASE_DEGREE as u8); // (1 << BASE_DEGREE) - 1);
        cur_parent = &cur_parent[BASE_DEGREE..];
    }

    if let Some(exp_labels) = exp_labels {
        // Read from each of the expander parent nodes
        for k in BASE_DEGREE..DEGREE {
            let parent_data = unsafe {
                let offset = cur_parent[0] as usize * NODE_WORDS;
                &exp_labels.as_slice()[offset..offset + NODE_WORDS]
            };
            let a = 64 + (NODE_SIZE * k);
            buf[a..a + NODE_SIZE].copy_from_slice(parent_data.as_byte_slice());
            cur_parent = &cur_parent[1..];
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
    layer_labels: &UnsafeSlice<u32>,
    exp_labels: Option<&UnsafeSlice<u32>>, // None for layer 0
    num_nodes: u64,
    cur_consumer: &AtomicU64,
    cur_producer: &AtomicU64,
    cur_awaiting: &AtomicU64,
    stride: u64,
    lookahead: u64,
    ring_buf: &RingBuf,
    base_parent_missing: &UnsafeSlice<BitMask>,
) -> Result<()> {
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
        // info!(
        //     "starting work on count items: {}, starting from {}",
        //     count, work
        // );

        // Do the work of filling the buffers
        for cur_node in work..work + count {
            // Determine which node slot in the ring_buffer to use
            // Note that node 0 does not use a buffer slot
            let cur_slot = (cur_node - 1) % lookahead;

            // Don't overrun the buffer
            while cur_node > (cur_consumer.load(SeqCst) + lookahead - 1) {
                std::thread::sleep(std::time::Duration::from_micros(10));
            }

            let buf = unsafe { ring_buf.slot_mut(cur_slot as usize) };
            let bpm = unsafe { base_parent_missing.get_mut(cur_slot as usize) };

            let pc = parents_cache.slice_at(cur_node as usize * DEGREE as usize, cur_consumer);
            // info!("filling");
            fill_buffer(
                cur_node,
                cur_consumer,
                pc,
                &layer_labels,
                exp_labels,
                buf,
                bpm,
            );
            // info!("filled");
        }

        // Wait for the previous node to finish
        while work > (cur_producer.load(SeqCst) + 1) {
            std::thread::sleep(std::time::Duration::from_micros(10));
        }

        // Mark our work as done
        cur_producer.fetch_add(count, SeqCst);
    }

    Ok(())
}

fn create_layer_labels(
    parents_cache: &CacheReader<u32>,
    replica_id: &[u8],
    layer_labels: &mut MmapMut,
    exp_labels: Option<&mut MmapMut>,
    num_nodes: u64,
    cur_layer: u32,
) -> Result<()> {
    info!("Creating labels for layer {}", cur_layer);
    // num_producers is the number of producer threads
    let (lookahead, num_producers, producer_stride) = {
        // NOTE: Stride must not exceed `sdr_parents_cache_window_nodes`.
        // If it does, the process will deadlock with producers and consumers
        // waiting for each other.
        // TODO: Enforce this.
        //(800, 1, 128)
        (800, 2, 128)
    };

    const BYTES_PER_NODE: usize = (NODE_SIZE * DEGREE) + 64;

    let mut ring_buf = RingBuf::new(BYTES_PER_NODE, lookahead);
    let mut base_parent_missing = vec![BitMask::default(); lookahead];

    // Fill in the fixed portion of all buffers
    for buf in ring_buf.iter_slot_mut() {
        prepare_block(replica_id, cur_layer, buf);
    }

    // Node the consumer is currently working on
    let cur_consumer = AtomicU64::new(0);
    // Highest node that is ready from the producer
    let cur_producer = AtomicU64::new(0);
    // Next node to be filled
    let cur_awaiting = AtomicU64::new(1);

    // These UnsafeSlices are managed through the 3 Atomics above, to minimize any locking overhead.
    let layer_labels = UnsafeSlice::from_slice(layer_labels.as_mut_slice_of::<u32>().unwrap());
    let exp_labels =
        exp_labels.map(|m| UnsafeSlice::from_slice(m.as_mut_slice_of::<u32>().unwrap()));
    let base_parent_missing = UnsafeSlice::from_slice(&mut base_parent_missing);

    thread::scope(|s| {
        let mut runners = Vec::with_capacity(num_producers);

        for _i in 0..num_producers {
            let layer_labels = &layer_labels;
            let exp_labels = exp_labels.as_ref();
            let cur_consumer = &cur_consumer;
            let cur_producer = &cur_producer;
            let cur_awaiting = &cur_awaiting;
            let ring_buf = &ring_buf;
            let base_parent_missing = &base_parent_missing;

            runners.push(s.spawn(move |_| {
                create_label_runner(
                    parents_cache,
                    layer_labels,
                    exp_labels,
                    num_nodes,
                    cur_consumer,
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
        let mut cur_parent_ptr = parents_cache.consumer_slice_at(DEGREE);
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
        cur_consumer.store(1, SeqCst);
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
                std::thread::sleep(std::time::Duration::from_micros(10));
                producer_val = cur_producer.load(SeqCst);
            }

            // Process as many nodes as are ready
            let ready_count = producer_val - i + 1;
            for _count in 0..ready_count {
                cur_node_ptr = &mut cur_node_ptr[8..];
                // Grab the current slot of the ring_buf
                let buf = unsafe { ring_buf.slot_mut(cur_slot) };
                // Fill in the base parents
                for k in 0..BASE_DEGREE {
                    let bpm = unsafe { base_parent_missing.get(cur_slot) };
                    if bpm.get(k) {
                        // info!("getting missing parent, k={}", k);
                        let source = unsafe {
                            if cur_parent_ptr.is_empty() {
                                cur_parent_ptr =
                                    parents_cache.consumer_slice_at(cur_parent_ptr_offset);
                            }
                            // info!("after unsafe, when getting miss parent");
                            let start = cur_parent_ptr[0] as usize * NODE_WORDS;
                            let end = start + NODE_WORDS;

                            // info!("before as_slice(), when getting miss parent");
                            &layer_labels.as_slice()[start..end]
                        };

                        buf[64 + (NODE_SIZE * k)..64 + (NODE_SIZE * (k + 1))]
                            .copy_from_slice(source.as_byte_slice());
                        // info!("got missing parent, k={}", k);
                    }
                    cur_parent_ptr = &cur_parent_ptr[1..];
                    cur_parent_ptr_offset += 1;
                }

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
                    sha2::compress256((&mut cur_node_ptr[..8]).try_into().unwrap(), &blocks);
                    sha2::compress256((&mut cur_node_ptr[..8]).try_into().unwrap(), &blocks);

                    // Final round is only nine parents
                    memset(&mut buf[352..384], 0); // Zero out upper half of last block
                    buf[352] = 0x80; // Padding
                    buf[382] = 0x27; // Length (0x2700 = 9984 bits -> 1248 bytes)
                    compress256!(cur_node_ptr, &buf[64..], 5);
                }

                // Fix endianess
                cur_node_ptr[..8].iter_mut().for_each(|x| *x = x.to_be());

                cur_node_ptr[7] &= 0x3FFF_FFFF; // Strip last two bits to fit in Fr

                cur_consumer.fetch_add(1, SeqCst);
                i += 1;
                cur_slot = (cur_slot + 1) % lookahead;
            }
        }

        for runner in runners {
            runner.join().unwrap().unwrap();
        }
    })
    .unwrap();

    Ok(())
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

    let layer_states = super::prepare_layers::<Tree>(graph, &config, layers);
    
    // For now, we require it due to changes in encodings structure.
    let mut labels: Vec<DiskStore<<Tree::Hasher as Hasher>::Domain>> = Vec::with_capacity(layers);

    let sector_size = graph.size() * NODE_SIZE;
    let node_count = graph.size() as u64;
    let cache_window_nodes = settings::SETTINGS
        .lock()
        .expect("sdr_parents_cache_size settings lock failure")
        .sdr_parents_cache_size as usize;

    let default_cache_size = DEGREE * 4 * cache_window_nodes;

    // NOTE: this means we currently keep 2x sector size around, to improve speed
    let (parents_cache, mut layer_labels, mut exp_labels) = setup_create_label_memory(
        sector_size,
        DEGREE,
        Some(default_cache_size as usize),
        &parents_cache.path,
    )?;

    for (layer, layer_state) in (1..=layers).zip(layer_states.iter()) {
        info!("Layer {}", layer);

        if layer_state.generated {
            info!("skipping layer {}, already generated", layer);

            // load the already generated layer into exp_labels
            super::read_layer(&layer_state.config, &mut exp_labels)?;
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
        )?;

        // Cache reset happens in two parts.
        // The first part (the start) happens after each layer but the last.
        if layer != layers {
            parents_cache.start_reset()?;
        }

        {
            let layer_config = &layer_state.config;

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

            std::mem::swap(&mut layer_labels, &mut exp_labels);

            // Track the layer specific store and StoreConfig for later retrieval.
            labels.push(layer_store);
        }
    }
    assert_eq!(
        labels.len(),
        layers,
        "Invalid amount of layers encoded expected"
    );

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
    let cache_window_nodes = (settings::SETTINGS
        .lock()
        .expect("sdr_parents_cache_window_nodes settings lock failure")
        .sdr_parents_cache_size
        / 2) as usize;

    let default_cache_size = DEGREE * 4 * cache_window_nodes;

    // NOTE: this means we currently keep 2x sector size around, to improve speed
    let (parents_cache, mut layer_labels, mut exp_labels) = setup_create_label_memory(
        sector_size,
        DEGREE,
        Some(default_cache_size as usize),
        &parents_cache.path,
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
        )?;

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

            std::mem::swap(&mut layer_labels, &mut exp_labels);

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

    Ok(
        LabelsCache::<Tree> { labels },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::PrimeField;
    use generic_array::typenum::{U0, U2, U8};
    use paired::bls12_381::{Fr, FrRepr};
    use storage_proofs_core::hasher::poseidon::PoseidonHasher;

    #[test]
    fn test_create_labels() {
        let layers = 11;
        let nodes_2k = 1 << 11;
        let nodes_4k = 1 << 12;
        let replica_id = [9u8; 32];
        let porep_id = [123; 32];
        test_create_labels_aux(
            nodes_2k,
            layers,
            replica_id,
            porep_id,
            Fr::from_repr(FrRepr([
                0x1a4017052cbe1c4a,
                0x446354db91e96d8e,
                0xbc864a95454eba0c,
                0x094cf219d72cad06,
            ]))
            .unwrap(),
        );

        test_create_labels_aux(
            nodes_4k,
            layers,
            replica_id,
            porep_id,
            Fr::from_repr(FrRepr([
                0x0a6917a59c51198b,
                0xd2edc96e3717044a,
                0xf438a1131f907206,
                0x084f42888ca2342c,
            ]))
            .unwrap(),
        );
    }

    fn test_create_labels_aux(
        sector_size: usize,
        layers: usize,
        replica_id: [u8; 32],
        porep_id: [u8; 32],
        expected_last_label: Fr,
    ) {
        let nodes = sector_size / NODE_SIZE;

        let cache_dir = tempfile::tempdir().expect("tempdir failure");
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
        )
        .unwrap();
        let cache = graph.parent_cache().unwrap();

        let labels = create_labels_for_decoding::<LCTree<PoseidonHasher, U8, U0, U2>, _>(
            &graph, &cache, layers, replica_id, config,
        )
        .unwrap();

        let final_labels = labels.labels_for_last_layer().unwrap();
        let last_label = final_labels.read_at(final_labels.len() - 1).unwrap();
        dbg!(&last_label);
        assert_eq!(expected_last_label.into_repr(), last_label.0);
    }
}
