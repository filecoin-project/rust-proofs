use std::fs;
use std::marker::PhantomData;
use std::panic::panic_any;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Context;
use bincode::deserialize;
use fdlimit::raise_fd_limit;
use filecoin_hashers::{Domain, HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::{Unsigned, U0, U11, U2, U8};
use lazy_static::lazy_static;
use log::{error, info, trace};
use merkletree::{
    merkle::{get_merkle_tree_len, is_merkle_tree_size_valid},
    store::{Store, StoreConfig},
};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, ParallelIterator, ParallelSliceMut,
};
use storage_proofs_core::{
    cache_key::CacheKey,
    data::Data,
    drgraph::Graph,
    error::Result,
    measurements::{measure_op, Operation},
    merkle::{
        create_disk_tree, create_lc_tree, get_base_tree_count, split_config,
        split_config_and_replica, BinaryMerkleTree, DiskTree, LCTree, MerkleProofTrait, MerkleTree,
        MerkleTreeTrait,
    },
    settings::SETTINGS,
    util::{default_rows_to_discard, NODE_SIZE},
};

use crate::{
    encode::{decode, encode},
    stacked::vanilla::{
        challenges::LayerChallenges,
        column::Column,
        create_label,
        graph::StackedBucketGraph,
        hash::hash_single_column,
        params::{
            get_node, Labels, LabelsCache, PersistentAux, Proof, PublicInputs, PublicParams,
            ReplicaColumnProof, Tau, TemporaryAux, TemporaryAuxCache, TransformedLayers,
            BINARY_ARITY,
        },
        EncodingProof, LabelingProof,
    },
    PoRep,
};

pub const TOTAL_PARENTS: usize = 37;

lazy_static! {
    /// Ensure that only one `TreeBuilder` or `ColumnTreeBuilder` uses the GPU at a time.
    /// Curently, this is accomplished by only instantiating at most one at a time.
    /// It might be possible to relax this constraint, but in that case, only one builder
    /// should actually be active at any given time, so the mutex should still be used.
    static ref GPU_LOCK: Mutex<()> = Mutex::new(());
}

#[derive(Debug)]
pub struct StackedDrg<'a, Tree: MerkleTreeTrait, G: Hasher> {
    _a: PhantomData<&'a Tree>,
    _b: PhantomData<&'a G>,
}

#[derive(Debug)]
pub struct LayerState {
    pub config: StoreConfig,
    pub generated: bool,
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> StackedDrg<'a, Tree, G> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_layers(
        graph: &StackedBucketGraph<Tree::Hasher>,
        pub_inputs: &PublicInputs<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>,
        p_aux: &PersistentAux<<Tree::Hasher as Hasher>::Domain>,
        t_aux: &TemporaryAuxCache<Tree, G>,
        layer_challenges: &LayerChallenges,
        layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Vec<Proof<Tree, G>>>> {
        assert!(layers > 0);
        assert_eq!(t_aux.labels.len(), layers);

        let graph_size = graph.size();

        // Sanity checks on restored trees.
        assert!(pub_inputs.tau.is_some());
        assert_eq!(
            pub_inputs.tau.as_ref().expect("as_ref failure").comm_d,
            t_aux.tree_d.root()
        );

        let get_drg_parents_columns = |x: usize| -> Result<Vec<Column<Tree::Hasher>>> {
            let base_degree = graph.base_graph().degree();

            let mut columns = Vec::with_capacity(base_degree);

            let mut parents = vec![0; base_degree];
            graph.base_parents(x, &mut parents)?;

            columns.extend(
                parents
                    .into_par_iter()
                    .map(|parent| t_aux.column(parent))
                    .collect::<Result<Vec<Column<Tree::Hasher>>>>()?,
            );

            debug_assert!(columns.len() == base_degree);

            Ok(columns)
        };

        let get_exp_parents_columns = |x: usize| -> Result<Vec<Column<Tree::Hasher>>> {
            let mut parents = vec![0; graph.expansion_degree()];
            graph.expanded_parents(x, &mut parents)?;

            parents
                .into_par_iter()
                .map(|parent| t_aux.column(parent))
                .collect()
        };

        (0..partition_count)
            .map(|k| {
                trace!("proving partition {}/{}", k + 1, partition_count);

                // Derive the set of challenges we are proving over.
                let challenges = pub_inputs.challenges(layer_challenges, graph_size, Some(k));

                // Stacked commitment specifics
                challenges
                    .into_par_iter()
                    .enumerate()
                    .map(|(challenge_index, challenge)| {
                        trace!(" challenge {} ({})", challenge, challenge_index);
                        assert!(challenge < graph.size(), "Invalid challenge");
                        assert!(challenge > 0, "Invalid challenge");

                        // Initial data layer openings (c_X in Comm_D)
                        let comm_d_proof = t_aux.tree_d.gen_proof(challenge)?;
                        assert!(comm_d_proof.validate(challenge));

                        // Stacked replica column openings
                        let rcp = {
                            let (c_x, drg_parents, exp_parents) = {
                                assert_eq!(p_aux.comm_c, t_aux.tree_c.root());
                                let tree_c = &t_aux.tree_c;

                                // All labels in C_X
                                trace!("  c_x");
                                let c_x = t_aux.column(challenge as u32)?.into_proof(tree_c)?;

                                // All labels in the DRG parents.
                                trace!("  drg_parents");
                                let drg_parents = get_drg_parents_columns(challenge)?
                                    .into_iter()
                                    .map(|column| column.into_proof(tree_c))
                                    .collect::<Result<_>>()?;

                                // Labels for the expander parents
                                trace!("  exp_parents");
                                let exp_parents = get_exp_parents_columns(challenge)?
                                    .into_iter()
                                    .map(|column| column.into_proof(tree_c))
                                    .collect::<Result<_>>()?;

                                (c_x, drg_parents, exp_parents)
                            };

                            ReplicaColumnProof {
                                c_x,
                                drg_parents,
                                exp_parents,
                            }
                        };

                        // Final replica layer openings
                        trace!("final replica layer openings");
                        let comm_r_last_proof = t_aux.tree_r_last.gen_cached_proof(
                            challenge,
                            Some(t_aux.tree_r_last_config_rows_to_discard),
                        )?;

                        debug_assert!(comm_r_last_proof.validate(challenge));

                        // Labeling Proofs Layer 1..l
                        let mut labeling_proofs = Vec::with_capacity(layers);
                        let mut encoding_proof = None;

                        for layer in 1..=layers {
                            trace!("  encoding proof layer {}", layer,);
                            let parents_data: Vec<<Tree::Hasher as Hasher>::Domain> = if layer == 1
                            {
                                let mut parents = vec![0; graph.base_graph().degree()];
                                graph.base_parents(challenge, &mut parents)?;

                                parents
                                    .into_par_iter()
                                    .map(|parent| t_aux.domain_node_at_layer(layer, parent))
                                    .collect::<Result<_>>()?
                            } else {
                                let mut parents = vec![0; graph.degree()];
                                graph.parents(challenge, &mut parents)?;
                                let base_parents_count = graph.base_graph().degree();

                                parents
                                    .into_par_iter()
                                    .enumerate()
                                    .map(|(i, parent)| {
                                        if i < base_parents_count {
                                            // parents data for base parents is from the current layer
                                            t_aux.domain_node_at_layer(layer, parent)
                                        } else {
                                            // parents data for exp parents is from the previous layer
                                            t_aux.domain_node_at_layer(layer - 1, parent)
                                        }
                                    })
                                    .collect::<Result<_>>()?
                            };

                            // repeat parents
                            let mut parents_data_full = vec![Default::default(); TOTAL_PARENTS];
                            for chunk in parents_data_full.chunks_mut(parents_data.len()) {
                                chunk.copy_from_slice(&parents_data[..chunk.len()]);
                            }

                            let proof = LabelingProof::<Tree::Hasher>::new(
                                layer as u32,
                                challenge as u64,
                                parents_data_full.clone(),
                            );

                            {
                                let labeled_node = rcp.c_x.get_node_at_layer(layer)?;
                                assert!(
                                    proof.verify(&pub_inputs.replica_id, &labeled_node),
                                    "Invalid encoding proof generated at layer {}",
                                    layer,
                                );
                                trace!("Valid encoding proof generated at layer {}", layer);
                            }

                            labeling_proofs.push(proof);

                            if layer == layers {
                                encoding_proof = Some(EncodingProof::new(
                                    layer as u32,
                                    challenge as u64,
                                    parents_data_full,
                                ));
                            }
                        }

                        Ok(Proof {
                            comm_d_proofs: comm_d_proof,
                            replica_column_proofs: rcp,
                            comm_r_last_proof,
                            labeling_proofs,
                            encoding_proof: encoding_proof.expect("invalid tapering"),
                        })
                    })
                    .collect()
            })
            .collect()
    }

    pub(crate) fn extract_and_invert_transform_layers(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        data: &mut [u8],
        config: StoreConfig,
    ) -> Result<()> {
        trace!("extract_and_invert_transform_layers");

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        let labels =
            Self::generate_labels_for_decoding(graph, layer_challenges, replica_id, config)?;

        let last_layer_labels = labels.labels_for_last_layer()?;
        let size = Store::len(last_layer_labels);

        for (key, encoded_node_bytes) in last_layer_labels
            .read_range(0..size)?
            .into_iter()
            .zip(data.chunks_mut(NODE_SIZE))
        {
            let encoded_node =
                <Tree::Hasher as Hasher>::Domain::try_from_bytes(encoded_node_bytes)?;
            let data_node = decode::<<Tree::Hasher as Hasher>::Domain>(key, encoded_node);

            // store result in the data
            encoded_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&data_node));
        }

        Ok(())
    }

    /// Generates the layers as needed for encoding.
    pub fn generate_labels_for_encoding(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        config: StoreConfig,
    ) -> Result<(Labels<Tree>, Vec<LayerState>)> {
        let mut parent_cache = graph.parent_cache()?;

        #[cfg(feature = "multicore-sdr")]
        {
            if SETTINGS.use_multicore_sdr {
                info!("multi core replication");
                create_label::multi::create_labels_for_encoding(
                    graph,
                    &parent_cache,
                    layer_challenges.layers(),
                    replica_id,
                    config,
                )
            } else {
                info!("single core replication");
                create_label::single::create_labels_for_encoding(
                    graph,
                    &mut parent_cache,
                    layer_challenges.layers(),
                    replica_id,
                    config,
                )
            }
        }

        #[cfg(not(feature = "multicore-sdr"))]
        {
            info!("single core replication");
            create_label::single::create_labels_for_encoding(
                graph,
                &mut parent_cache,
                layer_challenges.layers(),
                replica_id,
                config,
            )
        }
    }

    /// Generates the layers, as needed for decoding.
    pub fn generate_labels_for_decoding(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        config: StoreConfig,
    ) -> Result<LabelsCache<Tree>> {
        let mut parent_cache = graph.parent_cache()?;

        #[cfg(feature = "multicore-sdr")]
        {
            if SETTINGS.use_multicore_sdr {
                info!("multi core replication");
                create_label::multi::create_labels_for_decoding(
                    graph,
                    &parent_cache,
                    layer_challenges.layers(),
                    replica_id,
                    config,
                )
            } else {
                info!("single core replication");
                create_label::single::create_labels_for_decoding(
                    graph,
                    &mut parent_cache,
                    layer_challenges.layers(),
                    replica_id,
                    config,
                )
            }
        }

        #[cfg(not(feature = "multicore-sdr"))]
        {
            info!("single core replication");
            create_label::single::create_labels_for_decoding(
                graph,
                &mut parent_cache,
                layer_challenges.layers(),
                replica_id,
                config,
            )
        }
    }

    fn build_binary_tree<K: Hasher>(
        tree_data: &[u8],
        config: StoreConfig,
    ) -> Result<BinaryMerkleTree<K>> {
        trace!("building tree (size: {})", tree_data.len());

        let leafs = tree_data.len() / NODE_SIZE;
        assert_eq!(tree_data.len() % NODE_SIZE, 0);

        let tree = MerkleTree::from_par_iter_with_config(
            (0..leafs)
                .into_par_iter()
                // TODO: proper error handling instead of `unwrap()`
                .map(|i| get_node::<K>(tree_data, i).expect("get_node failure")),
            config,
        )?;
        Ok(tree)
    }

    #[cfg(any(feature = "gpu"))]
    fn generate_tree_c<ColumnArity, TreeArity>(
        layers: usize,
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: 'static + PoseidonArity,
        TreeArity: PoseidonArity,
    {
        if SETTINGS.use_gpu_column_builder {
            Self::generate_tree_c_gpu::<ColumnArity, TreeArity>(
                layers,
                nodes_count,
                tree_count,
                configs,
                labels,
            )
        } else {
            Self::generate_tree_c_cpu::<ColumnArity, TreeArity>(
                layers,
                nodes_count,
                tree_count,
                configs,
                labels,
            )
        }
    }

    #[cfg(not(any(feature = "gpu")))]
    fn generate_tree_c<ColumnArity, TreeArity>(
        layers: usize,
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: 'static + PoseidonArity,
        TreeArity: PoseidonArity,
    {
        Self::generate_tree_c_cpu::<ColumnArity, TreeArity>(
            layers,
            nodes_count,
            tree_count,
            configs,
            labels,
        )
    }

    #[allow(clippy::needless_range_loop)]
    #[cfg(any(feature = "gpu"))]
    fn generate_tree_c_gpu<ColumnArity, TreeArity>(
        layers: usize,
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: 'static + PoseidonArity,
        TreeArity: PoseidonArity,
    {
        use std::cmp::min;
        use std::sync::{mpsc::sync_channel, Arc, RwLock};

        use bellperson::bls::Fr;
        use fr32::fr_into_bytes;
        use generic_array::GenericArray;
        use merkletree::store::DiskStore;
        use neptune::{
            batch_hasher::Batcher,
            column_tree_builder::{ColumnTreeBuilder, ColumnTreeBuilderTrait},
        };

        info!("generating tree c using the GPU");
        // Build the tree for CommC
        measure_op(Operation::GenerateTreeC, || {
            info!("Building column hashes");

            // NOTE: The max number of columns we recommend sending to the GPU at once is
            // 400000 for columns and 700000 for trees (conservative soft-limits discussed).
            //
            // 'column_write_batch_size' is how many nodes to chunk the base layer of data
            // into when persisting to disk.
            //
            // Override these values with care using environment variables:
            // FIL_PROOFS_MAX_GPU_COLUMN_BATCH_SIZE, FIL_PROOFS_MAX_GPU_TREE_BATCH_SIZE, and
            // FIL_PROOFS_COLUMN_WRITE_BATCH_SIZE respectively.
            let max_gpu_column_batch_size = SETTINGS.max_gpu_column_batch_size as usize;
            let max_gpu_tree_batch_size = SETTINGS.max_gpu_tree_batch_size as usize;
            let column_write_batch_size = SETTINGS.column_write_batch_size as usize;

            // This channel will receive batches of columns and add them to the ColumnTreeBuilder.
            let (builder_tx, builder_rx) = sync_channel(0);

            let config_count = configs.len(); // Don't move config into closure below.
            rayon::scope(|s| {
                // This channel will receive the finished tree data to be written to disk.
                let (writer_tx, writer_rx) = sync_channel::<(Vec<Fr>, Vec<Fr>)>(0);

                s.spawn(move |_| {
                    for i in 0..config_count {
                        let mut node_index = 0;
                        let builder_tx = builder_tx.clone();
                        while node_index != nodes_count {
                            let chunked_nodes_count =
                                min(nodes_count - node_index, max_gpu_column_batch_size);
                            trace!(
                                "processing config {}/{} with column nodes {}",
                                i + 1,
                                tree_count,
                                chunked_nodes_count,
                            );

                            let columns: Vec<GenericArray<Fr, ColumnArity>> = {
                                use fr32::bytes_into_fr;

                                // Allocate layer data array and insert a placeholder for each layer.
                                let mut layer_data: Vec<Vec<u8>> =
                                    vec![
                                        vec![0u8; chunked_nodes_count * std::mem::size_of::<Fr>()];
                                        layers
                                    ];

                                // gather all layer data.
                                for (layer_index, mut layer_bytes) in
                                    layer_data.iter_mut().enumerate()
                                {
                                    let store = labels.labels_for_layer(layer_index + 1);
                                    let start = (i * nodes_count) + node_index;
                                    let end = start + chunked_nodes_count;

                                    store
                                        .read_range_into(start, end, &mut layer_bytes)
                                        .expect("failed to read store range");
                                }

                                (0..chunked_nodes_count)
                                    .into_par_iter()
                                    .map(|index| {
                                        (0..layers)
                                            .map(|layer_index| {
                                                bytes_into_fr(
                                                &layer_data[layer_index][std::mem::size_of::<Fr>()
                                                    * index
                                                    ..std::mem::size_of::<Fr>() * (index + 1)],
                                            )
                                            .expect("Could not create Fr from bytes.")
                                            })
                                            .collect::<GenericArray<Fr, ColumnArity>>()
                                    })
                                    .collect()
                            };

                            node_index += chunked_nodes_count;
                            trace!(
                                "node index {}/{}/{}",
                                node_index,
                                chunked_nodes_count,
                                nodes_count,
                            );

                            let is_final = node_index == nodes_count;
                            builder_tx
                                .send((columns, is_final))
                                .expect("failed to send columns");
                        }
                    }
                });
                s.spawn(move |_| {
                    let _gpu_lock = GPU_LOCK.lock().expect("failed to get gpu lock");
                    let column_batcher = Batcher::pick_gpu(max_gpu_column_batch_size)
                        .expect("failed to create column batcher");
                    let tree_batcher = Batcher::pick_gpu(max_gpu_tree_batch_size)
                        .expect("failed to create tree batcher");
                    let mut column_tree_builder = ColumnTreeBuilder::<ColumnArity, TreeArity>::new(
                        Some(column_batcher),
                        Some(tree_batcher),
                        nodes_count,
                    )
                    .expect("failed to create ColumnTreeBuilder");

                    // Loop until all trees for all configs have been built.
                    for i in 0..config_count {
                        loop {
                            let (columns, is_final): (Vec<GenericArray<Fr, ColumnArity>>, bool) =
                                builder_rx.recv().expect("failed to recv columns");

                            // Just add non-final column batches.
                            if !is_final {
                                column_tree_builder
                                    .add_columns(&columns)
                                    .expect("failed to add columns");
                                continue;
                            };

                            // If we get here, this is a final column: build a sub-tree.
                            let (base_data, tree_data) = column_tree_builder
                                .add_final_columns(&columns)
                                .expect("failed to add final columns");
                            trace!(
                                "base data len {}, tree data len {}",
                                base_data.len(),
                                tree_data.len()
                            );

                            let tree_len = base_data.len() + tree_data.len();
                            info!(
                                "persisting base tree_c {}/{} of length {}",
                                i + 1,
                                tree_count,
                                tree_len,
                            );

                            writer_tx
                                .send((base_data, tree_data))
                                .expect("failed to send base_data, tree_data");
                            break;
                        }
                    }
                });

                for config in &configs {
                    let (base_data, tree_data) = writer_rx
                        .recv()
                        .expect("failed to receive base_data, tree_data for tree_c");
                    let tree_len = base_data.len() + tree_data.len();

                    assert_eq!(base_data.len(), nodes_count);
                    assert_eq!(tree_len, config.size.expect("config size failure"));

                    // Persist the base and tree data to disk based using the current store config.
                    let tree_c_store_path = StoreConfig::data_path(&config.path, &config.id);
                    let tree_c_store_exists = Path::new(&tree_c_store_path).exists();
                    trace!(
                        "tree_c store path {:?} -- exists? {}",
                        tree_c_store_path,
                        tree_c_store_exists
                    );
                    if tree_c_store_exists {
                        std::fs::remove_file(&tree_c_store_path)
                            .expect("failed to remove tree_c_store_path");
                    }

                    let tree_c_store =
                        DiskStore::<<Tree::Hasher as Hasher>::Domain>::new_with_config(
                            tree_len,
                            Tree::Arity::to_usize(),
                            config.clone(),
                        )
                        .expect("failed to create DiskStore for base tree data");

                    let store = Arc::new(RwLock::new(tree_c_store));
                    let batch_size = min(base_data.len(), column_write_batch_size);
                    let flatten_and_write_store = |data: &Vec<Fr>, offset| {
                        data.into_par_iter()
                            .chunks(batch_size)
                            .enumerate()
                            .try_for_each(|(index, fr_elements)| {
                                let mut buf = Vec::with_capacity(batch_size * NODE_SIZE);

                                for fr in fr_elements {
                                    buf.extend(fr_into_bytes(&fr));
                                }
                                store
                                    .write()
                                    .expect("failed to access store for write")
                                    .copy_from_slice(&buf[..], offset + (batch_size * index))
                            })
                    };

                    trace!(
                        "flattening tree_c base data of {} nodes using batch size {}",
                        base_data.len(),
                        batch_size
                    );
                    flatten_and_write_store(&base_data, 0)
                        .expect("failed to flatten and write store");
                    trace!("done flattening tree_c base data");

                    let base_offset = base_data.len();
                    trace!("flattening tree_c tree data of {} nodes using batch size {} and base offset {}", tree_data.len(), batch_size, base_offset);
                    flatten_and_write_store(&tree_data, base_offset)
                        .expect("failed to flatten and write store");
                    trace!("done flattening tree_c tree data");

                    trace!("writing tree_c store data");
                    store
                        .write()
                        .expect("failed to access store for sync")
                        .sync()
                        .expect("store sync failure");
                    trace!("done writing tree_c store data");
                }
            });

            create_disk_tree::<
                DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >(configs[0].size.expect("config size failure"), &configs)
        })
    }

    fn generate_tree_c_cpu<ColumnArity, TreeArity>(
        layers: usize,
        nodes_count: usize,
        tree_count: usize,
        configs: Vec<StoreConfig>,
        labels: &LabelsCache<Tree>,
    ) -> Result<DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        ColumnArity: PoseidonArity,
        TreeArity: PoseidonArity,
    {
        info!("generating tree c using the CPU");
        measure_op(Operation::GenerateTreeC, || {
            info!("Building column hashes");

            let mut trees = Vec::with_capacity(tree_count);
            for (i, config) in configs.iter().enumerate() {
                let mut hashes: Vec<<Tree::Hasher as Hasher>::Domain> =
                    vec![<Tree::Hasher as Hasher>::Domain::default(); nodes_count];

                rayon::scope(|s| {
                    let n = num_cpus::get();

                    // only split if we have at least two elements per thread
                    let num_chunks = if n > nodes_count * 2 { 1 } else { n };

                    // chunk into n chunks
                    let chunk_size = (nodes_count as f64 / num_chunks as f64).ceil() as usize;

                    // calculate all n chunks in parallel
                    for (chunk, hashes_chunk) in hashes.chunks_mut(chunk_size).enumerate() {
                        let labels = &labels;

                        s.spawn(move |_| {
                            for (j, hash) in hashes_chunk.iter_mut().enumerate() {
                                let data: Vec<_> = (1..=layers)
                                    .map(|layer| {
                                        let store = labels.labels_for_layer(layer);
                                        let el: <Tree::Hasher as Hasher>::Domain = store
                                            .read_at((i * nodes_count) + j + chunk * chunk_size)
                                            .expect("store read_at failure");
                                        el.into()
                                    })
                                    .collect();

                                *hash = hash_single_column(&data).into();
                            }
                        });
                    }
                });

                info!("building base tree_c {}/{}", i + 1, tree_count);
                trees.push(
                    DiskTree::<Tree::Hasher, Tree::Arity, U0, U0>::from_par_iter_with_config(
                        hashes.into_par_iter(),
                        config.clone(),
                    ),
                );
            }

            assert_eq!(tree_count, trees.len());

            create_disk_tree::<
                DiskTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
            >(configs[0].size.expect("config size failure"), &configs)
        })
    }

    #[cfg(any(feature = "gpu"))]
    fn generate_tree_r_last<TreeArity>(
        data: &mut Data<'_>,
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
        labels: &LabelsCache<Tree>,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        TreeArity: PoseidonArity,
    {
        if SETTINGS.use_gpu_tree_builder {
            Self::generate_tree_r_last_gpu::<TreeArity>(
                data,
                nodes_count,
                tree_count,
                tree_r_last_config,
                replica_path,
                labels,
            )
        } else {
            Self::generate_tree_r_last_cpu::<TreeArity>(
                data,
                nodes_count,
                tree_count,
                tree_r_last_config,
                replica_path,
                labels,
            )
        }
    }

    #[cfg(not(any(feature = "gpu")))]
    fn generate_tree_r_last<TreeArity>(
        data: &mut Data<'_>,
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
        labels: &LabelsCache<Tree>,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        TreeArity: PoseidonArity,
    {
        Self::generate_tree_r_last_cpu::<TreeArity>(
            data,
            nodes_count,
            tree_count,
            tree_r_last_config,
            replica_path,
            labels,
        )
    }

    #[cfg(any(feature = "gpu"))]
    fn generate_tree_r_last_gpu<TreeArity>(
        data: &mut Data<'_>,
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
        labels: &LabelsCache<Tree>,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        TreeArity: PoseidonArity,
    {
        use std::cmp::min;
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::sync::mpsc::sync_channel;

        use bellperson::bls::Fr;
        use fr32::fr_into_bytes;
        use merkletree::merkle::{get_merkle_tree_cache_size, get_merkle_tree_leafs};
        use neptune::{
            batch_hasher::Batcher,
            tree_builder::{TreeBuilder, TreeBuilderTrait},
        };

        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path,
            nodes_count,
            tree_count,
        )?;

        data.ensure_data()?;
        let last_layer_labels = labels.labels_for_last_layer()?;

        info!("generating tree r last using the GPU");
        let max_gpu_tree_batch_size = SETTINGS.max_gpu_tree_batch_size as usize;

        // This channel will receive batches of leaf nodes and add them to the TreeBuilder.
        let (builder_tx, builder_rx) = sync_channel::<(Vec<Fr>, bool)>(0);
        let config_count = configs.len(); // Don't move config into closure below.
        let configs = &configs;
        let tree_r_last_config = &tree_r_last_config;
        rayon::scope(|s| {
            // This channel will receive the finished tree data to be written to disk.
            let (writer_tx, writer_rx) = sync_channel::<Vec<Fr>>(0);

            s.spawn(move |_| {
                for i in 0..config_count {
                    let mut node_index = 0;
                    while node_index != nodes_count {
                        let chunked_nodes_count =
                            min(nodes_count - node_index, max_gpu_tree_batch_size);
                        let start = (i * nodes_count) + node_index;
                        let end = start + chunked_nodes_count;
                        trace!(
                            "processing config {}/{} with leaf nodes {} [{}, {}, {}-{}]",
                            i + 1,
                            tree_count,
                            chunked_nodes_count,
                            node_index,
                            nodes_count,
                            start,
                            end,
                        );

                        let encoded_data = {
                            use fr32::bytes_into_fr;

                            let mut layer_bytes =
                                vec![0u8; (end - start) * std::mem::size_of::<Fr>()];
                            last_layer_labels
                                .read_range_into(start, end, &mut layer_bytes)
                                .expect("failed to read layer bytes");

                            layer_bytes
                                .into_par_iter()
                                .chunks(std::mem::size_of::<Fr>())
                                .map(|chunk| {
                                    bytes_into_fr(&chunk).expect("Could not create Fr from bytes.")
                                })
                                .zip(
                                    data.as_mut()[(start * NODE_SIZE)..(end * NODE_SIZE)]
                                        .par_chunks_mut(NODE_SIZE),
                                )
                                .map(|(key, data_node_bytes)| {
                                    let data_node =
                                        <Tree::Hasher as Hasher>::Domain::try_from_bytes(
                                            data_node_bytes,
                                        )
                                        .expect("try_from_bytes failed");

                                    let encoded_node = encode::<<Tree::Hasher as Hasher>::Domain>(
                                        key.into(),
                                        data_node,
                                    );
                                    data_node_bytes
                                        .copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));

                                    encoded_node
                                })
                        };

                        node_index += chunked_nodes_count;
                        trace!(
                            "node index {}/{}/{}",
                            node_index,
                            chunked_nodes_count,
                            nodes_count,
                        );

                        let encoded: Vec<_> =
                            encoded_data.into_par_iter().map(|x| x.into()).collect();

                        let is_final = node_index == nodes_count;
                        builder_tx
                            .send((encoded, is_final))
                            .expect("failed to send encoded");
                    }
                }
            });
            s.spawn(move |_| {
                let _gpu_lock = GPU_LOCK.lock().expect("failed to get gpu lock");
                let batcher =
                    Batcher::pick_gpu(max_gpu_tree_batch_size).expect("failed to create batcher");
                let mut tree_builder = TreeBuilder::<Tree::Arity>::new(
                    Some(batcher),
                    nodes_count,
                    tree_r_last_config.rows_to_discard,
                )
                .expect("failed to create TreeBuilder");

                // Loop until all trees for all configs have been built.
                for i in 0..config_count {
                    loop {
                        let (encoded, is_final) =
                            builder_rx.recv().expect("failed to recv encoded data");

                        // Just add non-final leaf batches.
                        if !is_final {
                            tree_builder
                                .add_leaves(&encoded)
                                .expect("failed to add leaves");
                            continue;
                        };

                        // If we get here, this is a final leaf batch: build a sub-tree.
                        info!(
                            "building base tree_r_last with GPU {}/{}",
                            i + 1,
                            tree_count
                        );
                        let (_, tree_data) = tree_builder
                            .add_final_leaves(&encoded)
                            .expect("failed to add final leaves");

                        writer_tx.send(tree_data).expect("failed to send tree_data");
                        break;
                    }
                }
            });

            for config in configs.iter() {
                let tree_data = writer_rx
                    .recv()
                    .expect("failed to receive tree_data for tree_r_last");

                let tree_data_len = tree_data.len();
                let cache_size = get_merkle_tree_cache_size(
                    get_merkle_tree_leafs(
                        config.size.expect("config size failure"),
                        Tree::Arity::to_usize(),
                    )
                    .expect("failed to get merkle tree leaves"),
                    Tree::Arity::to_usize(),
                    config.rows_to_discard,
                )
                .expect("failed to get merkle tree cache size");
                assert_eq!(tree_data_len, cache_size);

                let flat_tree_data: Vec<_> = tree_data
                    .into_par_iter()
                    .flat_map(|el| fr_into_bytes(&el))
                    .collect();

                // Persist the data to the store based on the current config.
                let tree_r_last_path = StoreConfig::data_path(&config.path, &config.id);
                trace!(
                    "persisting tree r of len {} with {} rows to discard at path {:?}",
                    tree_data_len,
                    config.rows_to_discard,
                    tree_r_last_path
                );
                let mut f = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&tree_r_last_path)
                    .expect("failed to open file for tree_r_last");
                f.write_all(&flat_tree_data)
                    .expect("failed to wrote tree_r_last data");
            }
        });

        create_lc_tree::<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>(
            tree_r_last_config.size.expect("config size failure"),
            &configs,
            &replica_config,
        )
    }

    fn generate_tree_r_last_cpu<TreeArity>(
        data: &mut Data<'_>,
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
        labels: &LabelsCache<Tree>,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        TreeArity: PoseidonArity,
    {
        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path,
            nodes_count,
            tree_count,
        )?;

        data.ensure_data()?;
        let last_layer_labels = labels.labels_for_last_layer()?;

        info!("generating tree r last using the CPU");
        let size = Store::len(last_layer_labels);

        let mut start = 0;
        let mut end = size / tree_count;

        for (i, config) in configs.iter().enumerate() {
            let encoded_data = last_layer_labels
                .read_range(start..end)?
                .into_par_iter()
                .zip(
                    data.as_mut()[(start * NODE_SIZE)..(end * NODE_SIZE)].par_chunks_mut(NODE_SIZE),
                )
                .map(|(key, data_node_bytes)| {
                    let data_node =
                        <Tree::Hasher as Hasher>::Domain::try_from_bytes(data_node_bytes)
                            .expect("try from bytes failed");
                    let encoded_node = encode::<<Tree::Hasher as Hasher>::Domain>(key, data_node);
                    data_node_bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));

                    encoded_node
                });

            info!(
                "building base tree_r_last with CPU {}/{}",
                i + 1,
                tree_count
            );

            // Remove the tree_r_last store if it exists already
            let tree_r_last_store_path = StoreConfig::data_path(&config.path, &config.id);
            let tree_r_last_store_exists = Path::new(&tree_r_last_store_path).exists();
            trace!(
                "tree_r_last store path {:?} -- exists? {}",
                tree_r_last_store_path,
                tree_r_last_store_exists
            );
            if tree_r_last_store_exists {
                std::fs::remove_file(&tree_r_last_store_path)
                    .expect("failed to remove tree_r_last_store_path");
            }

            LCTree::<Tree::Hasher, Tree::Arity, U0, U0>::from_par_iter_with_config(
                encoded_data,
                config.clone(),
            )
            .with_context(|| format!("failed tree_r_last CPU {}/{}", i + 1, tree_count))?;

            start = end;
            end += size / tree_count;
        }

        create_lc_tree::<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>(
            tree_r_last_config.size.expect("config size failure"),
            &configs,
            &replica_config,
        )
    }

    pub(crate) fn transform_and_replicate_layers(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        data: Data<'_>,
        data_tree: Option<BinaryMerkleTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<TransformedLayers<Tree, G>> {
        // Generate key layers.
        let labels = measure_op(Operation::EncodeWindowTimeAll, || {
            Self::generate_labels_for_encoding(graph, layer_challenges, replica_id, config.clone())
                .context("failed to generate labels")
        })?
        .0;

        Self::transform_and_replicate_layers_inner(
            graph,
            layer_challenges,
            data,
            data_tree,
            config,
            replica_path,
            labels,
        )
        .context("failed to transform")
    }

    pub(crate) fn transform_and_replicate_layers_inner(
        graph: &StackedBucketGraph<Tree::Hasher>,
        layer_challenges: &LayerChallenges,
        mut data: Data<'_>,
        data_tree: Option<BinaryMerkleTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
        label_configs: Labels<Tree>,
    ) -> Result<TransformedLayers<Tree, G>> {
        trace!("transform_and_replicate_layers");
        let nodes_count = graph.size();

        assert_eq!(data.len(), nodes_count * NODE_SIZE);
        trace!("nodes count {}, data len {}", nodes_count, data.len());

        let tree_count = get_base_tree_count::<Tree>();
        let nodes_count = graph.size() / tree_count;

        // Ensure that the node count will work for binary and oct arities.
        let binary_arity_valid = is_merkle_tree_size_valid(nodes_count, BINARY_ARITY);
        let other_arity_valid = is_merkle_tree_size_valid(nodes_count, Tree::Arity::to_usize());
        trace!(
            "is_merkle_tree_size_valid({}, BINARY_ARITY) = {}",
            nodes_count,
            binary_arity_valid
        );
        trace!(
            "is_merkle_tree_size_valid({}, {}) = {}",
            nodes_count,
            Tree::Arity::to_usize(),
            other_arity_valid
        );
        assert!(binary_arity_valid);
        assert!(other_arity_valid);

        let layers = layer_challenges.layers();
        assert!(layers > 0);

        // Generate all store configs that we need based on the
        // cache_path in the specified config.
        let mut tree_d_config = StoreConfig::from_config(
            &config,
            CacheKey::CommDTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, BINARY_ARITY)?),
        );
        tree_d_config.rows_to_discard = default_rows_to_discard(nodes_count, BINARY_ARITY);

        let mut tree_r_last_config = StoreConfig::from_config(
            &config,
            CacheKey::CommRLastTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?),
        );

        // A default 'rows_to_discard' value will be chosen for tree_r_last, unless the user overrides this value via the
        // environment setting (FIL_PROOFS_ROWS_TO_DISCARD).  If this value is specified, no checking is done on it and it may
        // result in a broken configuration.  Use with caution.  It must be noted that if/when this unchecked value is passed
        // through merkle_light, merkle_light now does a check that does not allow us to discard more rows than is possible
        // to discard.
        tree_r_last_config.rows_to_discard =
            default_rows_to_discard(nodes_count, Tree::Arity::to_usize());
        trace!(
            "tree_r_last using rows_to_discard={}",
            tree_r_last_config.rows_to_discard
        );

        let mut tree_c_config = StoreConfig::from_config(
            &config,
            CacheKey::CommCTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?),
        );
        tree_c_config.rows_to_discard =
            default_rows_to_discard(nodes_count, Tree::Arity::to_usize());

        let labels =
            LabelsCache::<Tree>::new(&label_configs).context("failed to create labels cache")?;
        let configs = split_config(tree_c_config.clone(), tree_count)?;

        match raise_fd_limit() {
            Some(res) => {
                info!("Building trees [{} descriptors max available]", res);
            }
            None => error!("Failed to raise the fd limit"),
        };

        let tree_c_root = match layers {
            2 => {
                let tree_c = Self::generate_tree_c::<U2, Tree::Arity>(
                    layers,
                    nodes_count,
                    tree_count,
                    configs,
                    &labels,
                )?;
                tree_c.root()
            }
            8 => {
                let tree_c = Self::generate_tree_c::<U8, Tree::Arity>(
                    layers,
                    nodes_count,
                    tree_count,
                    configs,
                    &labels,
                )?;
                tree_c.root()
            }
            11 => {
                let tree_c = Self::generate_tree_c::<U11, Tree::Arity>(
                    layers,
                    nodes_count,
                    tree_count,
                    configs,
                    &labels,
                )?;
                tree_c.root()
            }
            _ => panic_any("Unsupported column arity"),
        };
        info!("tree_c done");

        // Build the MerkleTree over the original data (if needed).
        let tree_d = match data_tree {
            Some(t) => {
                trace!("using existing original data merkle tree");
                assert_eq!(t.len(), 2 * (data.len() / NODE_SIZE) - 1);

                t
            }
            None => {
                trace!("building merkle tree for the original data");
                data.ensure_data()?;
                measure_op(Operation::CommD, || {
                    Self::build_binary_tree::<G>(data.as_ref(), tree_d_config.clone())
                })?
            }
        };
        tree_d_config.size = Some(tree_d.len());
        assert_eq!(
            tree_d_config.size.expect("config size failure"),
            tree_d.len()
        );
        let tree_d_root = tree_d.root();
        drop(tree_d);

        // Encode original data into the last layer.
        info!("building tree_r_last");
        let tree_r_last = measure_op(Operation::GenerateTreeRLast, || {
            Self::generate_tree_r_last::<Tree::Arity>(
                &mut data,
                nodes_count,
                tree_count,
                tree_r_last_config.clone(),
                replica_path.clone(),
                &labels,
            )
            .context("failed to generate tree_r_last")
        })?;
        info!("tree_r_last done");

        let tree_r_last_root = tree_r_last.root();
        drop(tree_r_last);

        data.drop_data();

        // comm_r = H(comm_c || comm_r_last)
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            <Tree::Hasher as Hasher>::Function::hash2(&tree_c_root, &tree_r_last_root);

        Ok((
            Tau {
                comm_d: tree_d_root,
                comm_r,
            },
            PersistentAux {
                comm_c: tree_c_root,
                comm_r_last: tree_r_last_root,
            },
            TemporaryAux {
                labels: label_configs,
                tree_d_config,
                tree_r_last_config,
                tree_c_config,
                _g: PhantomData,
            },
        ))
    }

    /// Phase1 of replication.
    pub fn replicate_phase1(
        pp: &'a PublicParams<Tree>,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        config: StoreConfig,
    ) -> Result<Labels<Tree>> {
        info!("replicate_phase1");

        let labels = measure_op(Operation::EncodeWindowTimeAll, || {
            Self::generate_labels_for_encoding(&pp.graph, &pp.layer_challenges, replica_id, config)
        })?
        .0;

        Ok(labels)
    }

    /// Phase2 of replication.
    #[allow(clippy::type_complexity)]
    pub fn replicate_phase2(
        pp: &'a PublicParams<Tree>,
        labels: Labels<Tree>,
        data: Data<'a>,
        data_tree: BinaryMerkleTree<G>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<(
        <Self as PoRep<'a, Tree::Hasher, G>>::Tau,
        <Self as PoRep<'a, Tree::Hasher, G>>::ProverAux,
    )> {
        info!("replicate_phase2");

        let (tau, paux, taux) = Self::transform_and_replicate_layers_inner(
            &pp.graph,
            &pp.layer_challenges,
            data,
            Some(data_tree),
            config,
            replica_path,
            labels,
        )?;

        Ok((tau, (paux, taux)))
    }

    // Assumes data is all zeros.
    // Replica path is used to create configs, but is not read.
    // Instead new zeros are provided (hence the need for replica to be all zeros).
    #[cfg(any(feature = "gpu"))]
    fn generate_fake_tree_r_last<TreeArity>(
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        TreeArity: PoseidonArity,
    {
        use std::fs::OpenOptions;
        use std::io::Write;

        use bellperson::bls::Fr;
        use ff::Field;
        use fr32::fr_into_bytes;
        use merkletree::merkle::{get_merkle_tree_cache_size, get_merkle_tree_leafs};
        use neptune::{
            batch_hasher::Batcher,
            tree_builder::{TreeBuilder, TreeBuilderTrait},
        };

        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path,
            nodes_count,
            tree_count,
        )?;

        if SETTINGS.use_gpu_tree_builder {
            info!("generating tree r last using the GPU");
            let max_gpu_tree_batch_size = SETTINGS.max_gpu_tree_batch_size as usize;

            let _gpu_lock = GPU_LOCK.lock().expect("failed to get gpu lock");
            let batcher =
                Batcher::pick_gpu(max_gpu_tree_batch_size).expect("failed to create batcher");
            let mut tree_builder = TreeBuilder::<Tree::Arity>::new(
                Some(batcher),
                nodes_count,
                tree_r_last_config.rows_to_discard,
            )
            .expect("failed to create TreeBuilder");

            // Allocate zeros once and reuse.
            let zero_leaves: Vec<Fr> = vec![Fr::zero(); max_gpu_tree_batch_size];
            for (i, config) in configs.iter().enumerate() {
                let mut consumed = 0;
                while consumed < nodes_count {
                    let batch_size = usize::min(max_gpu_tree_batch_size, nodes_count - consumed);

                    consumed += batch_size;

                    if consumed != nodes_count {
                        tree_builder
                            .add_leaves(&zero_leaves[0..batch_size])
                            .expect("failed to add leaves");
                        continue;
                    };

                    // If we get here, this is a final leaf batch: build a sub-tree.
                    info!(
                        "building base tree_r_last with GPU {}/{}",
                        i + 1,
                        tree_count
                    );

                    let (_, tree_data) = tree_builder
                        .add_final_leaves(&zero_leaves[0..batch_size])
                        .expect("failed to add final leaves");
                    let tree_data_len = tree_data.len();
                    let cache_size = get_merkle_tree_cache_size(
                        get_merkle_tree_leafs(
                            config.size.expect("config size failure"),
                            Tree::Arity::to_usize(),
                        )
                        .expect("failed to get merkle tree leaves"),
                        Tree::Arity::to_usize(),
                        config.rows_to_discard,
                    )
                    .expect("failed to get merkle tree cache size");
                    assert_eq!(tree_data_len, cache_size);

                    let flat_tree_data: Vec<_> = tree_data
                        .into_par_iter()
                        .flat_map(|el| fr_into_bytes(&el))
                        .collect();

                    // Persist the data to the store based on the current config.
                    let tree_r_last_path = StoreConfig::data_path(&config.path, &config.id);
                    trace!(
                        "persisting tree r of len {} with {} rows to discard at path {:?}",
                        tree_data_len,
                        config.rows_to_discard,
                        tree_r_last_path
                    );
                    let mut f = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .open(&tree_r_last_path)
                        .expect("failed to open file for tree_r_last");
                    f.write_all(&flat_tree_data)
                        .expect("failed to wrote tree_r_last data");
                }
            }
        } else {
            info!("generating tree r last using the CPU");
            for (i, config) in configs.iter().enumerate() {
                let encoded_data = vec![<Tree::Hasher as Hasher>::Domain::default(); nodes_count];

                info!(
                    "building base tree_r_last with CPU {}/{}",
                    i + 1,
                    tree_count
                );
                LCTree::<Tree::Hasher, Tree::Arity, U0, U0>::from_par_iter_with_config(
                    encoded_data,
                    config.clone(),
                )?;
            }
        };

        create_lc_tree::<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>(
            tree_r_last_config.size.expect("config size failure"),
            &configs,
            &replica_config,
        )
    }

    // Assumes data is all zeros.
    // Replica path is used to create configs, but is not read.
    // Instead new zeros are provided (hence the need for replica to be all zeros).
    #[cfg(not(any(feature = "gpu")))]
    fn generate_fake_tree_r_last<TreeArity>(
        nodes_count: usize,
        tree_count: usize,
        tree_r_last_config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>
    where
        TreeArity: PoseidonArity,
    {
        let (configs, replica_config) = split_config_and_replica(
            tree_r_last_config.clone(),
            replica_path,
            nodes_count,
            tree_count,
        )?;

        info!("generating tree r last using the CPU");
        for (i, config) in configs.iter().enumerate() {
            let encoded_data = vec![<Tree::Hasher as Hasher>::Domain::default(); nodes_count];

            info!(
                "building base tree_r_last with CPU {}/{}",
                i + 1,
                tree_count
            );
            LCTree::<Tree::Hasher, Tree::Arity, U0, U0>::from_par_iter_with_config(
                encoded_data,
                config.clone(),
            )?;
        }

        create_lc_tree::<LCTree<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>(
            tree_r_last_config.size.expect("config size failure"),
            &configs,
            &replica_config,
        )
    }

    pub fn fake_replicate_phase2<R: AsRef<Path>, S: AsRef<Path>>(
        tree_c_root: <Tree::Hasher as Hasher>::Domain,
        replica_path: R,
        cache_path: S,
        sector_size: usize,
    ) -> Result<(
        <Tree::Hasher as Hasher>::Domain,
        PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    )> {
        let leaf_count = sector_size / NODE_SIZE;
        let replica_pathbuf = PathBuf::from(replica_path.as_ref());
        assert_eq!(0, sector_size % NODE_SIZE);
        let tree_count = get_base_tree_count::<Tree>();
        let nodes_count = leaf_count / tree_count;

        let config = StoreConfig::new(
            cache_path.as_ref(),
            CacheKey::CommRLastTree.to_string(),
            default_rows_to_discard(nodes_count, Tree::Arity::to_usize()),
        );
        let tree_r_last_config = StoreConfig::from_config(
            &config,
            CacheKey::CommRLastTree.to_string(),
            Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?),
        );

        // Encode original data into the last layer.
        info!("building tree_r_last");
        let tree_r_last = Self::generate_fake_tree_r_last::<Tree::Arity>(
            nodes_count,
            tree_count,
            tree_r_last_config,
            replica_pathbuf,
        )?;
        info!("tree_r_last done");

        let tree_r_last_root = tree_r_last.root();
        drop(tree_r_last);

        // comm_r = H(comm_c || comm_r_last)
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            <Tree::Hasher as Hasher>::Function::hash2(&tree_c_root, &tree_r_last_root);

        let p_aux = PersistentAux {
            comm_c: tree_c_root,
            comm_r_last: tree_r_last_root,
        };

        Ok((comm_r, p_aux))
    }

    pub fn fake_comm_r<R: AsRef<Path>>(
        tree_c_root: <Tree::Hasher as Hasher>::Domain,
        existing_p_aux_path: R,
    ) -> Result<(
        <Tree::Hasher as Hasher>::Domain,
        PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    )> {
        let existing_p_aux: PersistentAux<<Tree::Hasher as Hasher>::Domain> = {
            let p_aux_bytes = fs::read(&existing_p_aux_path)?;

            deserialize(&p_aux_bytes)
        }?;

        let existing_comm_r_last = existing_p_aux.comm_r_last;

        // comm_r = H(comm_c || comm_r_last)
        let comm_r: <Tree::Hasher as Hasher>::Domain =
            <Tree::Hasher as Hasher>::Function::hash2(&tree_c_root, &existing_comm_r_last);

        let p_aux = PersistentAux {
            comm_c: tree_c_root,
            comm_r_last: existing_comm_r_last,
        };

        Ok((comm_r, p_aux))
    }
}
