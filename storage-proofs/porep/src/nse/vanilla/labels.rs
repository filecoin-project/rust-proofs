use anyhow::{ensure, Context, Result};
use generic_array::typenum::U0;
use itertools::Itertools;
use log::debug;
use merkletree::store::{Store, StoreConfig, StoreConfigDataVersion};
use rayon::prelude::*;
use rust_fil_nse_gpu as gpu;
use rust_fil_nse_gpu::NarrowStackedExpander;
use sha2raw::Sha256;
use storage_proofs_core::{
    hasher::{Domain, Hasher},
    merkle::{DiskStore, DiskTree, LCTree, MerkleTreeTrait, MerkleTreeWrapper},
    util::NODE_SIZE,
};

use super::{
    batch_hasher::{batch_hash, truncate_hash},
    butterfly_graph::ButterflyGraph,
    expander_graph::ExpanderGraph,
    Config,
};
use crate::encode;

pub type LCMerkleTree<Tree> =
    LCTree<<Tree as MerkleTreeTrait>::Hasher, <Tree as MerkleTreeTrait>::Arity, U0, U0>;
pub type MerkleTree<Tree> =
    DiskTree<<Tree as MerkleTreeTrait>::Hasher, <Tree as MerkleTreeTrait>::Arity, U0, U0>;

/// Encodes the provided data and returns the replica and a list of merkle trees for each layer.
pub fn encode_with_trees<Tree: 'static + MerkleTreeTrait>(
    config: &Config,
    mut store_configs: Vec<StoreConfig>,
    window_index: u32,
    replica_id: &<Tree::Hasher as Hasher>::Domain,
    data: &mut [u8],
) -> Result<(Vec<MerkleTree<Tree>>, LCMerkleTree<Tree>)> {
    let num_layers = config.num_layers();
    let mut trees = Vec::with_capacity(num_layers);

    assert_eq!(store_configs.len(), num_layers);
    let mut previous_layer = vec![0u8; config.window_size()];
    let mut current_layer = vec![0u8; config.window_size()];

    // 1. Construct the mask
    debug!("mask layer: {}", 1);
    mask_layer(config, window_index, replica_id, &mut previous_layer)
        .context("failed to construct the mask layer")?;

    let mask_config = store_configs.remove(0);

    debug!("mask layer tree");
    let mask_tree = tree_from_slice::<Tree>(&previous_layer, mask_config)
        .context("failed to construct merkle tree for the mask layer")?;
    trees.push(mask_tree);

    // 2. Construct expander layers
    for layer_index in 2..=(config.num_expander_layers as u32) {
        debug!("expander layer: {}", layer_index);
        expander_layer(
            config,
            window_index,
            replica_id,
            layer_index,
            &previous_layer,
            &mut current_layer,
        )
        .context("failed to construct expander layer")?;

        let store_config = store_configs.remove(0);
        debug!("expander layer tree");
        let tree = tree_from_slice::<Tree>(&current_layer, store_config)
            .context("failed to construct merkle tree for expander layer")?;
        trees.push(tree);

        // swap layers to reuse memory
        std::mem::swap(&mut previous_layer, &mut current_layer);
    }

    // 3. Construct butterfly layers
    for layer_index in (1 + config.num_expander_layers as u32)..(num_layers as u32) {
        debug!("butterfly layer: {}", layer_index);
        butterfly_layer(
            config,
            window_index,
            replica_id,
            layer_index,
            &previous_layer,
            &mut current_layer,
        )
        .context("failed to construct butterfly layer")?;

        let store_config = store_configs.remove(0);
        debug!("butterfly layer tree");
        let tree = tree_from_slice::<Tree>(&current_layer, store_config)
            .context("failed to construct merkle tree for butterfly layer")?;
        trees.push(tree);

        // swap layers to reuse memory
        std::mem::swap(&mut previous_layer, &mut current_layer);
    }

    // drop current, to reduce memory usage immediately
    drop(current_layer);

    // 4. Construct butterfly encoding layer
    let layer_index = num_layers as u32;

    debug!("replica layer: {}", layer_index);

    butterfly_encode_layer(
        config,
        window_index,
        replica_id,
        layer_index,
        &previous_layer,
        data,
    )
    .context("failed to construct butterfly encoding layer")?;

    // drop previous, to reduce memory usage immediately
    drop(previous_layer);

    let store_config = store_configs.remove(0);
    debug!("replica layer tree");
    let replica_tree = lc_tree_from_slice::<Tree>(data, store_config)
        .context("failed to construct merkle tree for butterfly encoding layer")?;

    Ok((trees, replica_tree))
}

/// Decodes the provided `encoded_data`, returning the decoded data.
pub fn decode<H: Hasher>(
    config: &Config,
    window_index: u32,
    replica_id: &H::Domain,
    encoded_data: &mut [u8],
) -> Result<()> {
    let num_layers = config.num_layers();

    let mut previous_layer = vec![0u8; config.window_size()];
    let mut current_layer = vec![0u8; config.window_size()];

    // 1. Construct the mask
    mask_layer(config, window_index, replica_id, &mut previous_layer)
        .context("failed to construct mask")?;

    // 2. Construct expander layers
    for layer_index in 2..=(config.num_expander_layers as u32) {
        expander_layer(
            config,
            window_index,
            replica_id,
            layer_index,
            &previous_layer,
            &mut current_layer,
        )
        .context("failed to construct expander layer")?;

        // swap layers to reuse memory
        std::mem::swap(&mut previous_layer, &mut current_layer);
    }

    // 3. Construct butterfly layers
    for layer_index in (1 + config.num_expander_layers as u32)..(num_layers as u32) {
        butterfly_layer(
            config,
            window_index,
            replica_id,
            layer_index,
            &previous_layer,
            &mut current_layer,
        )
        .context("failed to construct butterfly layer")?;

        // swap layers to reuse memory
        std::mem::swap(&mut previous_layer, &mut current_layer);
    }

    // 4. Construct butterfly encoding layer
    {
        let layer_index = num_layers as u32;

        butterfly_decode_layer(
            config,
            window_index,
            replica_id,
            layer_index,
            &previous_layer,
            encoded_data,
        )
        .context("failed to construct butterfly decoding layer")?;
    }

    Ok(())
}

/// Generate the mask layer, for one window.
fn mask_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_out: &mut [u8],
) -> Result<()> {
    ensure!(
        layer_out.len() == config.window_size(),
        "layer_out must be of size {}, got {}",
        config.window_size(),
        layer_out.len()
    );

    // The mask layer is always layer 1.
    const LAYER_INDEX: u32 = 1;

    // Construct the mask
    layer_out
        .par_chunks_mut(NODE_SIZE)
        .enumerate()
        .for_each(|(node_index, node)| {
            let node_absolute_index =
                window_index as u64 * config.num_nodes_window as u64 + node_index as u64;
            let prefix = hash_prefix(LAYER_INDEX, node_absolute_index);
            let hash = Sha256::digest(&[&prefix[..], AsRef::<[u8]>::as_ref(replica_id)]);
            node.copy_from_slice(&hash);
            truncate_hash(node);
        });

    Ok(())
}

/// Generate a single expander layer, for one window.
pub fn expander_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    layer_out: &mut [u8],
) -> Result<()> {
    ensure!(
        layer_in.len() == layer_out.len(),
        "layer_in and layer_out must of the same size"
    );
    ensure!(
        layer_out.len() == config.window_size(),
        "layer_out must be of size {}, got {}",
        config.window_size(),
        layer_out.len()
    );
    ensure!(
        layer_index > 1 && layer_index as usize <= config.num_expander_layers,
        "layer index must be in range (1, {}], got {}",
        config.num_expander_layers,
        layer_index,
    );

    let graph: ExpanderGraph = config.into();

    // Iterate over each node.
    layer_out
        .par_chunks_mut(NODE_SIZE)
        .enumerate()
        .for_each(|(node_index, node)| {
            if node_index % (1024 * 1024) == 0 {
                debug!(
                    "expander {} - {}/{}",
                    layer_index, node_index, config.num_nodes_window
                );
            }
            let node_index = node_index as u32;

            // Compute the parents for this node.
            let parents: Vec<_> = graph.expanded_parents(node_index).collect();

            let mut hasher = Sha256::new();

            // Hash prefix + replica id, each 32 bytes.
            let node_absolute_index =
                window_index as u64 * config.num_nodes_window as u64 + node_index as u64;
            let prefix = hash_prefix(layer_index, node_absolute_index);
            hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(replica_id)]);

            // Compute batch hash of the parents.
            let hash = batch_hash(
                config.k as usize,
                config.degree_expander,
                hasher,
                &parents,
                layer_in,
            );
            node.copy_from_slice(&hash);
        });

    Ok(())
}

/// Generate a single butterfly layer.
pub fn butterfly_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    layer_out: &mut [u8],
) -> Result<()> {
    ensure!(
        layer_in.len() == layer_out.len(),
        "layer_in and layer_out must of the same size"
    );
    ensure!(
        layer_out.len() == config.window_size(),
        "layer_out must be of size {}, got {}",
        config.window_size(),
        layer_out.len()
    );
    ensure!(
        layer_index as usize > config.num_expander_layers
            && (layer_index as usize) < config.num_expander_layers + config.num_butterfly_layers,
        "layer index must be in range ({}, {}), got {}",
        config.num_expander_layers,
        config.num_expander_layers + config.num_butterfly_layers,
        layer_index,
    );

    let graph: ButterflyGraph = config.into();

    // Iterate over each node.
    layer_out
        .par_chunks_mut(NODE_SIZE)
        .enumerate()
        .for_each(|(node_index, node)| {
            let node_index = node_index as u32;

            let mut hasher = Sha256::new();

            // Hash prefix + replica id, each 32 bytes.
            let node_absolute_index =
                window_index as u64 * config.num_nodes_window as u64 + node_index as u64;
            let prefix = hash_prefix(layer_index, node_absolute_index);
            hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(replica_id)]);

            // Compute hash of the parents.
            for (parent_a, parent_b) in graph.parents(node_index, layer_index).tuples() {
                let parent_a = parent_a as usize;
                let parent_b = parent_b as usize;
                let parent_a_value = &layer_in[parent_a * NODE_SIZE..(parent_a + 1) * NODE_SIZE];
                let parent_b_value = &layer_in[parent_b * NODE_SIZE..(parent_b + 1) * NODE_SIZE];

                hasher.input(&[parent_a_value, parent_b_value]);
            }

            let hash = hasher.finish();
            node.copy_from_slice(&hash);
            truncate_hash(node);
        });

    Ok(())
}

/// Generate a butterfly layer which additionally encodes using the data.
pub fn butterfly_encode_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    data: &mut [u8],
) -> Result<()> {
    butterfly_encode_decode_layer(
        config,
        window_index,
        replica_id,
        layer_index,
        layer_in,
        data,
        encode::encode,
    )
}

/// Generate a butterfly layer which additionally decodes using the data.
pub fn butterfly_decode_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    data: &mut [u8],
) -> Result<()> {
    butterfly_encode_decode_layer(
        config,
        window_index,
        replica_id,
        layer_index,
        layer_in,
        data,
        encode::decode,
    )
}

/// Generate a butterfly layer which additionally encodes or decodes using the data.
fn butterfly_encode_decode_layer<D: Domain, F: Fn(D, D) -> D>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    data: &mut [u8],
    op: F,
) -> Result<()> {
    ensure!(
        layer_in.len() == data.len(),
        "layer_in and data must of the same size"
    );
    ensure!(
        layer_in.len() == config.window_size(),
        "layer_in must be of size {}, got {}",
        config.window_size(),
        layer_in.len()
    );
    ensure!(
        layer_index as usize == config.num_expander_layers + config.num_butterfly_layers,
        "encoding must be on the last layer"
    );

    let graph: ButterflyGraph = config.into();

    // Iterate over each node.
    for (node_index, data_node) in data.chunks_mut(NODE_SIZE).enumerate() {
        let node_index = node_index as u32;

        let mut hasher = Sha256::new();

        // Hash prefix + replica id, each 32 bytes.
        let node_absolute_index =
            window_index as u64 * config.num_nodes_window as u64 + node_index as u64;
        let prefix = hash_prefix(layer_index, node_absolute_index);
        hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(replica_id)]);

        // Compute hash of the parents.
        for (parent_a, parent_b) in graph.parents(node_index, layer_index).tuples() {
            let parent_a = parent_a as usize;
            let parent_b = parent_b as usize;
            let parent_a_value = &layer_in[parent_a * NODE_SIZE..(parent_a + 1) * NODE_SIZE];
            let parent_b_value = &layer_in[parent_b * NODE_SIZE..(parent_b + 1) * NODE_SIZE];

            hasher.input(&[parent_a_value, parent_b_value]);
        }

        let mut key = hasher.finish();
        truncate_hash(&mut key);

        // encode
        let key = D::try_from_bytes(&key)?;
        let data_node_fr = D::try_from_bytes(data_node)?;
        let encoded_node = op(key, data_node_fr);

        // write result
        data_node.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));
    }

    Ok(())
}

/// Constructs the first 32 byte prefix for hashing any node.
pub fn hash_prefix(layer: u32, node_index: u64) -> [u8; 32] {
    let mut prefix = [0u8; 32];
    // layer: 32bits
    prefix[..4].copy_from_slice(&layer.to_be_bytes());
    // absolute_node_index: 64bits
    prefix[4..12].copy_from_slice(&node_index.to_be_bytes());
    // 0 padding for the rest

    prefix
}

/// Construct a tree from the given byte slice.
fn lc_tree_from_slice<Tree: MerkleTreeTrait>(
    data: &[u8],
    config: StoreConfig,
) -> Result<LCMerkleTree<Tree>> {
    MerkleTreeWrapper::from_par_iter_with_config(
        data.par_chunks(NODE_SIZE)
            .map(|node| <Tree::Hasher as Hasher>::Domain::try_from_bytes(node).unwrap()),
        config,
    )
}

/// Construct a tree from the given byte slice.
fn tree_from_slice<Tree: MerkleTreeTrait>(
    data: &[u8],
    config: StoreConfig,
) -> Result<MerkleTree<Tree>> {
    let mut tree = MerkleTreeWrapper::from_par_iter_with_config(
        data.par_chunks(NODE_SIZE)
            .map(|node| <Tree::Hasher as Hasher>::Domain::try_from_bytes(node).unwrap()),
        config.clone(),
    )?;

    // compact the thing
    tree.compact(config, StoreConfigDataVersion::One as u32)?;

    Ok(tree)
}

fn to_gpu_config(conf: &Config) -> gpu::Config {
    gpu::Config {
        num_nodes_window: conf.num_nodes_window,
        num_butterfly_layers: conf.num_butterfly_layers,
        num_expander_layers: conf.num_expander_layers,
        degree_expander: conf.degree_expander,
        degree_butterfly: conf.degree_butterfly,
        k: conf.k,
    }
}

type GPUHasherDomain = storage_proofs_core::hasher::PoseidonDomain;
type GPUHasher = storage_proofs_core::hasher::PoseidonHasher;
type GPUTree = storage_proofs_core::merkle::OctLCMerkleTree<GPUHasher>;
pub fn encode_with_oct_lc_poseidon_trees_gpu<'a, I>(
    conf: &Config,
    inps: I,
) -> gpu::NSEResult<Vec<(Vec<MerkleTree<GPUTree>>, LCMerkleTree<GPUTree>)>>
where
    I: Iterator<Item = (Vec<StoreConfig>, u32, GPUHasherDomain, &'a mut [u8])>,
{
    use storage_proofs_core::fr32::fr_into_bytes;
    let gpu_conf = to_gpu_config(conf);
    let pool = gpu::SealerPool::new(
        gpu::utils::all_devices()?,
        gpu_conf,
        gpu::TreeOptions::Enabled { rows_to_discard: 0 },
    )?;

    let outputs = inps
        .map(|(store_configs, window_index, replica_id, data)| {
            let inp = gpu::SealerInput {
                replica_id: unsafe { std::mem::transmute::<_, gpu::ReplicaId>(replica_id) },
                window_index: window_index as usize,
                original_data: gpu::Layer::from(&data.to_vec()),
            };
            (store_configs, data, pool.seal_on_gpu(inp))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|(mut store_configs, data, chan)| -> gpu::NSEResult<(Vec<MerkleTree<GPUTree>>, LCMerkleTree<GPUTree>)> {
            let layers = chan.iter().collect::<gpu::NSEResult<Vec<_>>>()?;
            data.copy_from_slice(Vec::<u8>::from(&layers.last().unwrap().base).as_slice());
            let tree_len = layers[0].tree.len() + layers[0].base.0.len();

            let mut tree_data = Vec::new();
            for lo in layers.iter() {
                let data: Vec<u8> = lo
                    .base
                    .0
                    .iter()
                    .chain(lo.tree.iter())
                    .flat_map(|node| fr_into_bytes(&node.0))
                    .collect();
                tree_data.push(data);
            }

            let _replica_data = tree_data.pop().unwrap();

            let mut trees = Vec::new();
            for data in tree_data {
                let store_config = store_configs.remove(0);
                let mut store = DiskStore::<GPUHasherDomain>::new_with_config(
                    tree_len,
                    8,
                    store_config.clone(),
                )
                .unwrap();
                store.copy_from_slice(&data[..], 0).unwrap();
                trees.push(
                    MerkleTree::<GPUTree>::from_data_store(store, conf.num_nodes_window).unwrap(),
                );
            }

            let store_config = store_configs.remove(0);
            let replica_tree = lc_tree_from_slice::<GPUTree>(&data, store_config).unwrap();
            //let mut store =
            //    LCStore::<GPUHasherDomain>::new_with_config(tree_len, 8, store_config.clone()).unwrap();
            //store.copy_from_slice(&replica_data[..], 0).unwrap();
            //let replica_tree =
            //    LCMerkleTree::<GPUTree>::from_data_store(store, conf.num_nodes_window).unwrap();

            Ok((trees, replica_tree))
        })
        .collect::<gpu::NSEResult<Vec<_>>>()?;

    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use paired::bls12_381::Fr;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        cache_key::CacheKey,
        fr32::fr_into_bytes,
        hasher::{PoseidonDomain, PoseidonHasher, Sha256Domain},
        merkle::{split_config, OctLCMerkleTree},
    };

    fn sample_config() -> Config {
        Config {
            k: 8,
            num_nodes_window: 2048 / 32,
            degree_expander: 12,
            degree_butterfly: 4,
            num_expander_layers: 6,
            num_butterfly_layers: 4,
            sector_size: 2048 * 8,
        }
    }

    #[test]
    fn test_mask_layer() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = sample_config();
        let replica_id: Sha256Domain = Fr::random(rng).into();
        let window_index = rng.gen();

        let mut layer: Vec<u8> = (0..config.window_size()).map(|_| rng.gen()).collect();

        mask_layer(&config, window_index, &replica_id, &mut layer).unwrap();

        assert!(!layer.iter().all(|&byte| byte == 0), "must not all be zero");
    }

    #[test]
    fn test_expander_layer() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = sample_config();
        let replica_id: Sha256Domain = Fr::random(rng).into();
        let window_index = rng.gen();
        let layer_index = rng.gen_range(2, config.num_expander_layers as u32);

        let layer_in: Vec<u8> = (0..config.num_nodes_window)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();
        let mut layer_out = vec![0u8; config.window_size()];

        expander_layer(
            &config,
            window_index,
            &replica_id,
            layer_index,
            &layer_in,
            &mut layer_out,
        )
        .unwrap();

        assert!(
            !layer_out.iter().all(|&byte| byte == 0),
            "must not all be zero"
        );
    }

    #[test]
    fn test_butterfly_layer() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = sample_config();
        let replica_id: Sha256Domain = Fr::random(rng).into();
        let window_index = rng.gen();
        let layer_index = rng.gen_range(
            config.num_expander_layers,
            config.num_expander_layers + config.num_butterfly_layers,
        ) as u32;

        let layer_in: Vec<u8> = (0..config.num_nodes_window)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();
        let mut layer_out = vec![0u8; config.window_size()];

        butterfly_layer(
            &config,
            window_index,
            &replica_id,
            layer_index,
            &layer_in,
            &mut layer_out,
        )
        .unwrap();

        assert!(
            !layer_out.iter().all(|&byte| byte == 0),
            "must not all be zero"
        );
    }

    #[test]
    fn test_butterfly_encode_decode_layer() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = sample_config();
        let replica_id: Sha256Domain = Fr::random(rng).into();
        let window_index = rng.gen();
        let layer_index = (config.num_expander_layers + config.num_butterfly_layers) as u32;

        let data: Vec<u8> = (0..config.num_nodes_window)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let layer_in: Vec<u8> = (0..config.num_nodes_window)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let mut layer_out = data.clone();

        butterfly_encode_layer(
            &config,
            window_index,
            &replica_id,
            layer_index,
            &layer_in,
            &mut layer_out,
        )
        .unwrap();

        assert!(
            !layer_out.iter().all(|&byte| byte == 0),
            "must not all be zero"
        );

        butterfly_decode_layer(
            &config,
            window_index,
            &replica_id,
            layer_index,
            &layer_in,
            &mut layer_out,
        )
        .unwrap();
        assert_eq!(data, layer_out, "failed to decode");
    }

    #[test]
    fn test_encode_decode_layer() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = sample_config();
        let replica_id: PoseidonDomain = Fr::random(rng).into();
        let window_index = rng.gen();

        let data: Vec<u8> = (0..config.num_nodes_window)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let cache_dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_rows_to_discard(config.num_nodes_window as usize, 8),
        );
        let mut encoded_data = data.clone();

        let store_configs = split_config(store_config.clone(), config.num_layers()).unwrap();

        let (trees, _replica_tree) = encode_with_trees::<OctLCMerkleTree<PoseidonHasher>>(
            &config,
            store_configs,
            window_index,
            &replica_id,
            &mut encoded_data,
        )
        .unwrap();
        assert_eq!(
            trees.len(),
            config.num_expander_layers + config.num_butterfly_layers - 1
        );
        assert_ne!(data, encoded_data, "failed to encode");

        decode::<PoseidonHasher>(&config, window_index, &replica_id, &mut encoded_data).unwrap();
        assert_eq!(data, encoded_data, "failed to decode");
    }

    #[test]
    fn test_hash_prefix() {
        assert_eq!(hash_prefix(0, 0), [0u8; 32]);
        assert_eq!(
            hash_prefix(1, 6),
            [
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_gpu_cpu_consistency() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = Config {
            k: 2,
            num_nodes_window: 512,
            degree_expander: 96,
            degree_butterfly: 4,
            num_expander_layers: 4,
            num_butterfly_layers: 3,
            sector_size: 2048 * 8,
        };

        let replica_id: PoseidonDomain = Fr::random(rng).into();
        let window_index = rng.gen();

        let data: Vec<u8> = (0..config.num_nodes_window)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let cpu_cache_dir = tempfile::tempdir().unwrap();
        let cpu_store_config = StoreConfig::new(
            cpu_cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_rows_to_discard(config.num_nodes_window as usize, 8),
        );
        let mut cpu_encoded_data = data.clone();

        let cpu_store_configs =
            split_config(cpu_store_config.clone(), config.num_layers()).unwrap();

        let (cpu_trees, cpu_replica_tree) = encode_with_trees::<OctLCMerkleTree<PoseidonHasher>>(
            &config,
            cpu_store_configs,
            window_index,
            &replica_id,
            &mut cpu_encoded_data,
        )
        .unwrap();
        let cpu_roots = cpu_trees.into_iter().map(|t| t.root()).collect::<Vec<_>>();
        let cpu_replica_root = cpu_replica_tree.root();

        let gpu_cache_dir = tempfile::tempdir().unwrap();
        let gpu_store_config = StoreConfig::new(
            gpu_cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_rows_to_discard(config.num_nodes_window as usize, 8),
        );
        let mut gpu_encoded_data = data.clone();

        let gpu_store_configs =
            split_config(gpu_store_config.clone(), config.num_layers()).unwrap();

        let (gpu_trees, gpu_replica_tree) = &encode_with_oct_lc_poseidon_trees_gpu(
            &config,
            vec![(
                gpu_store_configs,
                window_index,
                replica_id,
                &mut gpu_encoded_data[..],
            )]
            .into_iter(),
        )
        .unwrap()[0];

        let gpu_roots = gpu_trees.into_iter().map(|t| t.root()).collect::<Vec<_>>();
        let gpu_replica_root = gpu_replica_tree.root();

        assert_eq!(cpu_encoded_data, gpu_encoded_data);
        assert_eq!(cpu_roots, gpu_roots);
        assert_eq!(cpu_replica_root, gpu_replica_root);
    }
}
