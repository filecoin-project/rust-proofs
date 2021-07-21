use std::fs::remove_file;

use bellperson::bls::{Fr, FrRepr};
use ff::{Field, PrimeField};
use filecoin_hashers::{
    blake2s::Blake2sHasher, poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain, Hasher,
};
use fr32::fr_into_bytes;
use generic_array::typenum::{U0, U2, U4, U8};
use glob::glob;
use merkletree::store::{Store, StoreConfig};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    cache_key::CacheKey,
    drgraph::BASE_DEGREE,
    merkle::{get_base_tree_count, DiskTree, MerkleTreeTrait},
    proof::ProofScheme,
    table_tests,
    test_helper::setup_replica,
    util::{default_rows_to_discard, NODE_SIZE},
    TEST_SEED,
};
use storage_proofs_porep::{
    stacked::{
        LayerChallenges, PrivateInputs, PublicInputs, SetupParams, StackedBucketGraph, StackedDrg,
        TemporaryAux, TemporaryAuxCache, BINARY_ARITY, EXP_DEGREE,
    },
    PoRep,
};
use tempfile::tempdir;

const DEFAULT_STACKED_LAYERS: usize = 11;

#[test]
fn test_stacked_porep_extract_all_sha256_base_8() {
    test_extract_all::<DiskTree<Sha256Hasher, U8, U0, U0>>();
}

#[test]
fn test_stacked_porep_extract_all_sha256_sub_8_8() {
    test_extract_all::<DiskTree<Sha256Hasher, U8, U8, U0>>();
}

#[test]
fn test_stacked_porep_extract_all_sha256_top_8_8_2() {
    test_extract_all::<DiskTree<Sha256Hasher, U8, U8, U2>>();
}

#[test]
fn test_stacked_porep_extract_all_blake2s_base_8() {
    test_extract_all::<DiskTree<Blake2sHasher, U8, U0, U0>>();
}

#[test]
fn test_stacked_porep_extract_all_blake2s_sub_8_8() {
    test_extract_all::<DiskTree<Blake2sHasher, U8, U8, U0>>();
}

#[test]
fn test_stacked_porep_extract_all_blake2s_top_8_8_2() {
    test_extract_all::<DiskTree<Blake2sHasher, U8, U8, U2>>();
}

#[test]
fn test_stacked_porep_extract_all_poseidon_base_8() {
    test_extract_all::<DiskTree<PoseidonHasher, U8, U0, U0>>();
}

#[test]
fn test_stacked_porep_extract_all_poseidon_sub_8_2() {
    test_extract_all::<DiskTree<PoseidonHasher, U8, U2, U0>>();
}

#[test]
fn test_stacked_porep_extract_all_poseidon_top_8_8_2() {
    test_extract_all::<DiskTree<PoseidonHasher, U8, U8, U2>>();
}

fn test_extract_all<Tree: 'static + MerkleTreeTrait>() {
    //  pretty_env_logger::try_init();

    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let replica_id: <Tree::Hasher as Hasher>::Domain =
        <Tree::Hasher as Hasher>::Domain::random(rng);
    let nodes = 64 * get_base_tree_count::<Tree>();

    let data: Vec<u8> = (0..nodes)
        .flat_map(|_| {
            let v = <Tree::Hasher as Hasher>::Domain::random(rng);
            v.into_bytes()
        })
        .collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempdir().expect("tempdir failure");
    let config = StoreConfig::new(
        cache_dir.path(),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(nodes, BINARY_ARITY),
    );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let layer_challenges = LayerChallenges::new(DEFAULT_STACKED_LAYERS, 5);

    let sp = SetupParams {
        nodes,
        degree: BASE_DEGREE,
        expansion_degree: EXP_DEGREE,
        porep_id: [32; 32],
        layer_challenges: layer_challenges.clone(),
        api_version: ApiVersion::V1_1_0,
    };

    let pp = StackedDrg::<Tree, Blake2sHasher>::setup(&sp).expect("setup failed");

    StackedDrg::<Tree, Blake2sHasher>::replicate(
        &pp,
        &replica_id,
        (mmapped_data.as_mut()).into(),
        None,
        config.clone(),
        replica_path,
    )
    .expect("replication failed");

    // The layers are still in the cache dir, so rerunning the label generation should
    // not do any work.

    let (_, label_states) = StackedDrg::<Tree, Blake2sHasher>::generate_labels_for_encoding(
        &pp.graph,
        &layer_challenges,
        &replica_id,
        config.clone(),
    )
    .expect("label generation failed");
    for state in &label_states {
        assert!(state.generated);
    }
    // delete last 2 layers
    let off = label_states.len() - 3;
    for label_state in &label_states[off..] {
        let config = &label_state.config;
        let data_path = StoreConfig::data_path(&config.path, &config.id);
        remove_file(data_path).expect("failed to delete layer cache");
    }

    let (_, label_states) = StackedDrg::<Tree, Blake2sHasher>::generate_labels_for_encoding(
        &pp.graph,
        &layer_challenges,
        &replica_id,
        config.clone(),
    )
    .expect("label generation failed");
    for state in &label_states[..off] {
        assert!(state.generated);
    }
    for state in &label_states[off..] {
        assert!(!state.generated);
    }

    assert_ne!(data, &mmapped_data[..], "replication did not change data");

    StackedDrg::<Tree, Blake2sHasher>::extract_all(
        &pp,
        &replica_id,
        mmapped_data.as_mut(),
        Some(config),
    )
    .expect("failed to extract data");

    assert_eq!(data, mmapped_data.as_ref());

    cache_dir.close().expect("Failed to remove cache dir");
}

#[test]
fn test_stacked_porep_resume_seal() {
    //pretty_env_logger::try_init().ok();

    type Tree = DiskTree<PoseidonHasher, U8, U8, U2>;

    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let replica_id = <PoseidonHasher as Hasher>::Domain::random(rng);
    let nodes = 64 * get_base_tree_count::<Tree>();

    let data: Vec<u8> = (0..nodes)
        .flat_map(|_| {
            let v = <PoseidonHasher as Hasher>::Domain::random(rng);
            v.into_bytes()
        })
        .collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempdir().expect("tempdir failure");
    let config = StoreConfig::new(
        cache_dir.path(),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(nodes, BINARY_ARITY),
    );

    // Generate a replica path.
    let replica_path1 = cache_dir.path().join("replica-path-1");
    let replica_path2 = cache_dir.path().join("replica-path-2");
    let replica_path3 = cache_dir.path().join("replica-path-3");
    let mut mmapped_data1 = setup_replica(&data, &replica_path1);
    let mut mmapped_data2 = setup_replica(&data, &replica_path2);
    let mut mmapped_data3 = setup_replica(&data, &replica_path3);

    let layer_challenges = LayerChallenges::new(DEFAULT_STACKED_LAYERS, 5);

    let sp = SetupParams {
        nodes,
        degree: BASE_DEGREE,
        expansion_degree: EXP_DEGREE,
        porep_id: [32; 32],
        layer_challenges: layer_challenges.clone(),
        api_version: ApiVersion::V1_1_0,
    };

    let pp = StackedDrg::<Tree, Blake2sHasher>::setup(&sp).expect("setup failed");

    let clear_temp = || {
        for entry in glob(&(cache_dir.path().to_string_lossy() + "/*.dat")).unwrap() {
            let entry = entry.unwrap();
            if entry.is_file() {
                // delete everything except the data-layers
                if !entry.to_string_lossy().contains("data-layer") {
                    remove_file(entry).unwrap();
                }
            }
        }
    };

    // first replicaton
    StackedDrg::<Tree, Blake2sHasher>::replicate(
        &pp,
        &replica_id,
        (mmapped_data1.as_mut()).into(),
        None,
        config.clone(),
        replica_path1,
    )
    .expect("replication failed 1");
    clear_temp();

    // replicate a second time
    StackedDrg::<Tree, Blake2sHasher>::replicate(
        &pp,
        &replica_id,
        (mmapped_data2.as_mut()).into(),
        None,
        config.clone(),
        replica_path2,
    )
    .expect("replication failed 2");
    clear_temp();

    // delete last 2 layers
    let (_, label_states) = StackedDrg::<Tree, Blake2sHasher>::generate_labels_for_encoding(
        &pp.graph,
        &layer_challenges,
        &replica_id,
        config.clone(),
    )
    .expect("label generation failed");
    let off = label_states.len() - 3;
    for label_state in &label_states[off..] {
        let config = &label_state.config;
        let data_path = StoreConfig::data_path(&config.path, &config.id);
        remove_file(data_path).expect("failed to delete layer cache");
    }

    // replicate a third time
    StackedDrg::<Tree, Blake2sHasher>::replicate(
        &pp,
        &replica_id,
        (mmapped_data3.as_mut()).into(),
        None,
        config.clone(),
        replica_path3,
    )
    .expect("replication failed 3");
    clear_temp();

    assert_ne!(data, &mmapped_data1[..], "replication did not change data");

    assert_eq!(&mmapped_data1[..], &mmapped_data2[..]);
    assert_eq!(&mmapped_data2[..], &mmapped_data3[..]);

    StackedDrg::<Tree, Blake2sHasher>::extract_all(
        &pp,
        &replica_id,
        mmapped_data1.as_mut(),
        Some(config),
    )
    .expect("failed to extract data");

    assert_eq!(data, mmapped_data1.as_ref());

    cache_dir.close().expect("Failed to remove cache dir");
}

table_tests! {
    test_prove_verify_fixed {
       test_stacked_porep_prove_verify(64);
    }
}

fn test_prove_verify_fixed(n: usize) {
    let challenges = LayerChallenges::new(DEFAULT_STACKED_LAYERS, 5);

    test_prove_verify::<DiskTree<Sha256Hasher, U8, U0, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<Sha256Hasher, U8, U2, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<Sha256Hasher, U8, U8, U2>>(n, challenges.clone());

    test_prove_verify::<DiskTree<Sha256Hasher, U4, U0, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<Sha256Hasher, U4, U2, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<Sha256Hasher, U4, U8, U2>>(n, challenges.clone());

    test_prove_verify::<DiskTree<Blake2sHasher, U4, U0, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<Blake2sHasher, U4, U2, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<Blake2sHasher, U4, U8, U2>>(n, challenges.clone());

    test_prove_verify::<DiskTree<Blake2sHasher, U8, U0, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<Blake2sHasher, U8, U2, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<Blake2sHasher, U8, U8, U2>>(n, challenges.clone());

    test_prove_verify::<DiskTree<PoseidonHasher, U4, U0, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<PoseidonHasher, U4, U2, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<PoseidonHasher, U4, U8, U2>>(n, challenges.clone());

    test_prove_verify::<DiskTree<PoseidonHasher, U8, U0, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<PoseidonHasher, U8, U2, U0>>(n, challenges.clone());
    test_prove_verify::<DiskTree<PoseidonHasher, U8, U8, U2>>(n, challenges);
}

fn test_prove_verify<Tree: 'static + MerkleTreeTrait>(n: usize, challenges: LayerChallenges) {
    // This will be called multiple times, only the first one succeeds, and that is ok.
    // femme::pretty::Logger::new()
    //     .start(log::LevelFilter::Trace)
    //     .ok();

    let nodes = n * get_base_tree_count::<Tree>();
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let degree = BASE_DEGREE;
    let expansion_degree = EXP_DEGREE;
    let replica_id: <Tree::Hasher as Hasher>::Domain =
        <Tree::Hasher as Hasher>::Domain::random(rng);
    let data: Vec<u8> = (0..nodes)
        .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
        .collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempdir().expect("tempdir failure");
    let config = StoreConfig::new(
        cache_dir.path(),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(nodes, BINARY_ARITY),
    );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let partitions = 2;

    let arbitrary_porep_id = [92; 32];
    let sp = SetupParams {
        nodes,
        degree,
        expansion_degree,
        porep_id: arbitrary_porep_id,
        layer_challenges: challenges,
        api_version: ApiVersion::V1_1_0,
    };

    let pp = StackedDrg::<Tree, Blake2sHasher>::setup(&sp).expect("setup failed");
    let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, Blake2sHasher>::replicate(
        &pp,
        &replica_id,
        (mmapped_data.as_mut()).into(),
        None,
        config,
        replica_path.clone(),
    )
    .expect("replication failed");

    let mut copied = vec![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne!(data, copied, "replication did not change data");

    let seed = rng.gen();
    let pub_inputs =
        PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Blake2sHasher as Hasher>::Domain> {
            replica_id,
            seed,
            tau: Some(tau),
            k: None,
        };

    // Store a copy of the t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, Blake2sHasher>::new(&t_aux, replica_path)
        .expect("failed to restore contents of t_aux");

    let priv_inputs = PrivateInputs { p_aux, t_aux };

    let all_partition_proofs = &StackedDrg::<Tree, Blake2sHasher>::prove_all_partitions(
        &pp,
        &pub_inputs,
        &priv_inputs,
        partitions,
    )
    .expect("failed to generate partition proofs");

    let proofs_are_valid = StackedDrg::<Tree, Blake2sHasher>::verify_all_partitions(
        &pp,
        &pub_inputs,
        all_partition_proofs,
    )
    .expect("failed to verify partition proofs");

    // Discard cached MTs that are no longer needed.
    TemporaryAux::<Tree, Blake2sHasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

    assert!(proofs_are_valid);

    cache_dir.close().expect("Failed to remove cache dir");
}

// We are seeing a bug, in which setup never terminates for some sector sizes. This test is to
// debug that and should remain as a regression test.
#[test]
fn test_stacked_porep_setup_terminates() {
    let degree = BASE_DEGREE;
    let expansion_degree = EXP_DEGREE;
    let nodes = 1024 * 1024 * 32 * 8; // This corresponds to 8GiB sectors (32-byte nodes)
    let layer_challenges = LayerChallenges::new(10, 333);
    let sp = SetupParams {
        nodes,
        degree,
        expansion_degree,
        porep_id: [32; 32],
        layer_challenges,
        api_version: ApiVersion::V1_1_0,
    };

    // When this fails, the call to setup should panic, but seems to actually hang (i.e. neither return nor panic) for some reason.
    // When working as designed, the call to setup returns without error.
    let _pp = StackedDrg::<DiskTree<Sha256Hasher, U8, U0, U0>, Blake2sHasher>::setup(&sp)
        .expect("setup failed");
}

#[test]
fn test_stacked_porep_generate_labels() {
    let layers = 11;
    let nodes_2k = 1 << 11;
    let nodes_4k = 1 << 12;
    let replica_id = [9u8; 32];
    let legacy_porep_id = [0; 32];
    let porep_id = [123; 32];
    test_generate_labels_aux(
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
        .unwrap(),
    );

    test_generate_labels_aux(
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
        .unwrap(),
    );

    test_generate_labels_aux(
        nodes_2k,
        layers,
        replica_id,
        porep_id,
        ApiVersion::V1_1_0,
        Fr::from_repr(FrRepr([
            0xabb3f38bb70defcf,
            0x777a2e4d7769119f,
            0x3448959d495490bc,
            0x06021188c7a71cb5,
        ]))
        .unwrap(),
    );

    test_generate_labels_aux(
        nodes_4k,
        layers,
        replica_id,
        porep_id,
        ApiVersion::V1_1_0,
        Fr::from_repr(FrRepr([
            0x22ab81cf68c4676d,
            0x7a77a82fc7c9c189,
            0xc6c03d32c1e42d23,
            0x0f777c18cc2c55bd,
        ]))
        .unwrap(),
    );
}

fn test_generate_labels_aux(
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
    .unwrap();

    let unused_layer_challenges = LayerChallenges::new(layers, 0);

    let labels = StackedDrg::<
        // Although not generally correct for every size, the hasher shape is not used,
        // so for purposes of testing label creation, it is safe to supply a dummy.
        DiskTree<PoseidonHasher, U8, U8, U2>,
        Sha256Hasher,
    >::generate_labels_for_decoding(
        &graph,
        &unused_layer_challenges,
        &<PoseidonHasher as Hasher>::Domain::try_from_bytes(&replica_id).unwrap(),
        config,
    )
    .unwrap();

    let final_labels = labels.labels_for_last_layer().unwrap();
    let last_label = final_labels.read_at(nodes - 1).unwrap();

    assert_eq!(expected_last_label.into_repr(), last_label.0);
}
