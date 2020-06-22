use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Once;

use anyhow::Result;
use ff::Field;
use paired::bls12_381::Fr;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs::hasher::Hasher;
use storage_proofs::sector::*;
use tempfile::NamedTempFile;

use filecoin_proofs::*;

static INIT_LOGGER: Once = Once::new();
fn init_logger() {
    INIT_LOGGER.call_once(|| {
        fil_logger::init();
    });
}

const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];

#[test]
#[ignore]
fn test_seal_lifecycle_2kib_base_8() -> Result<()> {
    seal_lifecycle::<SectorShape2KiB>(SECTOR_SIZE_2_KIB)
}

#[test]
#[ignore]
fn test_seal_lifecycle_4kib_sub_8_2() -> Result<()> {
    seal_lifecycle::<SectorShape4KiB>(SECTOR_SIZE_4_KIB)
}

#[test]
#[ignore]
fn test_seal_lifecycle_16kib_sub_8_2() -> Result<()> {
    seal_lifecycle::<SectorShape16KiB>(SECTOR_SIZE_16_KIB)
}

#[test]
#[ignore]
fn test_seal_lifecycle_32kib_top_8_8_2() -> Result<()> {
    seal_lifecycle::<SectorShape32KiB>(SECTOR_SIZE_32_KIB)
}

// These tests are good to run, but take a long time.

//#[test]
//#[ignore]
//fn test_seal_lifecycle_512mib_top_8_0_0() -> Result<()> {
//    seal_lifecycle::<SectorShape512MiB>(SECTOR_SIZE_512_MIB)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_32gib_sub_8_8() -> Result<()> {
//    seal_lifecycle::<SectorShape32GiB>(SECTOR_SIZE_32_GIB)
//}

//#[test]
//#[ignore]
//fn test_seal_lifecycle_64gib_top_8_8_2() -> Result<()> {
//    seal_lifecycle::<SectorShape64GiB>(SECTOR_SIZE_64_GIB)
//}

fn seal_lifecycle<Tree: 'static + MerkleTreeTrait>(sector_size: u64) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    create_seal::<_, Tree>(rng, sector_size, prover_id, false)?;
    Ok(())
}

#[test]
#[ignore]
fn test_winning_post_2kib_base_8() -> Result<()> {
    winning_post::<SectorShape2KiB>(SECTOR_SIZE_2_KIB)
}

#[test]
#[ignore]
fn test_winning_post_4kib_sub_8_2() -> Result<()> {
    winning_post::<SectorShape4KiB>(SECTOR_SIZE_4_KIB)
}

#[test]
#[ignore]
fn test_winning_post_16kib_sub_8_8() -> Result<()> {
    winning_post::<SectorShape16KiB>(SECTOR_SIZE_16_KIB)
}

#[test]
#[ignore]
fn test_winning_post_32kib_top_8_8_2() -> Result<()> {
    winning_post::<SectorShape32KiB>(SECTOR_SIZE_32_KIB)
}

#[test]
fn test_winning_post_empty_sector_challenge() -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let sector_count = 0;
    let sector_size = SECTOR_SIZE_2_KIB;

    let (_, _, _, _) = create_seal::<_, SectorShape2KiB>(rng, sector_size, prover_id, true)?;

    let random_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        typ: PoStType::Winning,
        priority: false,
    };

    assert!(generate_winning_post_sector_challenge::<SectorShape2KiB>(
        &config,
        &randomness,
        sector_count as u64,
        prover_id
    )
    .is_err());

    Ok(())
}

fn winning_post<Tree: 'static + MerkleTreeTrait>(sector_size: u64) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let (sector_id, replica, comm_r, cache_dir) =
        create_seal::<_, Tree>(rng, sector_size, prover_id, true)?;
    let sector_count = WINNING_POST_SECTOR_COUNT;

    let random_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        typ: PoStType::Winning,
        priority: false,
    };

    let challenged_sectors = generate_winning_post_sector_challenge::<Tree>(
        &config,
        &randomness,
        sector_count as u64,
        prover_id,
    )?;
    assert_eq!(challenged_sectors.len(), sector_count);
    assert_eq!(challenged_sectors[0], 0); // with a sector_count of 1, the only valid index is 0

    let pub_replicas = vec![(sector_id, PublicReplicaInfo::new(comm_r)?)];
    let priv_replicas = vec![(
        sector_id,
        PrivateReplicaInfo::new(replica.path().into(), comm_r, cache_dir.path().into())?,
    )];

    let proof = generate_winning_post::<Tree>(&config, &randomness, &priv_replicas[..], prover_id)?;

    let valid =
        verify_winning_post::<Tree>(&config, &randomness, &pub_replicas[..], prover_id, &proof)?;
    assert!(valid, "proof did not verify");
    Ok(())
}

#[test]
#[ignore]
fn test_window_post_single_partition_smaller_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .unwrap()
        .get(&sector_size)
        .unwrap();

    window_post::<SectorShape2KiB>(sector_size, sector_count / 2, sector_count)
}

#[test]
#[ignore]
fn test_window_post_two_partitions_matching_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .unwrap()
        .get(&sector_size)
        .unwrap();

    window_post::<SectorShape2KiB>(sector_size, 2 * sector_count, sector_count)
}

#[test]
#[ignore]
fn test_window_post_two_partitions_matching_4kib_sub_8_2() -> Result<()> {
    let sector_size = SECTOR_SIZE_4_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .unwrap()
        .get(&sector_size)
        .unwrap();

    window_post::<SectorShape4KiB>(sector_size, 2 * sector_count, sector_count)
}

#[test]
#[ignore]
fn test_window_post_two_partitions_matching_16kib_sub_8_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_16_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .unwrap()
        .get(&sector_size)
        .unwrap();

    window_post::<SectorShape16KiB>(sector_size, 2 * sector_count, sector_count)
}

#[test]
#[ignore]
fn test_window_post_two_partitions_matching_32kib_top_8_8_2() -> Result<()> {
    let sector_size = SECTOR_SIZE_32_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .unwrap()
        .get(&sector_size)
        .unwrap();

    window_post::<SectorShape32KiB>(sector_size, 2 * sector_count, sector_count)
}

#[test]
#[ignore]
fn test_window_post_two_partitions_smaller_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .unwrap()
        .get(&sector_size)
        .unwrap();

    window_post::<SectorShape2KiB>(sector_size, 2 * sector_count - 1, sector_count)
}

#[test]
#[ignore]
fn test_window_post_single_partition_matching_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .unwrap()
        .get(&sector_size)
        .unwrap();

    window_post::<SectorShape2KiB>(sector_size, sector_count, sector_count)
}

fn window_post<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    total_sector_count: usize,
    sector_count: usize,
) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let mut sectors = Vec::with_capacity(total_sector_count);
    let mut pub_replicas = BTreeMap::new();
    let mut priv_replicas = BTreeMap::new();

    let prover_fr: <Tree::Hasher as Hasher>::Domain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    for _ in 0..total_sector_count {
        let (sector_id, replica, comm_r, cache_dir) =
            create_seal::<_, Tree>(rng, sector_size, prover_id, true)?;
        priv_replicas.insert(
            sector_id,
            PrivateReplicaInfo::new(replica.path().into(), comm_r, cache_dir.path().into())?,
        );
        pub_replicas.insert(sector_id, PublicReplicaInfo::new(comm_r)?);
        sectors.push((sector_id, replica, comm_r, cache_dir, prover_id));
    }
    assert_eq!(priv_replicas.len(), total_sector_count);
    assert_eq!(pub_replicas.len(), total_sector_count);
    assert_eq!(sectors.len(), total_sector_count);

    let random_fr: <Tree::Hasher as Hasher>::Domain = Fr::random(rng).into();
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINDOW_POST_CHALLENGE_COUNT,
        typ: PoStType::Window,
        priority: false,
    };

    let proof = generate_window_post::<Tree>(&config, &randomness, &priv_replicas, prover_id)?;

    let valid = verify_window_post::<Tree>(&config, &randomness, &pub_replicas, prover_id, &proof)?;
    assert!(valid, "proof did not verify");
    Ok(())
}

fn create_seal<R: Rng, Tree: 'static + MerkleTreeTrait>(
    rng: &mut R,
    sector_size: u64,
    prover_id: ProverId,
    skip_proof: bool,
) -> Result<(SectorId, NamedTempFile, Commitment, tempfile::TempDir)> {
    init_logger();

    let number_of_bytes_in_piece = UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));

    let piece_bytes: Vec<u8> = (0..number_of_bytes_in_piece.0)
        .map(|_| rand::random::<u8>())
        .collect();

    let mut piece_file = NamedTempFile::new()?;
    piece_file.write_all(&piece_bytes)?;
    piece_file.as_file_mut().sync_all()?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    let piece_info = generate_piece_commitment(piece_file.as_file_mut(), number_of_bytes_in_piece)?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    let mut staged_sector_file = NamedTempFile::new()?;
    add_piece(
        &mut piece_file,
        &mut staged_sector_file,
        number_of_bytes_in_piece,
        &[],
    )?;

    let piece_infos = vec![piece_info];
    let arbitrary_porep_id = [28; 32];
    let sealed_sector_file = NamedTempFile::new()?;
    let mut unseal_file = NamedTempFile::new()?;
    let config = PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS.read().unwrap().get(&sector_size).unwrap(),
        ),
        porep_id: arbitrary_porep_id,
    };

    let cache_dir = tempfile::tempdir().unwrap();

    let ticket = rng.gen();
    let seed = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    let phase1_output = seal_pre_commit_phase1::<_, _, _, Tree>(
        config,
        cache_dir.path(),
        staged_sector_file.path(),
        sealed_sector_file.path(),
        prover_id,
        sector_id,
        ticket,
        &piece_infos,
    )?;

    validate_cache_for_precommit_phase2(
        cache_dir.path(),
        staged_sector_file.path(),
        &phase1_output,
    )?;

    let pre_commit_output = seal_pre_commit_phase2(
        config,
        phase1_output,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;

    let comm_d = pre_commit_output.comm_d;
    let comm_r = pre_commit_output.comm_r;

    validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_sector_file.path())?;

    if skip_proof {
        clear_cache::<Tree>(cache_dir.path())?;
    } else {
        let phase1_output = seal_commit_phase1::<_, Tree>(
            config,
            cache_dir.path(),
            sealed_sector_file.path(),
            prover_id,
            sector_id,
            ticket,
            seed,
            pre_commit_output,
            &piece_infos,
        )?;

        clear_cache::<Tree>(cache_dir.path())?;

        let commit_output = seal_commit_phase2(config, phase1_output, prover_id, sector_id)?;

        let _ = unseal_range::<_, _, _, Tree>(
            config,
            cache_dir.path(),
            &sealed_sector_file,
            &unseal_file,
            prover_id,
            sector_id,
            comm_d,
            ticket,
            UnpaddedByteIndex(508),
            UnpaddedBytesAmount(508),
        )?;

        unseal_file.seek(SeekFrom::Start(0))?;

        let mut contents = vec![];
        assert!(
            unseal_file.read_to_end(&mut contents).is_ok(),
            "failed to populate buffer with unsealed bytes"
        );
        assert_eq!(contents.len(), 508);
        assert_eq!(&piece_bytes[508..508 + 508], &contents[..]);

        let computed_comm_d = compute_comm_d(config.sector_size, &piece_infos)?;

        assert_eq!(
            comm_d, computed_comm_d,
            "Computed and expected comm_d don't match."
        );

        let verified = verify_seal::<Tree>(
            config,
            comm_r,
            comm_d,
            prover_id,
            sector_id,
            ticket,
            seed,
            &commit_output.proof,
        )?;
        assert!(verified, "failed to verify valid seal");
    }

    Ok((sector_id, sealed_sector_file, comm_r, cache_dir))
}
