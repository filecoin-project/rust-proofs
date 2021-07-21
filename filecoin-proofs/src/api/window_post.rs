use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use bellperson::groth16::BellTaskType;
use filecoin_hashers::Hasher;
use log::info;
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    merkle::MerkleTreeTrait,
    multi_proof::MultiProof,
    sector::SectorId,
};
use storage_proofs_post::fallback::{
    self, FallbackPoSt, FallbackPoStCompound, PrivateSector, PublicSector,
};

use crate::{
    api::{as_safe_commitment, get_partitions_for_window_post, partition_vanilla_proofs},
    caches::{get_post_params, get_post_verifying_key},
    parameters::window_post_setup_params,
    types::{
        ChallengeSeed, FallbackPoStSectorProof, PoStConfig, PrivateReplicaInfo, ProverId,
        PublicReplicaInfo, SnarkProof,
    },
    PoStType,
};

/// Generates a Window proof-of-spacetime with provided vanilla proofs.
pub fn generate_window_post_with_vanilla<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
) -> Result<SnarkProof> {
    info!("generate_window_post_with_vanilla:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(vanilla_proofs.len(), &post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let partitions = partitions.unwrap_or(1);

    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let mut pub_sectors = Vec::with_capacity(vanilla_proofs.len());
    for vanilla_proof in &vanilla_proofs {
        pub_sectors.push(PublicSector {
            id: vanilla_proof.sector_id,
            comm_r: vanilla_proof.comm_r,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let partitioned_proofs = partition_vanilla_proofs(
        &post_config,
        &pub_params.vanilla_params,
        &pub_inputs,
        partitions,
        &vanilla_proofs,
    )?;

    // tell the scheduler in bellperson what task it is,
    // so the scheduler can handle timing requirements accordingly
    // as well as resources that are meant to be used by this task
    let post_type = match post_config.typ {
        PoStType::Winning => BellTaskType::WinningPost,
        PoStType::Window => BellTaskType::WindowPost,
    };

    let proof = FallbackPoStCompound::prove_with_vanilla(
        &pub_params,
        &pub_inputs,
        partitioned_proofs,
        &groth_params,
        Some(post_type),
    )?;

    info!("generate_window_post_with_vanilla:finish");

    proof.to_vec()
}

/// Generates a Window proof-of-spacetime.
pub fn generate_window_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>,
    prover_id: ProverId,
) -> Result<SnarkProof> {
    info!("generate_window_post:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), &post_config);

    let sector_count = vanilla_params.sector_count;
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let trees: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_window_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<_>>()?;

    let mut pub_sectors = Vec::with_capacity(sector_count);
    let mut priv_sectors = Vec::with_capacity(sector_count);

    for ((sector_id, replica), tree) in replicas.iter().zip(trees.iter()) {
        let comm_r = replica.safe_comm_r().with_context(|| {
            format!("generate_window_post: safe_comm_r failed: {:?}", sector_id)
        })?;
        let comm_c = replica.safe_comm_c();
        let comm_r_last = replica.safe_comm_r_last();

        pub_sectors.push(PublicSector {
            id: *sector_id,
            comm_r,
        });
        priv_sectors.push(PrivateSector {
            tree,
            comm_c,
            comm_r_last,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let post_type = match post_config.typ {
        PoStType::Winning => BellTaskType::WinningPost,
        PoStType::Window => BellTaskType::WindowPost,
    };

    let proof = FallbackPoStCompound::prove_with_type(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        &groth_params,
        Some(post_type),
    )?;

    info!("generate_window_post:finish");

    proof.to_vec()
}

/// Verifies a window proof-of-spacetime.
pub fn verify_window_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool> {
    info!("verify_window_post:start");

    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), &post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;

    let pub_sectors: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("verify_window_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            Ok(PublicSector {
                id: *sector_id,
                comm_r,
            })
        })
        .collect::<Result<_>>()?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let is_valid = {
        let verifying_key = get_post_verifying_key::<Tree>(&post_config)?;
        let multi_proof = MultiProof::new_from_reader(partitions, proof, &verifying_key)?;

        FallbackPoStCompound::verify(
            &pub_params,
            &pub_inputs,
            &multi_proof,
            &fallback::ChallengeRequirements {
                minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
            },
        )?
    };
    if !is_valid {
        return Ok(false);
    }

    info!("verify_window_post:finish");

    Ok(true)
}
