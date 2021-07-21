use std::fs::{self, metadata, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bellperson::bls::{Bls12, Fr};
use bellperson::groth16;
use bincode::{deserialize, serialize};
use filecoin_hashers::{Domain, Hasher};
use log::{info, trace};
use memmap::MmapOptions;
use merkletree::store::{DiskStore, Store, StoreConfig};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    cache_key::CacheKey,
    compound_proof::{self, CompoundProof},
    drgraph::Graph,
    measurements::{measure_op, Operation},
    merkle::{create_base_merkle_tree, BinaryMerkleTree, MerkleTreeTrait},
    multi_proof::MultiProof,
    parameter_cache::SRS_MAX_PROOFS_TO_AGGREGATE,
    proof::ProofScheme,
    sector::SectorId,
    util::default_rows_to_discard,
    Data,
};
use storage_proofs_porep::stacked::{
    self, generate_replica_id, ChallengeRequirements, StackedCompound, StackedDrg, Tau,
    TemporaryAux, TemporaryAuxCache,
};

use crate::{
    api::{as_safe_commitment, commitment_from_fr, get_base_tree_leafs, get_base_tree_size},
    caches::{
        get_stacked_params, get_stacked_srs_key, get_stacked_srs_verifier_key,
        get_stacked_verifying_key,
    },
    constants::{
        DefaultBinaryTree, DefaultPieceDomain, DefaultPieceHasher, POREP_MINIMUM_CHALLENGES,
        SINGLE_PARTITION_PROOF_LEN,
    },
    parameters::setup_params,
    pieces::{self, verify_pieces},
    types::{
        AggregateSnarkProof, Commitment, PaddedBytesAmount, PieceInfo, PoRepConfig,
        PoRepProofPartitions, ProverId, SealCommitOutput, SealCommitPhase1Output,
        SealPreCommitOutput, SealPreCommitPhase1Output, SectorSize, Ticket, BINARY_ARITY,
    },
};

#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit_phase1<R, S, T, Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    cache_path: R,
    in_path: S,
    out_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: &[PieceInfo],
) -> Result<SealPreCommitPhase1Output<Tree>>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
    T: AsRef<Path>,
{
    info!("seal_pre_commit_phase1:start: {:?}", sector_id);

    // Sanity check all input path types.
    ensure!(
        metadata(in_path.as_ref())?.is_file(),
        "in_path must be a file"
    );
    ensure!(
        metadata(out_path.as_ref())?.is_file(),
        "out_path must be a file"
    );
    ensure!(
        metadata(cache_path.as_ref())?.is_dir(),
        "cache_path must be a directory"
    );

    let sector_bytes = usize::from(PaddedBytesAmount::from(porep_config));
    fs::metadata(&in_path)
        .with_context(|| format!("could not read in_path={:?})", in_path.as_ref().display()))?;

    fs::metadata(&out_path)
        .with_context(|| format!("could not read out_path={:?}", out_path.as_ref().display()))?;

    // Copy unsealed data to output location, where it will be sealed in place.
    fs::copy(&in_path, &out_path).with_context(|| {
        format!(
            "could not copy in_path={:?} to out_path={:?}",
            in_path.as_ref().display(),
            out_path.as_ref().display()
        )
    })?;

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&out_path)
        .with_context(|| format!("could not open out_path={:?}", out_path.as_ref().display()))?;

    // Zero-pad the data to the requested size by extending the underlying file if needed.
    f_data.set_len(sector_bytes as u64)?;

    let data = unsafe {
        MmapOptions::new()
            .map_mut(&f_data)
            .with_context(|| format!("could not mmap out_path={:?}", out_path.as_ref().display()))?
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    info!("building merkle tree for the original data");
    let (config, comm_d) = measure_op(Operation::CommD, || -> Result<_> {
        let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(porep_config.sector_size)?;
        let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;
        ensure!(
            compound_public_params.vanilla_params.graph.size() == base_tree_leafs,
            "graph size and leaf size don't match"
        );

        trace!(
            "seal phase 1: sector_size {}, base tree size {}, base tree leafs {}",
            u64::from(porep_config.sector_size),
            base_tree_size,
            base_tree_leafs,
        );

        let mut config = StoreConfig::new(
            cache_path.as_ref(),
            CacheKey::CommDTree.to_string(),
            default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
        );

        let data_tree = create_base_merkle_tree::<BinaryMerkleTree<DefaultPieceHasher>>(
            Some(config.clone()),
            base_tree_leafs,
            &data,
        )?;
        drop(data);

        config.size = Some(data_tree.len());
        let comm_d_root: Fr = data_tree.root().into();
        let comm_d = commitment_from_fr(comm_d_root);

        drop(data_tree);

        Ok((config, comm_d))
    })?;

    info!("verifying pieces");

    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let labels = StackedDrg::<Tree, DefaultPieceHasher>::replicate_phase1(
        &compound_public_params.vanilla_params,
        &replica_id,
        config.clone(),
    )?;

    let out = SealPreCommitPhase1Output {
        labels,
        config,
        comm_d,
    };

    info!("seal_pre_commit_phase1:finish: {:?}", sector_id);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_pre_commit_phase2<R, S, Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    phase1_output: SealPreCommitPhase1Output<Tree>,
    cache_path: S,
    replica_path: R,
) -> Result<SealPreCommitOutput>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
{
    info!("seal_pre_commit_phase2:start");

    // Sanity check all input path types.
    ensure!(
        metadata(cache_path.as_ref())?.is_dir(),
        "cache_path must be a directory"
    );
    ensure!(
        metadata(replica_path.as_ref())?.is_file(),
        "replica_path must be a file"
    );

    let SealPreCommitPhase1Output {
        mut labels,
        mut config,
        comm_d,
        ..
    } = phase1_output;

    labels.update_root(cache_path.as_ref());
    config.path = cache_path.as_ref().into();

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&replica_path)
        .with_context(|| {
            format!(
                "could not open replica_path={:?}",
                replica_path.as_ref().display()
            )
        })?;
    let data = unsafe {
        MmapOptions::new().map_mut(&f_data).with_context(|| {
            format!(
                "could not mmap replica_path={:?}",
                replica_path.as_ref().display()
            )
        })?
    };
    let data: Data<'_> = (data, PathBuf::from(replica_path.as_ref())).into();

    // Load data tree from disk
    let data_tree = {
        let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(porep_config.sector_size)?;
        let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;

        trace!(
            "seal phase 2: base tree size {}, base tree leafs {}, rows to discard {}",
            base_tree_size,
            base_tree_leafs,
            default_rows_to_discard(base_tree_leafs, BINARY_ARITY)
        );
        ensure!(
            config.rows_to_discard == default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
            "Invalid cache size specified"
        );

        let store: DiskStore<DefaultPieceDomain> =
            DiskStore::new_from_disk(base_tree_size, BINARY_ARITY, &config)?;
        BinaryMerkleTree::<DefaultPieceHasher>::from_data_store(store, base_tree_leafs)?
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, DefaultPieceHasher>::replicate_phase2(
        &compound_public_params.vanilla_params,
        labels,
        data,
        data_tree,
        config,
        replica_path.as_ref().to_path_buf(),
    )?;

    let comm_r = commitment_from_fr(tau.comm_r.into());

    // Persist p_aux and t_aux here
    let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
    let mut f_p_aux = File::create(&p_aux_path)
        .with_context(|| format!("could not create file p_aux={:?}", p_aux_path))?;
    let p_aux_bytes = serialize(&p_aux)?;
    f_p_aux
        .write_all(&p_aux_bytes)
        .with_context(|| format!("could not write to file p_aux={:?}", p_aux_path))?;

    let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
    let mut f_t_aux = File::create(&t_aux_path)
        .with_context(|| format!("could not create file t_aux={:?}", t_aux_path))?;
    let t_aux_bytes = serialize(&t_aux)?;
    f_t_aux
        .write_all(&t_aux_bytes)
        .with_context(|| format!("could not write to file t_aux={:?}", t_aux_path))?;

    let out = SealPreCommitOutput { comm_r, comm_d };

    info!("seal_pre_commit_phase2:finish");
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_commit_phase1<T: AsRef<Path>, Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    cache_path: T,
    replica_path: T,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitOutput,
    piece_infos: &[PieceInfo],
) -> Result<SealCommitPhase1Output<Tree>> {
    info!("seal_commit_phase1:start: {:?}", sector_id);

    // Sanity check all input path types.
    ensure!(
        metadata(cache_path.as_ref())?.is_dir(),
        "cache_path must be a directory"
    );
    ensure!(
        metadata(replica_path.as_ref())?.is_file(),
        "replica_path must be a file"
    );

    let SealPreCommitOutput { comm_d, comm_r } = pre_commit;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
    ensure!(
        verify_pieces(&comm_d, piece_infos, porep_config.into())?,
        "pieces and comm_d do not match"
    );

    let p_aux = {
        let p_aux_path = cache_path.as_ref().join(CacheKey::PAux.to_string());
        let p_aux_bytes = fs::read(&p_aux_path)
            .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

        deserialize(&p_aux_bytes)
    }?;

    let t_aux = {
        let t_aux_path = cache_path.as_ref().join(CacheKey::TAux.to_string());
        let t_aux_bytes = fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let mut res: TemporaryAux<_, _> = deserialize(&t_aux_bytes)?;

        // Switch t_aux to the passed in cache_path
        res.set_cache_path(cache_path);
        res
    };

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux_cache: TemporaryAuxCache<Tree, DefaultPieceHasher> =
        TemporaryAuxCache::new(&t_aux, replica_path.as_ref().to_path_buf())
            .context("failed to restore contents of t_aux")?;

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::try_from_bytes(&comm_d)?;

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d_safe,
        &porep_config.porep_id,
    );

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let private_inputs = stacked::PrivateInputs::<Tree, DefaultPieceHasher> {
        p_aux,
        t_aux: t_aux_cache,
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    let vanilla_proofs = StackedDrg::prove_all_partitions(
        &compound_public_params.vanilla_params,
        &public_inputs,
        &private_inputs,
        StackedCompound::partition_count(&compound_public_params),
    )?;

    let sanity_check = StackedDrg::<Tree, DefaultPieceHasher>::verify_all_partitions(
        &compound_public_params.vanilla_params,
        &public_inputs,
        &vanilla_proofs,
    )?;
    ensure!(sanity_check, "Invalid vanilla proof generated");

    let out = SealCommitPhase1Output {
        vanilla_proofs,
        comm_r,
        comm_d,
        replica_id,
        seed,
        ticket,
    };

    info!("seal_commit_phase1:finish: {:?}", sector_id);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn seal_commit_phase2<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    phase1_output: SealCommitPhase1Output<Tree>,
    prover_id: ProverId,
    sector_id: SectorId,
) -> Result<SealCommitOutput> {
    info!("seal_commit_phase2:start: {:?}", sector_id);

    let SealCommitPhase1Output {
        vanilla_proofs,
        comm_d,
        comm_r,
        replica_id,
        seed,
        ticket,
    } = phase1_output;

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::try_from_bytes(&comm_d)?;

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let groth_params = get_stacked_params::<Tree>(porep_config)?;

    info!(
        "got groth params ({}) while sealing",
        u64::from(PaddedBytesAmount::from(porep_config))
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    info!("snark_proof:start");
    let groth_proofs = StackedCompound::<Tree, DefaultPieceHasher>::circuit_proofs(
        &public_inputs,
        vanilla_proofs,
        &compound_public_params.vanilla_params,
        &groth_params,
        None,
    )?;
    info!("snark_proof:finish");

    let proof = MultiProof::new(groth_proofs, &groth_params.pvk);

    let mut buf = Vec::with_capacity(
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoRepProofPartitions::from(porep_config)),
    );

    proof.write(&mut buf)?;

    // Verification is cheap when parameters are cached,
    // and it is never correct to return a proof which does not verify.
    verify_seal::<Tree>(
        porep_config,
        comm_r,
        comm_d,
        prover_id,
        sector_id,
        ticket,
        seed,
        &buf,
    )
    .context("post-seal verification sanity check failed")?;

    let out = SealCommitOutput { proof: buf };

    info!("seal_commit_phase2:finish: {:?}", sector_id);
    Ok(out)
}

/// Given the specified arguments, this method returns the inputs that were used to
/// generate the seal proof.  This can be useful for proof aggregation, as verification
/// requires these inputs.
///
/// This method allows them to be retrieved when needed, rather than storing them for
/// some amount of time.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `comm_r` - a commitment to a sector's replica.
/// * `comm_d` - a commitment to a sector's data.
/// * `prover_id` - the prover_id used to seal this sector.
/// * `sector_id` - the sector_id of this sector.
/// * `ticket` - the ticket used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
pub fn get_seal_inputs<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    comm_r: Commitment,
    comm_d: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
) -> Result<Vec<Vec<Fr>>> {
    info!("get_seal_inputs:start");

    ensure!(comm_d != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let comm_r_safe = as_safe_commitment(&comm_r, "comm_r")?;
    let comm_d_safe = DefaultPieceDomain::try_from_bytes(&comm_d)?;

    let public_inputs = stacked::PublicInputs {
        replica_id,
        tau: Some(stacked::Tau {
            comm_d: comm_d_safe,
            comm_r: comm_r_safe,
        }),
        k: None,
        seed,
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    let partitions = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::partition_count(&compound_public_params);

    // These are returned for aggregated proof verification.
    let inputs: Vec<_> = (0..partitions)
        .into_par_iter()
        .map(|k| {
            StackedCompound::<Tree, DefaultPieceHasher>::generate_public_inputs(
                &public_inputs,
                &compound_public_params.vanilla_params,
                Some(k),
            )
        })
        .collect::<Result<_>>()?;

    info!("get_seal_inputs:finish");

    Ok(inputs)
}

/// Given a value, get one suitable for aggregation.
fn get_aggregate_target_len(len: usize) -> usize {
    if len == 1 {
        2
    } else {
        len.next_power_of_two()
    }
}

/// Given a list of proofs and a target_len, make sure that the proofs list is padded to the target_len size.
fn pad_proofs_to_target(proofs: &mut Vec<groth16::Proof<Bls12>>, target_len: usize) -> Result<()> {
    trace!(
        "pad_proofs_to_target target_len {}, proofs len {}",
        target_len,
        proofs.len()
    );
    ensure!(
        target_len >= proofs.len(),
        "target len must be greater than actual num proofs"
    );
    ensure!(
        proofs.last().is_some(),
        "invalid last proof for duplication"
    );

    let last = proofs
        .last()
        .expect("invalid last proof for duplication")
        .clone();
    let mut padding: Vec<groth16::Proof<Bls12>> = (0..target_len - proofs.len())
        .map(|_| last.clone())
        .collect();
    proofs.append(&mut padding);

    ensure!(
        proofs.len().next_power_of_two() == proofs.len(),
        "proof count must be a power of 2 for aggregation"
    );
    ensure!(
        proofs.len() <= SRS_MAX_PROOFS_TO_AGGREGATE,
        "proof count for aggregation is larger than the max supported value"
    );

    Ok(())
}

/// Given a list of public inputs and a target_len, make sure that the inputs list is padded to the target_len size.
fn pad_inputs_to_target(
    commit_inputs: &[Vec<Fr>],
    num_inputs_per_proof: usize,
    target_len: usize,
) -> Result<Vec<Vec<Fr>>> {
    ensure!(
        !commit_inputs.is_empty(),
        "cannot aggregate with empty public inputs"
    );

    let mut num_inputs = commit_inputs.len();
    let mut new_inputs = commit_inputs.to_owned();

    if target_len != num_inputs {
        ensure!(
            target_len > num_inputs,
            "target len must be greater than actual num inputs"
        );
        let duplicate_inputs = &commit_inputs[(num_inputs - num_inputs_per_proof)..num_inputs];

        trace!("padding inputs from {} to {}", num_inputs, target_len);
        while target_len != num_inputs {
            new_inputs.extend_from_slice(duplicate_inputs);
            num_inputs += num_inputs_per_proof;
        }
    }

    Ok(new_inputs)
}

/// Given a porep_config and a list of seal commit outputs, this method aggregates
/// those proofs (naively padding the count if necessary up to a power of 2) and
/// returns the aggregate proof bytes.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `seeds` - an ordered list of seeds used to derive the PoRep challenges.
/// * `commit_outputs` - an ordered list of seal proof outputs returned from 'seal_commit_phase2'.
pub fn aggregate_seal_commit_proofs<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    comm_rs: &[[u8; 32]],
    seeds: &[[u8; 32]],
    commit_outputs: &[SealCommitOutput],
) -> Result<AggregateSnarkProof> {
    info!("aggregate_seal_commit_proofs:start");

    ensure!(
        !commit_outputs.is_empty(),
        "cannot aggregate with empty outputs"
    );

    let partitions = usize::from(PoRepProofPartitions::from(porep_config));
    let verifying_key = get_stacked_verifying_key::<Tree>(porep_config)?;
    let mut proofs: Vec<_> =
        commit_outputs
            .iter()
            .try_fold(Vec::new(), |mut acc, commit_output| -> Result<_> {
                acc.extend(
                    MultiProof::new_from_reader(
                        Some(partitions),
                        &commit_output.proof[..],
                        &verifying_key,
                    )?
                    .circuit_proofs,
                );

                Ok(acc)
            })?;
    trace!(
        "aggregate_seal_commit_proofs called with {} commit_outputs containing {} proofs",
        commit_outputs.len(),
        proofs.len(),
    );

    let target_proofs_len = get_aggregate_target_len(proofs.len());
    ensure!(
        target_proofs_len > 1,
        "cannot aggregate less than two proofs"
    );
    trace!(
        "aggregate_seal_commit_proofs will pad proofs to target_len {}",
        target_proofs_len
    );

    // If we're not at the pow2 target, duplicate the last proof until we are.
    pad_proofs_to_target(&mut proofs, target_proofs_len)?;

    // Hash all of the seeds and comm_r's pair-wise into a digest for the aggregate proof method.
    let hashed_seeds_and_comm_rs: [u8; 32] = {
        let mut hasher = Sha256::new();
        for cur in seeds.iter().zip(comm_rs.iter()) {
            let (seed, comm_r) = cur;
            hasher.update(seed);
            hasher.update(comm_r);
        }
        hasher.finalize().into()
    };

    let srs_prover_key = get_stacked_srs_key::<Tree>(porep_config, proofs.len())?;
    let aggregate_proof = StackedCompound::<Tree, DefaultPieceHasher>::aggregate_proofs(
        &srs_prover_key,
        &hashed_seeds_and_comm_rs,
        proofs.as_slice(),
    )?;
    let mut aggregate_proof_bytes = Vec::new();
    aggregate_proof.write(&mut aggregate_proof_bytes)?;

    info!("aggregate_seal_commit_proofs:finish");

    Ok(aggregate_proof_bytes)
}

/// Given a porep_config, an aggregate proof, a list of seeds and a combined and flattened list
/// of public inputs, this method verifies the aggregate seal proof.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `seeds` - an ordered list of seeds used to derive the PoRep challenges.
/// * `aggregate_proof_bytes` - the returned aggregate proof from 'aggreate_seal_commit_proofs'.
/// * `commit_inputs` - a flattened/combined and ordered list of all public inputs, which must match
///    the ordering of the seal proofs when aggregated.
pub fn verify_aggregate_seal_commit_proofs<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    aggregate_proof_bytes: AggregateSnarkProof,
    comm_rs: &[[u8; 32]],
    seeds: &[[u8; 32]],
    commit_inputs: Vec<Vec<Fr>>,
) -> Result<bool> {
    info!("verify_aggregate_seal_commit_proofs:start");

    let aggregate_proof =
        groth16::aggregate::AggregateProof::read(std::io::Cursor::new(&aggregate_proof_bytes))?;

    let aggregated_proofs_len = aggregate_proof.tmipp.gipa.nproofs as usize;

    ensure!(aggregated_proofs_len != 0, "cannot verify zero proofs");
    ensure!(!commit_inputs.is_empty(), "cannot verify with empty inputs");
    ensure!(
        comm_rs.len() == seeds.len(),
        "invalid comm_rs and seeds len mismatch"
    );

    trace!(
        "verify_aggregate_seal_commit_proofs called with len {}",
        aggregated_proofs_len,
    );

    ensure!(
        aggregated_proofs_len > 1,
        "cannot verify less than two proofs"
    );
    ensure!(
        aggregated_proofs_len == aggregated_proofs_len.next_power_of_two(),
        "cannot verify non-pow2 aggregate seal proofs"
    );

    let num_inputs = commit_inputs.len();
    let num_inputs_per_proof = get_aggregate_target_len(num_inputs) / aggregated_proofs_len;
    let target_inputs_len = aggregated_proofs_len * num_inputs_per_proof;
    ensure!(
        target_inputs_len % aggregated_proofs_len == 0,
        "invalid number of inputs provided",
    );

    trace!(
        "verify_aggregate_seal_commit_proofs got {} inputs with {} inputs per proof",
        num_inputs,
        target_inputs_len / aggregated_proofs_len,
    );

    // Pad public inputs if needed.
    let commit_inputs =
        pad_inputs_to_target(&commit_inputs, num_inputs_per_proof, target_inputs_len)?;

    let verifying_key = get_stacked_verifying_key::<Tree>(porep_config)?;
    let srs_verifier_key =
        get_stacked_srs_verifier_key::<Tree>(porep_config, aggregated_proofs_len)?;

    // Hash all of the seeds and comm_r's pair-wise into a digest for the aggregate proof method.
    let hashed_seeds_and_comm_rs: [u8; 32] = {
        let mut hasher = Sha256::new();
        for cur in seeds.iter().zip(comm_rs.iter()) {
            let (seed, comm_r) = cur;
            hasher.update(seed);
            hasher.update(comm_r);
        }
        hasher.finalize().into()
    };

    info!("start verifying aggregate proof");
    let result = StackedCompound::<Tree, DefaultPieceHasher>::verify_aggregate_proofs(
        &srs_verifier_key,
        &verifying_key,
        &hashed_seeds_and_comm_rs,
        commit_inputs.as_slice(),
        &aggregate_proof,
    )?;
    info!("end verifying aggregate proof");

    info!("verify_aggregate_seal_commit_proofs:finish");

    Ok(result)
}

/// Computes a sectors's `comm_d` given its pieces.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in the sector.
/// * `piece_infos` - the piece info (commitment and byte length) for each piece in this sector.
pub fn compute_comm_d(sector_size: SectorSize, piece_infos: &[PieceInfo]) -> Result<Commitment> {
    info!("compute_comm_d:start");

    let result = pieces::compute_comm_d(sector_size, piece_infos);

    info!("compute_comm_d:finish");
    result
}

/// Verifies the output of some previously-run seal operation.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
/// * `comm_r_in` - commitment to the sector's replica (`comm_r`).
/// * `comm_d_in` - commitment to the sector's data (`comm_d`).
/// * `prover_id` - the prover-id that sealed this sector.
/// * `sector_id` - this sector's sector-id.
/// * `ticket` - the ticket that was used to generate this sector's replica-id.
/// * `seed` - the seed used to derive the porep challenges.
/// * `proof_vec` - the porep circuit proof serialized into a vector of bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_seal<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_vec: &[u8],
) -> Result<bool> {
    info!("verify_seal:start: {:?}", sector_id);
    ensure!(comm_d_in != [0; 32], "Invalid all zero commitment (comm_d)");
    ensure!(comm_r_in != [0; 32], "Invalid all zero commitment (comm_r)");

    let comm_r: <Tree::Hasher as Hasher>::Domain = as_safe_commitment(&comm_r_in, "comm_r")?;
    let comm_d: DefaultPieceDomain = as_safe_commitment(&comm_d_in, "comm_d")?;

    let replica_id = generate_replica_id::<Tree::Hasher, _>(
        &prover_id,
        sector_id.into(),
        &ticket,
        comm_d,
        &porep_config.porep_id,
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        StackedDrg<'_, Tree, DefaultPieceHasher>,
    > = StackedCompound::setup(&compound_setup_params)?;

    let public_inputs =
        stacked::PublicInputs::<<Tree::Hasher as Hasher>::Domain, DefaultPieceDomain> {
            replica_id,
            tau: Some(Tau { comm_r, comm_d }),
            seed,
            k: None,
        };

    let result = {
        let sector_bytes = PaddedBytesAmount::from(porep_config);
        let verifying_key = get_stacked_verifying_key::<Tree>(porep_config)?;

        info!(
            "got verifying key ({}) while verifying seal",
            u64::from(sector_bytes)
        );

        let proof = MultiProof::new_from_reader(
            Some(usize::from(PoRepProofPartitions::from(porep_config))),
            proof_vec,
            &verifying_key,
        )?;

        StackedCompound::verify(
            &compound_public_params,
            &public_inputs,
            &proof,
            &ChallengeRequirements {
                minimum_challenges: *POREP_MINIMUM_CHALLENGES
                    .read()
                    .expect("POREP_MINIMUM_CHALLENGES poisoned")
                    .get(&u64::from(SectorSize::from(porep_config)))
                    .expect("unknown sector size") as usize,
            },
        )
    };

    info!("verify_seal:finish: {:?}", sector_id);
    result
}

/// Verifies a batch of outputs of some previously-run seal operations.
///
/// # Arguments
///
/// * `porep_config` - this sector's porep config that contains the number of bytes in this sector.
/// * `[comm_r_ins]` - list of commitments to the sector's replica (`comm_r`).
/// * `[comm_d_ins]` - list of commitments to the sector's data (`comm_d`).
/// * `[prover_ids]` - list of prover-ids that sealed this sector.
/// * `[sector_ids]` - list of the sector's sector-id.
/// * `[tickets]` - list of tickets that was used to generate this sector's replica-id.
/// * `[seeds]` - list of seeds used to derive the porep challenges.
/// * `[proof_vecs]` - list of porep circuit proofs serialized into a vector of bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_batch_seal<Tree: 'static + MerkleTreeTrait>(
    porep_config: PoRepConfig,
    comm_r_ins: &[Commitment],
    comm_d_ins: &[Commitment],
    prover_ids: &[ProverId],
    sector_ids: &[SectorId],
    tickets: &[Ticket],
    seeds: &[Ticket],
    proof_vecs: &[&[u8]],
) -> Result<bool> {
    info!("verify_batch_seal:start");
    ensure!(!comm_r_ins.is_empty(), "Cannot prove empty batch");
    let l = comm_r_ins.len();
    ensure!(l == comm_d_ins.len(), "Inconsistent inputs");
    ensure!(l == prover_ids.len(), "Inconsistent inputs");
    ensure!(l == prover_ids.len(), "Inconsistent inputs");
    ensure!(l == sector_ids.len(), "Inconsistent inputs");
    ensure!(l == tickets.len(), "Inconsistent inputs");
    ensure!(l == seeds.len(), "Inconsistent inputs");
    ensure!(l == proof_vecs.len(), "Inconsistent inputs");

    for comm_d_in in comm_d_ins {
        ensure!(
            comm_d_in != &[0; 32],
            "Invalid all zero commitment (comm_d)"
        );
    }
    for comm_r_in in comm_r_ins {
        ensure!(
            comm_r_in != &[0; 32],
            "Invalid all zero commitment (comm_r)"
        );
    }

    let sector_bytes = PaddedBytesAmount::from(porep_config);

    let verifying_key = get_stacked_verifying_key::<Tree>(porep_config)?;
    info!(
        "got verifying key ({}) while verifying seal",
        u64::from(sector_bytes)
    );

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
            porep_config.api_version,
        )?,
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        StackedDrg<'_, Tree, DefaultPieceHasher>,
    > = StackedCompound::setup(&compound_setup_params)?;

    let mut public_inputs = Vec::with_capacity(l);
    let mut proofs = Vec::with_capacity(l);

    for i in 0..l {
        let comm_r = as_safe_commitment(&comm_r_ins[i], "comm_r")?;
        let comm_d = as_safe_commitment(&comm_d_ins[i], "comm_d")?;

        let replica_id = generate_replica_id::<Tree::Hasher, _>(
            &prover_ids[i],
            sector_ids[i].into(),
            &tickets[i],
            comm_d,
            &porep_config.porep_id,
        );

        public_inputs.push(stacked::PublicInputs::<
            <Tree::Hasher as Hasher>::Domain,
            DefaultPieceDomain,
        > {
            replica_id,
            tau: Some(Tau { comm_r, comm_d }),
            seed: seeds[i],
            k: None,
        });
        proofs.push(MultiProof::new_from_reader(
            Some(usize::from(PoRepProofPartitions::from(porep_config))),
            proof_vecs[i],
            &verifying_key,
        )?);
    }

    let result = StackedCompound::<Tree, DefaultPieceHasher>::batch_verify(
        &compound_public_params,
        &public_inputs,
        &proofs,
        &ChallengeRequirements {
            minimum_challenges: *POREP_MINIMUM_CHALLENGES
                .read()
                .expect("POREP_MINIMUM_CHALLENGES poisoned")
                .get(&u64::from(SectorSize::from(porep_config)))
                .expect("unknown sector size") as usize,
        },
    )
    .map_err(Into::into);

    info!("verify_batch_seal:finish");
    result
}
