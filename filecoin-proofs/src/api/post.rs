use std::collections::BTreeMap;
use std::hash::{Hash, Hasher as StdHasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bincode::deserialize;
use generic_array::typenum::Unsigned;
use libfuzzer_sys::arbitrary;
use log::{info, trace};
use merkletree::store::StoreConfig;
use storage_proofs::cache_key::CacheKey;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::merkle::{
    create_tree, get_base_tree_count, split_config_and_replica, MerkleTreeTrait, MerkleTreeWrapper,
};
use storage_proofs::multi_proof::MultiProof;
use storage_proofs::post::fallback;
use storage_proofs::sector::*;
use storage_proofs::util::default_rows_to_discard;

use crate::api::util::{as_safe_commitment, get_base_tree_leafs, get_base_tree_size};
use crate::caches::{get_post_params, get_post_verifying_key};
use crate::constants::*;
use crate::parameters::{window_post_setup_params, winning_post_setup_params};
use crate::types::{
    ChallengeSeed, Commitment, PersistentAux, PoStConfig, ProverId, SectorSize, TemporaryAux,
};
use crate::PoStType;

/// The minimal information required about a replica, in order to be able to generate
/// a PoSt over it.
#[derive(Debug)]
pub struct PrivateReplicaInfo<Tree: MerkleTreeTrait> {
    /// Path to the replica.
    replica: PathBuf,
    /// The replica commitment.
    comm_r: Commitment,
    /// Persistent Aux.
    aux: PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    /// Contains sector-specific (e.g. merkle trees) assets
    cache_dir: PathBuf,

    _t: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait> Clone for PrivateReplicaInfo<Tree> {
    fn clone(&self) -> Self {
        Self {
            replica: self.replica.clone(),
            comm_r: self.comm_r,
            aux: self.aux.clone(),
            cache_dir: self.cache_dir.clone(),
            _t: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait> std::cmp::PartialEq for PrivateReplicaInfo<Tree> {
    fn eq(&self, other: &Self) -> bool {
        self.replica == other.replica
            && self.comm_r == other.comm_r
            && self.aux == other.aux
            && self.cache_dir == other.cache_dir
    }
}

impl<Tree: MerkleTreeTrait> Hash for PrivateReplicaInfo<Tree> {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.replica.hash(state);
        self.comm_r.hash(state);
        self.aux.hash(state);
        self.cache_dir.hash(state);
    }
}

impl<Tree: MerkleTreeTrait> std::cmp::Eq for PrivateReplicaInfo<Tree> {}

impl<Tree: MerkleTreeTrait> std::cmp::Ord for PrivateReplicaInfo<Tree> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.comm_r.as_ref().cmp(other.comm_r.as_ref())
    }
}

impl<Tree: MerkleTreeTrait> std::cmp::PartialOrd for PrivateReplicaInfo<Tree> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.comm_r.as_ref().partial_cmp(other.comm_r.as_ref())
    }
}

impl<Tree: 'static + MerkleTreeTrait> PrivateReplicaInfo<Tree> {
    pub fn new(replica: PathBuf, comm_r: Commitment, cache_dir: PathBuf) -> Result<Self> {
        ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

        let aux = {
            let f_aux_path = cache_dir.join(CacheKey::PAux.to_string());
            let aux_bytes = std::fs::read(&f_aux_path)
                .with_context(|| format!("could not read from path={:?}", f_aux_path))?;

            deserialize(&aux_bytes)
        }?;

        ensure!(replica.exists(), "Sealed replica does not exist");

        Ok(PrivateReplicaInfo {
            replica,
            comm_r,
            aux,
            cache_dir,
            _t: Default::default(),
        })
    }

    pub fn cache_dir_path(&self) -> &Path {
        self.cache_dir.as_path()
    }

    pub fn replica_path(&self) -> &Path {
        self.replica.as_path()
    }

    pub fn safe_comm_r(&self) -> Result<<Tree::Hasher as Hasher>::Domain> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }

    pub fn safe_comm_c(&self) -> Result<<Tree::Hasher as Hasher>::Domain> {
        Ok(self.aux.comm_c)
    }

    pub fn safe_comm_r_last(&self) -> Result<<Tree::Hasher as Hasher>::Domain> {
        Ok(self.aux.comm_r_last)
    }

    /// Generate the merkle tree of this particular replica.
    pub fn merkle_tree(
        &self,
        sector_size: SectorSize,
    ) -> Result<
        MerkleTreeWrapper<
            Tree::Hasher,
            Tree::Store,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    > {
        let base_tree_size = get_base_tree_size::<Tree>(sector_size)?;
        let base_tree_leafs = get_base_tree_leafs::<Tree>(base_tree_size)?;
        trace!(
            "post: base tree size {}, base tree leafs {}, rows_to_discard {}, arities [{}, {}, {}]",
            base_tree_size,
            base_tree_leafs,
            default_rows_to_discard(base_tree_leafs, Tree::Arity::to_usize()),
            Tree::Arity::to_usize(),
            Tree::SubTreeArity::to_usize(),
            Tree::TopTreeArity::to_usize(),
        );

        let mut config = StoreConfig::new(
            self.cache_dir_path(),
            CacheKey::CommRLastTree.to_string(),
            default_rows_to_discard(base_tree_leafs, Tree::Arity::to_usize()),
        );
        config.size = Some(base_tree_size);

        let tree_count = get_base_tree_count::<Tree>();
        let (configs, replica_config) = split_config_and_replica(
            config,
            self.replica_path().to_path_buf(),
            base_tree_leafs,
            tree_count,
        )?;

        create_tree::<Tree>(base_tree_size, &configs, Some(&replica_config))
    }
}

/// The minimal information required about a replica, in order to be able to verify
/// a PoSt over it.
#[derive(arbitrary::Arbitrary, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicReplicaInfo {
    /// The replica commitment.
    comm_r: Commitment,
}

impl std::cmp::Ord for PublicReplicaInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.comm_r.as_ref().cmp(other.comm_r.as_ref())
    }
}

impl std::cmp::PartialOrd for PublicReplicaInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PublicReplicaInfo {
    pub fn new(comm_r: Commitment) -> Result<Self> {
        ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
        Ok(PublicReplicaInfo { comm_r })
    }

    pub fn safe_comm_r<T: Domain>(&self) -> Result<T> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }
}

// Ensure that any associated cached data persisted is discarded.
pub fn clear_cache<Tree: MerkleTreeTrait>(cache_dir: &Path) -> Result<()> {
    info!("clear_cache:start");

    let t_aux = {
        let f_aux_path = cache_dir.to_path_buf().join(CacheKey::TAux.to_string());
        let aux_bytes = std::fs::read(&f_aux_path)
            .with_context(|| format!("could not read from path={:?}", f_aux_path))?;

        deserialize(&aux_bytes)
    }?;

    let result = TemporaryAux::<Tree, DefaultPieceHasher>::clear_temp(t_aux);

    info!("clear_cache:finish");

    result
}

// Ensure that any associated cached data persisted is discarded.
pub fn clear_caches<Tree: MerkleTreeTrait>(
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>,
) -> Result<()> {
    info!("clear_caches:start");

    for replica in replicas.values() {
        clear_cache::<Tree>(&replica.cache_dir.as_path())?;
    }

    info!("clear_caches:finish");

    Ok(())
}

pub type SnarkProof = Vec<u8>;

/// Generates a Winning proof-of-spacetime.
pub fn generate_winning_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PrivateReplicaInfo<Tree>)],
    prover_id: ProverId,
) -> Result<SnarkProof> {
    info!("generate_winning_post:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    ensure!(
        replicas.len() == post_config.sector_count,
        "invalid amount of replicas"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(&post_config)?;
    let param_sector_count = vanilla_params.sector_count;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let trees = replicas
        .iter()
        .map(|(_, replica)| replica.merkle_tree(post_config.sector_size))
        .collect::<Result<Vec<_>>>()?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    let mut priv_sectors = Vec::with_capacity(param_sector_count);

    for _ in 0..param_sector_count {
        for ((id, replica), tree) in replicas.iter().zip(trees.iter()) {
            let comm_r = replica.safe_comm_r()?;
            let comm_c = replica.safe_comm_c()?;
            let comm_r_last = replica.safe_comm_r_last()?;

            pub_sectors.push(fallback::PublicSector::<<Tree::Hasher as Hasher>::Domain> {
                id: *id,
                comm_r,
            });
            priv_sectors.push(fallback::PrivateSector {
                tree,
                comm_c,
                comm_r_last,
            });
        }
    }

    let pub_inputs = fallback::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let proof = fallback::FallbackPoStCompound::<Tree>::prove(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        &groth_params,
    )?;
    let proof = proof.to_vec()?;

    info!("generate_winning_post:finish");

    Ok(proof)
}

/// Given some randomness and a the length of available sectors, generates the challenged sector.
///
/// The returned values are indicies in the range of `0..sector_set_size`, requiring the caller
/// to match the index to the correct sector.
pub fn generate_winning_post_sector_challenge<Tree: MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    sector_set_size: u64,
    prover_id: Commitment,
) -> Result<Vec<u64>> {
    info!("generate_winning_post_sector_challenge:start");
    ensure!(sector_set_size != 0, "empty sector set is invalid");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let result = fallback::generate_sector_challenges(
        randomness_safe,
        post_config.sector_count,
        sector_set_size,
        prover_id_safe,
    );

    info!("generate_winning_post_sector_challenge:finish");

    result
}

/// Verifies a winning proof-of-spacetime.
///
/// The provided `replicas` must be the same ones as passed to `generate_winning_post`, and be based on
/// the indices generated by `generate_winning_post_sector_challenge`. It is the responsibility of the
/// caller to ensure this.
pub fn verify_winning_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PublicReplicaInfo)],
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool> {
    info!("verify_winning_post:start");

    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );
    ensure!(
        post_config.sector_count == replicas.len(),
        "invalid amount of replicas provided"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(&post_config)?;
    let param_sector_count = vanilla_params.sector_count;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;

    let verifying_key = get_post_verifying_key::<Tree>(&post_config)?;

    let proof = MultiProof::new_from_reader(None, &proof[..], &verifying_key)?;
    if proof.len() != 1 {
        return Ok(false);
    }

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    for _ in 0..param_sector_count {
        for (id, replica) in replicas.iter() {
            let comm_r = replica.safe_comm_r()?;
            pub_sectors.push(fallback::PublicSector { id: *id, comm_r });
        }
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let is_valid = fallback::FallbackPoStCompound::verify(
        &pub_params,
        &pub_inputs,
        &proof,
        &fallback::ChallengeRequirements {
            minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
        },
    )?;

    if !is_valid {
        return Ok(false);
    }

    info!("verify_winning_post:finish");

    Ok(true)
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

    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let trees: Vec<_> = replicas
        .iter()
        .map(|(_id, replica)| replica.merkle_tree(post_config.sector_size))
        .collect::<Result<_>>()?;

    let mut pub_sectors = Vec::with_capacity(sector_count);
    let mut priv_sectors = Vec::with_capacity(sector_count);

    for ((sector_id, replica), tree) in replicas.iter().zip(trees.iter()) {
        let comm_r = replica.safe_comm_r()?;
        let comm_c = replica.safe_comm_c()?;
        let comm_r_last = replica.safe_comm_r_last()?;

        pub_sectors.push(fallback::PublicSector {
            id: *sector_id,
            comm_r,
        });
        priv_sectors.push(fallback::PrivateSector {
            tree,
            comm_c,
            comm_r_last,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let proof = fallback::FallbackPoStCompound::prove(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        &groth_params,
    )?;

    info!("generate_window_post:finish");

    Ok(proof.to_vec()?)
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
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;

    let verifying_key = get_post_verifying_key::<Tree>(&post_config)?;

    let proof = MultiProof::new_from_reader(partitions, &proof[..], &verifying_key)?;

    let pub_sectors: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r = replica.safe_comm_r()?;
            Ok(fallback::PublicSector {
                id: *sector_id,
                comm_r,
            })
        })
        .collect::<Result<_>>()?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let is_valid = fallback::FallbackPoStCompound::verify(
        &pub_params,
        &pub_inputs,
        &proof,
        &fallback::ChallengeRequirements {
            minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
        },
    )?;

    if !is_valid {
        return Ok(false);
    }

    info!("verify_window_post:finish");

    Ok(true)
}

fn get_partitions_for_window_post(
    total_sector_count: usize,
    post_config: &PoStConfig,
) -> Option<usize> {
    let partitions = (total_sector_count as f32 / post_config.sector_count as f32).ceil() as usize;

    if partitions > 1 {
        Some(partitions)
    } else {
        None
    }
}
