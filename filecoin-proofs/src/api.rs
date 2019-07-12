use std::fs::{copy, File, OpenOptions};
use std::io::prelude::*;
use std::io::{BufWriter, Cursor, Read, SeekFrom};
use std::path::{Path, PathBuf};

use ff::PrimeField;
use memmap::MmapOptions;
use paired::bls12_381::Bls12;
use paired::Engine;
use tempfile::tempfile;

use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::vdf_post::VDFPostCompound;
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgraph::{DefaultTreeHasher, Graph};
use storage_proofs::fr32::{bytes_into_fr, fr_into_bytes, Fr32Ary};
use storage_proofs::hasher::pedersen::{PedersenDomain, PedersenHasher};
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::layered_drgporep::{self, ChallengeRequirements};
use storage_proofs::merkle::MerkleTree;
use storage_proofs::piece_inclusion_proof::{
    generate_piece_commitment_bytes_from_source, piece_inclusion_proofs, PieceInclusionProof,
    PieceSpec,
};
use storage_proofs::porep::{replica_id, PoRep, Tau};
use storage_proofs::proof::NoRequirements;
use storage_proofs::zigzag_drgporep::ZigZagDrgPoRep;
use storage_proofs::{vdf_post, vdf_sloth};

use crate::caches::{
    get_post_params, get_post_verifying_key, get_zigzag_params, get_zigzag_verifying_key,
};
use crate::constants::{POREP_MINIMUM_CHALLENGES, SINGLE_PARTITION_PROOF_LEN};
use crate::error;
use crate::error::ExpectWithBacktrace;
use crate::file_cleanup::FileCleanup;
use crate::fr32::{write_padded, write_unpadded};
use crate::parameters::{post_setup_params, public_params, setup_params};
use crate::pieces::{get_aligned_source, get_piece_alignment, PieceAlignment};
use crate::post_adapter::*;
use crate::singletons::ENGINE_PARAMS;
use crate::singletons::FCP_LOG;
use crate::types::{
    PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, PoStConfig, PoStProofPartitions,
    SectorSize, UnpaddedByteIndex, UnpaddedBytesAmount,
};

/// FrSafe is an array of the largest whole number of bytes guaranteed not to overflow the field.
pub type FrSafe = [u8; 31];

pub type Commitment = Fr32Ary;
pub type ChallengeSeed = Fr32Ary;
type Tree = MerkleTree<PedersenDomain, <PedersenHasher as Hasher>::Function>;

#[derive(Clone, Debug)]
pub struct SealOutput {
    pub comm_r: Commitment,
    pub comm_r_star: Commitment,
    pub comm_d: Commitment,
    pub proof: Vec<u8>,
    pub comm_ps: Vec<Commitment>,
    pub piece_inclusion_proofs: Vec<PieceInclusionProof<PedersenHasher>>,
}

/// Generates a proof-of-spacetime, returning and detected storage faults.
/// Accepts as input a challenge seed, configuration struct, and a vector of
/// sealed sector file-path plus CommR tuples.
///
pub fn generate_post(
    post_config: PoStConfig,
    challenge_seed: ChallengeSeed,
    input_parts: Vec<(Option<String>, Commitment)>,
) -> error::Result<GeneratePoStDynamicSectorsCountOutput> {
    generate_post_dynamic(GeneratePoStDynamicSectorsCountInput {
        post_config,
        challenge_seed,
        input_parts,
    })
}

/// Verifies a proof-of-spacetime.
///
pub fn verify_post(
    post_config: PoStConfig,
    comm_rs: Vec<Commitment>,
    challenge_seed: ChallengeSeed,
    proofs: Vec<Vec<u8>>,
    faults: Vec<u64>,
) -> error::Result<VerifyPoStDynamicSectorsCountOutput> {
    verify_post_dynamic(VerifyPoStDynamicSectorsCountInput {
        post_config,
        comm_rs,
        challenge_seed,
        proofs,
        faults,
    })
}

/// @SIDTODO: write tests for this complicated block
fn generate_piece_specs<T: AsRef<Path>>(
    piece_lengths: &[UnpaddedBytesAmount],
    in_path: T,
) -> error::Result<Vec<PieceSpec>> {
    let mut piece_specs = Vec::new();
    let mut cursor = UnpaddedBytesAmount(0);
    let mut in_data = OpenOptions::new().read(true).open(&in_path)?;

    for &unpadded_piece_length in piece_lengths {
        let PieceAlignment {
            left_bytes,
            right_bytes,
        } = get_piece_alignment(cursor, unpadded_piece_length);

        let padded_piece_length = PaddedBytesAmount::from(unpadded_piece_length);
        let padded_left_bytes = PaddedBytesAmount::from(left_bytes);
        let padded_right_bytes =
            PaddedBytesAmount::from(unpadded_piece_length + right_bytes) - padded_piece_length;

        let leaf_position = (usize::from(cursor) / 127) * 4;

        cursor = cursor + left_bytes + unpadded_piece_length + right_bytes;

        let number_of_leaves = (usize::from(cursor) / 127) * 4 - leaf_position;

        let mut buf = vec![0; usize::from(padded_left_bytes)];
        in_data.read_exact(&mut buf)?;

        let mut buf = vec![0; usize::from(padded_piece_length + padded_right_bytes)];
        in_data.read_exact(&mut buf)?;

        let mut source = Cursor::new(&buf);
        let comm_p = generate_piece_commitment_bytes_from_source::<PedersenHasher>(&mut source)?;

        piece_specs.push(PieceSpec {
            comm_p,
            position: leaf_position,
            number_of_leaves,
        });
    }

    Ok(piece_specs)
}

/// Seals the staged sector at `in_path` in place, saving the resulting replica
/// to `out_path`.
///
pub fn seal<T: AsRef<Path>>(
    porep_config: PoRepConfig,
    in_path: T,
    out_path: T,
    prover_id_in: &FrSafe,
    sector_id_in: &FrSafe,
    piece_lengths: &[UnpaddedBytesAmount],
) -> error::Result<SealOutput> {
    let sector_bytes = usize::from(PaddedBytesAmount::from(porep_config));

    let mut cleanup = FileCleanup::new(&out_path);

    // Copy unsealed data to output location, where it will be sealed in place.
    copy(&in_path, &out_path)?;
    let f_data = OpenOptions::new().read(true).write(true).open(&out_path)?;

    // Zero-pad the data to the requested size by extending the underlying file if needed.
    f_data.set_len(sector_bytes as u64)?;

    let mut data = unsafe { MmapOptions::new().map_mut(&f_data).unwrap() };

    // Zero-pad the prover_id to 32 bytes (and therefore Fr32).
    let prover_id = pad_safe_fr(prover_id_in);
    // Zero-pad the sector_id to 32 bytes (and therefore Fr32).
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        engine_params: &(*ENGINE_PARAMS),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params = ZigZagCompound::setup(&compound_setup_params)?;

    let (tau, aux) = ZigZagDrgPoRep::replicate(
        &compound_public_params.vanilla_params,
        &replica_id,
        &mut data,
        None,
    )?;

    let piece_specs = generate_piece_specs(&piece_lengths, &in_path)?;
    let piece_inclusion_proofs = piece_inclusion_proofs::<PedersenHasher>(&piece_specs, &aux[0])?;
    let comm_ps: Vec<Commitment> = piece_specs
        .iter()
        .map(|piece_spec| piece_spec.comm_p)
        .collect();

    // If we succeeded in replicating, flush the data and protect output from being cleaned up.
    data.flush()?;
    cleanup.success = true;

    let public_tau = tau.simplify();

    let public_inputs = layered_drgporep::PublicInputs {
        replica_id,
        tau: Some(public_tau),
        comm_r_star: tau.comm_r_star,
        k: None,
        seed: None,
    };

    let private_inputs = layered_drgporep::PrivateInputs::<DefaultTreeHasher> {
        aux,
        tau: tau.layer_taus,
    };

    let groth_params = get_zigzag_params(porep_config)?;

    info!(FCP_LOG, "got groth params ({}) while sealing", u64::from(PaddedBytesAmount::from(porep_config)); "target" => "params");

    let proof = ZigZagCompound::prove(
        &compound_public_params,
        &public_inputs,
        &private_inputs,
        &groth_params,
    )?;

    let mut buf = Vec::with_capacity(
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoRepProofPartitions::from(porep_config)),
    );

    proof.write(&mut buf)?;

    let comm_r = commitment_from_fr::<Bls12>(public_tau.comm_r.into());
    let comm_d = commitment_from_fr::<Bls12>(public_tau.comm_d.into());
    let comm_r_star = commitment_from_fr::<Bls12>(tau.comm_r_star.into());

    let valid_pieces = PieceInclusionProof::verify_all(
        &comm_d,
        &piece_inclusion_proofs,
        &comm_ps,
        &piece_specs
            .into_iter()
            .map(|p| p.number_of_leaves)
            .collect::<Vec<_>>(),
        (sector_bytes / 127) * 4,
    )
    .expect("pip verification sanity check failed");

    if !valid_pieces {
        return Err(format_err!("pip verification sanity check failed"));
    }

    // Verification is cheap when parameters are cached,
    // and it is never correct to return a proof which does not verify.
    verify_seal(
        porep_config,
        comm_r,
        comm_d,
        comm_r_star,
        prover_id_in,
        sector_id_in,
        &buf,
    )
    .expect("post-seal verification sanity check failed");

    Ok(SealOutput {
        comm_r,
        comm_r_star,
        comm_d,
        proof: buf,
        comm_ps,
        piece_inclusion_proofs,
    })
}

/// Verifies the output of some previously-run seal operation.
///
pub fn verify_seal(
    porep_config: PoRepConfig,
    comm_r: Commitment,
    comm_d: Commitment,
    comm_r_star: Commitment,
    prover_id_in: &FrSafe,
    sector_id_in: &FrSafe,
    proof_vec: &[u8],
) -> error::Result<bool> {
    let sector_bytes = PaddedBytesAmount::from(porep_config);
    let prover_id = pad_safe_fr(prover_id_in);
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let comm_r = bytes_into_fr::<Bls12>(&comm_r)?;
    let comm_d = bytes_into_fr::<Bls12>(&comm_d)?;
    let comm_r_star = bytes_into_fr::<Bls12>(&comm_r_star)?;

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        engine_params: &(*ENGINE_PARAMS),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let compound_public_params: compound_proof::PublicParams<
        '_,
        Bls12,
        ZigZagDrgPoRep<'_, DefaultTreeHasher>,
    > = ZigZagCompound::setup(&compound_setup_params)?;

    let public_inputs = layered_drgporep::PublicInputs::<<DefaultTreeHasher as Hasher>::Domain> {
        replica_id,
        tau: Some(Tau {
            comm_r: comm_r.into(),
            comm_d: comm_d.into(),
        }),
        seed: None,
        comm_r_star: comm_r_star.into(),
        k: None,
    };

    let verifying_key = get_zigzag_verifying_key(porep_config)?;

    info!(FCP_LOG, "got verifying key ({}) while verifying seal", u64::from(sector_bytes); "target" => "params");

    let proof = MultiProof::new_from_reader(
        Some(usize::from(PoRepProofPartitions::from(porep_config))),
        proof_vec,
        &verifying_key,
    )?;

    ZigZagCompound::verify(
        &compound_public_params,
        &public_inputs,
        &proof,
        &ChallengeRequirements {
            minimum_challenges: POREP_MINIMUM_CHALLENGES,
        },
    )
    .map_err(Into::into)
}

/// Verify the provided piece inclusion proof demonstrates the piece commitment exists in a
/// merkle tree of a specific size with root hash comm_d
pub fn verify_piece_inclusion_proof(
    piece_inclusion_proof: &[u8],
    comm_d: &Commitment,
    comm_p: &Commitment,
    piece_size: PaddedBytesAmount,
    sector_size: SectorSize,
) -> error::Result<bool> {
    let piece_inclusion_proof: PieceInclusionProof<PedersenHasher> = piece_inclusion_proof.into();
    let comm_d = storage_proofs::hasher::pedersen::PedersenDomain::try_from_bytes(comm_d)?;
    let comm_p = storage_proofs::hasher::pedersen::PedersenDomain::try_from_bytes(comm_p)?;
    let piece_leaves = u64::from(piece_size) / 32;
    let sector_leaves = u64::from(PaddedBytesAmount::from(sector_size)) / 32;

    Ok(piece_inclusion_proof.verify(
        &comm_d,
        &comm_p,
        piece_leaves as usize,
        sector_leaves as usize,
    ))
}

/// Takes a piece file at `unpadded_piece_path` and the size of the piece and returns the comm_p
/// alongside the number of padded bytes (both bit padded and piece aligned) that are used to
/// generate the comm_p.
///
pub fn generate_piece_commitment<T: Into<PathBuf> + AsRef<Path>>(
    unpadded_piece_path: T,
    unpadded_piece_size: UnpaddedBytesAmount,
) -> error::Result<(Commitment, PaddedBytesAmount)> {
    let mut unpadded_piece_file = File::open(unpadded_piece_path)?;
    let mut padded_piece_file = tempfile()?;

    let (_, mut source) = get_aligned_source(&mut unpadded_piece_file, &[], unpadded_piece_size);
    let padded_piece_size = write_padded(&mut source, &mut padded_piece_file)?;

    let _ = padded_piece_file.seek(SeekFrom::Start(0))?;

    let comm_p =
        generate_piece_commitment_bytes_from_source::<PedersenHasher>(&mut padded_piece_file)?;
    Ok((comm_p, PaddedBytesAmount(padded_piece_size as u64)))
}

/// Unseals the sector at `sealed_path` and returns the bytes for a piece
/// whose first (unpadded) byte begins at `offset` and ends at `offset` plus
/// `num_bytes`, inclusive. Note that the entire sector is unsealed each time
/// this function is called.
///
pub fn get_unsealed_range<T: Into<PathBuf> + AsRef<Path>>(
    porep_config: PoRepConfig,
    sealed_path: T,
    output_path: T,
    prover_id_in: &FrSafe,
    sector_id_in: &FrSafe,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
) -> error::Result<(UnpaddedBytesAmount)> {
    let prover_id = pad_safe_fr(prover_id_in);
    let sector_id = pad_safe_fr(sector_id_in);
    let replica_id = replica_id::<DefaultTreeHasher>(prover_id, sector_id);

    let f_in = File::open(sealed_path)?;
    let mut data = Vec::new();
    f_in.take(u64::from(PaddedBytesAmount::from(porep_config)))
        .read_to_end(&mut data)?;

    let f_out = File::create(output_path)?;
    let mut buf_writer = BufWriter::new(f_out);

    let unsealed = ZigZagDrgPoRep::extract_all(
        &public_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        ),
        &replica_id,
        &data,
    )?;

    let written = write_unpadded(&unsealed, &mut buf_writer, offset.into(), num_bytes.into())?;

    Ok(UnpaddedBytesAmount(written as u64))
}

fn verify_post_dynamic(
    dynamic: VerifyPoStDynamicSectorsCountInput,
) -> error::Result<VerifyPoStDynamicSectorsCountOutput> {
    let fixed = verify_post_spread_input(dynamic)?
        .iter()
        .map(verify_post_fixed_sectors_count)
        .collect();

    verify_post_collect_output(fixed)
}

fn generate_post_dynamic(
    dynamic: GeneratePoStDynamicSectorsCountInput,
) -> error::Result<GeneratePoStDynamicSectorsCountOutput> {
    let n = { dynamic.input_parts.len() };

    let fixed_output = generate_post_spread_input(dynamic)
        .iter()
        .map(generate_post_fixed_sectors_count)
        .collect();

    generate_post_collect_output(n, fixed_output)
}

fn generate_post_fixed_sectors_count(
    fixed: &GeneratePoStFixedSectorsCountInput,
) -> error::Result<GeneratePoStFixedSectorsCountOutput> {
    let faults: Vec<u64> = Vec::new();

    let setup_params = compound_proof::SetupParams {
        vanilla_params: &post_setup_params(fixed.post_config),
        engine_params: &(*ENGINE_PARAMS),
        partitions: None,
    };

    let pub_params: compound_proof::PublicParams<
        _,
        vdf_post::VDFPoSt<PedersenHasher, vdf_sloth::Sloth>,
    > = VDFPostCompound::setup(&setup_params).expect("setup failed");

    let commitments = fixed
        .input_parts
        .iter()
        .map(|(_, comm_r)| PedersenDomain::try_from_bytes(&comm_r[..]).unwrap()) // FIXME: don't unwrap
        .collect();

    let safe_challenge_seed = {
        let mut cs = vec![0; 32];
        cs.copy_from_slice(&fixed.challenge_seed);
        cs[31] &= 0b0011_1111;
        cs
    };

    let pub_inputs = vdf_post::PublicInputs {
        challenge_seed: PedersenDomain::try_from_bytes(&safe_challenge_seed).unwrap(),
        commitments,
        faults: Vec::new(),
    };

    let trees: Vec<Tree> = fixed
        .input_parts
        .iter()
        .map(|(access, _)| {
            if let Some(s) = &access {
                make_merkle_tree(
                    s,
                    PaddedBytesAmount(pub_params.vanilla_params.sector_size as u64),
                )
                .unwrap()
            } else {
                panic!("faults are not yet supported")
            }
        })
        .collect();

    let borrowed_trees: Vec<&Tree> = trees.iter().map(|t| t).collect();

    let priv_inputs = vdf_post::PrivateInputs::<PedersenHasher>::new(&borrowed_trees[..]);

    let groth_params = get_post_params(fixed.post_config)?;

    let proof = VDFPostCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params)
        .expect("failed while proving");

    let mut buf = Vec::with_capacity(
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoStProofPartitions::from(fixed.post_config)),
    );

    proof.write(&mut buf)?;

    Ok(GeneratePoStFixedSectorsCountOutput { proof: buf, faults })
}

fn verify_post_fixed_sectors_count(
    fixed: &VerifyPoStFixedSectorsCountInput,
) -> error::Result<VerifyPoStFixedSectorsCountOutput> {
    let safe_challenge_seed = {
        let mut cs = vec![0; 32];
        cs.copy_from_slice(&fixed.challenge_seed);
        cs[31] &= 0b0011_1111;
        cs
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params: &post_setup_params(fixed.post_config),
        engine_params: &(*ENGINE_PARAMS),
        partitions: None,
    };

    let compound_public_params: compound_proof::PublicParams<
        _,
        vdf_post::VDFPoSt<PedersenHasher, vdf_sloth::Sloth>,
    > = VDFPostCompound::setup(&compound_setup_params).expect("setup failed");

    let commitments = fixed
        .comm_rs
        .iter()
        .map(|comm_r| {
            PedersenDomain(
                bytes_into_fr::<Bls12>(comm_r)
                    .expects("could not could not map comm_r to Fr")
                    .into_repr(),
            )
        })
        .collect::<Vec<PedersenDomain>>();

    let public_inputs = vdf_post::PublicInputs::<PedersenDomain> {
        commitments,
        challenge_seed: PedersenDomain::try_from_bytes(&safe_challenge_seed)?,
        faults: fixed.faults.clone(),
    };

    let verifying_key = get_post_verifying_key(fixed.post_config)?;

    let num_post_proof_bytes =
        SINGLE_PARTITION_PROOF_LEN * usize::from(PoStProofPartitions::from(fixed.post_config));

    let proof = MultiProof::new_from_reader(
        Some(usize::from(PoStProofPartitions::from(fixed.post_config))),
        &fixed.proof[0..num_post_proof_bytes],
        &verifying_key,
    )?;

    let is_valid = VDFPostCompound::verify(
        &compound_public_params,
        &public_inputs,
        &proof,
        &NoRequirements,
    )?;

    // Since callers may rely on previous mocked success, just pretend verification succeeded, for now.
    Ok(VerifyPoStFixedSectorsCountOutput { is_valid })
}

fn make_merkle_tree<T: Into<PathBuf> + AsRef<Path>>(
    sealed_path: T,
    bytes: PaddedBytesAmount,
) -> storage_proofs::error::Result<Tree> {
    let mut f_in = File::open(sealed_path.into())?;
    let mut data = Vec::new();
    f_in.read_to_end(&mut data)?;

    public_params(bytes, 1).graph.merkle_tree(&data)
}

fn commitment_from_fr<E: Engine>(fr: E::Fr) -> Commitment {
    let mut commitment = [0; 32];
    for (i, b) in fr_into_bytes::<E>(&fr).iter().enumerate() {
        commitment[i] = *b;
    }
    commitment
}

fn pad_safe_fr(unpadded: &FrSafe) -> Fr32Ary {
    let mut res = [0; 32];
    res[0..31].copy_from_slice(unpadded);
    res
}

#[cfg(test)]
mod tests {
    use crate::constants::{
        MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR as MINIMUM_PIECE_SIZE,
        TEST_SECTOR_SIZE,
    };
    use crate::types::SectorSize;
    use tempfile::NamedTempFile;

    use super::*;

    fn generate_comm_p(data: &[u8]) -> Result<Commitment, failure::Error> {
        let mut file = NamedTempFile::new().expects("could not create named temp file");
        file.write_all(data)?;
        let (comm_p, _) =
            generate_piece_commitment(file.path(), UnpaddedBytesAmount(data.len() as u64))?;
        Ok(comm_p)
    }

    fn add_piece<R, W>(
        mut source: &mut R,
        target: &mut W,
        piece_size: UnpaddedBytesAmount,
    ) -> std::io::Result<usize>
    where
        R: Read + ?Sized,
        W: Read + Write + Seek + ?Sized,
    {
        let (_, mut aligned_source) = get_aligned_source(&mut source, &[], piece_size);
        write_padded(&mut aligned_source, target)
    }

    #[test]
    fn test_generate_piece_commitment_up_to_minimum() -> Result<(), failure::Error> {
        // test comm_p generation for all byte lengths up to the minimum piece alignment when
        // writing a piece to a sector
        let max = MINIMUM_PIECE_SIZE as usize;

        for n in 0..=max {
            let bytes: Vec<u8> = (0..n).map(|_| rand::random::<u8>()).collect();
            let mut data_a = vec![0; n];
            let mut data_b = vec![0; max];

            for i in 0..n {
                data_a[i] = bytes[i];
                data_b[i] = bytes[i];
            }

            let comm_p_a = generate_comm_p(&data_a)?;
            let comm_p_b = generate_comm_p(&data_b)?;

            assert_eq!(comm_p_a, comm_p_b);
        }

        Ok(())
    }

    #[test]
    fn test_generate_piece_commitment_over_minimum() -> Result<(), failure::Error> {
        // sanity check that larger byte lengths are still zero padded
        let bytes: Vec<u8> = (0..400).map(|_| rand::random::<u8>()).collect();
        let mut data_a = vec![0; 400];
        let mut data_b = vec![0; 508];

        for i in 0..400 {
            data_a[i] = bytes[i];
            data_b[i] = bytes[i];
        }

        let comm_p_a = generate_comm_p(&data_a)?;
        let comm_p_b = generate_comm_p(&data_b)?;

        assert_eq!(comm_p_a, comm_p_b);

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_pip_lifecycle() -> Result<(), failure::Error> {
        let number_of_bytes_in_piece: u64 = 500;
        let unpadded_number_of_bytes_in_piece = UnpaddedBytesAmount(number_of_bytes_in_piece);
        let bytes: Vec<u8> = (0..number_of_bytes_in_piece)
            .map(|_| rand::random::<u8>())
            .collect();
        let mut piece_file = NamedTempFile::new().expects("could not create named temp file");
        piece_file.write_all(&bytes)?;
        piece_file.seek(SeekFrom::Start(0))?;
        let (comm_p, padded_number_of_bytes_in_piece) =
            generate_piece_commitment(&piece_file.path(), unpadded_number_of_bytes_in_piece)?;

        let mut staged_sector_file =
            NamedTempFile::new().expects("could not create named temp file");

        add_piece(
            &mut piece_file,
            &mut staged_sector_file,
            unpadded_number_of_bytes_in_piece,
        )?;

        let sealed_sector_file = NamedTempFile::new().expects("could not create named temp file");

        let sector_size = SectorSize(TEST_SECTOR_SIZE);
        let config = PoRepConfig(sector_size, PoRepProofPartitions(2));

        let output = seal(
            config,
            &staged_sector_file.path(),
            &sealed_sector_file.path(),
            &[0; 31],
            &[0; 31],
            &[unpadded_number_of_bytes_in_piece],
        )?;

        let piece_inclusion_proof_bytes: Vec<u8> = output.piece_inclusion_proofs[0].clone().into();

        let verified = verify_piece_inclusion_proof(
            &piece_inclusion_proof_bytes,
            &output.comm_d,
            &output.comm_ps[0],
            padded_number_of_bytes_in_piece,
            sector_size,
        )?;

        assert!(verified);

        assert_eq!(output.comm_ps.len(), 1);
        assert_eq!(output.comm_ps[0], comm_p);

        Ok(())
    }
}
