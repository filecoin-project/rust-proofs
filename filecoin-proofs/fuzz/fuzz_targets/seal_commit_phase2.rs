#![no_main]
use filecoin_proofs::{
    seal_commit_phase2, Commitment, DefaultTreeHasher, Ticket, PoRepConfig, PoRepProofPartitions, ProverId, SectorSize, SealCommitPhase1Output, VanillaSealProof
};
use filecoin_proofs::constants::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;
use storage_proofs::hasher::Hasher;
use storage_proofs::merkle::MerkleProof;
use storage_proofs::porep::stacked::{generate_replica_id, ColumnProof, EncodingProof, LabelingProof, ReplicaColumnProof};
use storage_proofs::sector::SectorId;
use typenum::{U0, U2};

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    //phase1_output: SealCommitPhase1Output,
    comm_r: Commitment,
    comm_d: Commitment,
    seed: Ticket,
    ticket: Ticket,
    prover_id: ProverId,
    sector_id: SectorId,
}

fuzz_target!(|wrap: Wrapper| {
    let po_rep_config = PoRepConfig {
        sector_size: SectorSize(2048u64),
        partitions: PoRepProofPartitions(1),
    };

    //println!("{:?}\n", wrap);
    /*
    let _ = seal_commit_phase2::<SectorShape2KiB>(
        po_rep_config,
        wrap.phase1_output,
        wrap.prover_id,
        wrap.sector_id,
    );
    */
});
