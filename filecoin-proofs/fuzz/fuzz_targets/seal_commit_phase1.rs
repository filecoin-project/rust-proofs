#![no_main]
use filecoin_proofs::{
    seal_commit_phase1, PieceInfo, PoRepConfig, PoRepProofPartitions, ProverId, SectorSize, Ticket, SealPreCommitOutput,
};
use filecoin_proofs::constants::*;
use storage_proofs::sector::SectorId;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    cache_path: PathBuf,
    replica_path: PathBuf,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    pre_commit: SealPreCommitOutput,
    piece_infos: Vec<PieceInfo>,
}

fuzz_target!(|wrap: Wrapper| {
    let po_rep_config = PoRepConfig {
        sector_size: SectorSize(2048u64),
        partitions: PoRepProofPartitions(1),
    };

    //println!("{:?}\n", wrap);
    let _ = seal_commit_phase1::<_, SectorShape2KiB>(
        po_rep_config,
        &wrap.cache_path,
        &wrap.replica_path,
        wrap.prover_id.clone(),
        wrap.sector_id,
        wrap.ticket,
        wrap.seed,
        wrap.pre_commit,
        &wrap.piece_infos,
    );
});
