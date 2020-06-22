#![no_main]
use filecoin_proofs::{
    seal_pre_commit_phase1, PieceInfo, PoRepConfig, PoRepProofPartitions, ProverId, SectorSize, Ticket,
};
use filecoin_proofs::constants::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;
use storage_proofs::sector::SectorId;
use std::path::PathBuf;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    cache_path: PathBuf,
    in_path: PathBuf,
    out_path: PathBuf,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    piece_infos: Vec<PieceInfo>,
}

fuzz_target!(|wrap: Wrapper| {
    let po_rep_config = PoRepConfig {
        sector_size: SectorSize(2048u64),
        partitions: PoRepProofPartitions(1),
    };

    //println!("{:?}\n", wrap);
    let _ = seal_pre_commit_phase1::<_, _, _, SectorShape2KiB>(
        po_rep_config,
        &wrap.cache_path,
        &wrap.in_path,
        &wrap.out_path,
        wrap.prover_id.clone(),
        wrap.sector_id,
        wrap.ticket,
        &wrap.piece_infos,
    );
});
