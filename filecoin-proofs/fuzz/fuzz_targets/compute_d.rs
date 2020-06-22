#![no_main]
use filecoin_proofs::{
    compute_comm_d, SectorSize, PieceInfo
};
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    piece_infos: Vec<PieceInfo>,
}

fuzz_target!(|wrap: Wrapper| {
    let sector_size = SectorSize(2048);
    //println!("{:?}\n", wrap);
    let _ = compute_comm_d(
        sector_size,
        &wrap.piece_infos,
    );
});
