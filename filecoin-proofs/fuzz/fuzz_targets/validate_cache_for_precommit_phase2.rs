#![no_main]
use filecoin_proofs::{
    validate_cache_for_precommit_phase2, Commitment, SealPreCommitPhase1Output, StoreConfig,
};
use filecoin_proofs::constants::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;
use storage_proofs::porep::stacked::Labels;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    comm_d: Commitment,
    cache_path: PathBuf,
    replica_path: PathBuf,
    //seal_precommit_phase1_output: SealPreCommitPhase1Output,
}

fuzz_target!(|wrap: Wrapper| {
    let config = StoreConfig::new(wrap.cache_path.to_path_buf(), String::from("fuzz-test-id"), 2);
    let labels: Labels<SectorShape2KiB> = Labels::new(vec![config.clone()]);
    let phase1_output: SealPreCommitPhase1Output<SectorShape2KiB> = SealPreCommitPhase1Output {
        labels,
        config,
        comm_d: wrap.comm_d,
    };

    //println!("{:?}\n", wrap);
    let _ = validate_cache_for_precommit_phase2(
        &wrap.cache_path,
        &wrap.replica_path,
        &phase1_output,
    );
});
