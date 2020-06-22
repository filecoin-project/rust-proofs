#![no_main]
use filecoin_proofs::{
    generate_window_post, Commitment, ChallengeSeed, PoStConfig, PrivateReplicaInfo, ProverId,
};
use filecoin_proofs::constants::*;
use storage_proofs::sector::SectorId;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    replica: PathBuf,
    comm_r: Commitment,
    cache_dir: PathBuf,
    post_config: PoStConfig,
    randomness: ChallengeSeed,
    prover_id: ProverId,
    // FIXME: requires Domain to be arbitrary
    //replicas: BTreeMap<SectorId, PrivateReplicaInfo<SectorShape2KiB>>,
}

fuzz_target!(|wrap: Wrapper| {
    /*
    let _ = generate_window_post::<SectorShape2KiB>(
        &wrap.post_config,
        &wrap.randomness,
        &replicas,
        wrap.prover_id.clone(),
    );
    */
});
