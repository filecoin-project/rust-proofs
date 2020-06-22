#![no_main]
use filecoin_proofs::{
    verify_window_post, ChallengeSeed, PoStConfig, PoStType, ProverId, PublicReplicaInfo,
    SectorSize,
};
use filecoin_proofs::constants::*;
use storage_proofs::sector::SectorId;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    randomness: ChallengeSeed,
    proof: Vec<u8>,
    replicas: BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
}

fuzz_target!(|wrap: Wrapper| {
    let post_config = PoStConfig {
        sector_size: SectorSize(2048u64),
        sector_count: 1,
        challenge_count: WINDOW_POST_CHALLENGE_COUNT,
        typ: PoStType::Window,
        priority: false,
    };

    //println!("{:?}\n", wrap);
    let _ = verify_window_post::<SectorShape2KiB>(
        &post_config,
        &wrap.randomness,
        &wrap.replicas,
        wrap.prover_id.clone(),
        &wrap.proof,
    );
});
