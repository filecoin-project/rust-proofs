#![no_main]
use filecoin_proofs::{
    verify_seal, Commitment, PoRepConfig, PoRepProofPartitions, ProverId, SectorSize, Ticket,
};

use filecoin_proofs::constants::*;

use storage_proofs::sector::SectorId;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    comm_r_in: Commitment,
    comm_d_in: Commitment,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: Ticket,
    seed: Ticket,
    proof_vec: Vec<u8>,
}

fuzz_target!(|wrap: Wrapper| {
    let po_rep_config = PoRepConfig {
        sector_size: SectorSize(2048u64),
        partitions: PoRepProofPartitions(1),
    };

    //println!("{:?}\n", wrap);
    let _ = verify_seal::<SectorShape2KiB>(
        po_rep_config,
        wrap.comm_r_in,
        wrap.comm_d_in,
        wrap.prover_id,
        wrap.sector_id,
        wrap.ticket,
        wrap.seed,
        &wrap.proof_vec,
    );
});
