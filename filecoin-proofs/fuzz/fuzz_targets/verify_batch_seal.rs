#![no_main]
use filecoin_proofs::{
    verify_batch_seal, Commitment, PoRepConfig, PoRepProofPartitions, ProverId, SectorSize, Ticket,
};
use filecoin_proofs::constants::*;
use storage_proofs::sector::SectorId;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    comm_r_in: Vec<Commitment>,
    comm_d_in: Vec<Commitment>,
    prover_id: Vec<ProverId>,
    sector_id: Vec<SectorId>,
    ticket: Vec<Ticket>,
    seed: Vec<Ticket>,
    proof_vec: Vec<Vec<u8>>,
}

fuzz_target!(|wrap: Wrapper| {
    let po_rep_config = PoRepConfig {
        sector_size: SectorSize(2048u64),
        partitions: PoRepProofPartitions(1),
    };

    let mut proof_vec: Vec<&[u8]> = vec![];

    for item in wrap.proof_vec.iter() {
        proof_vec.push(item);
    }

    //println!("{:?}\n", wrap);
    let _ = verify_batch_seal::<SectorShape2KiB>(
        po_rep_config,
        &wrap.comm_r_in,
        &wrap.comm_d_in,
        &wrap.prover_id,
        &wrap.sector_id,
        &wrap.ticket,
        &wrap.seed,
        &proof_vec,
    );
});
