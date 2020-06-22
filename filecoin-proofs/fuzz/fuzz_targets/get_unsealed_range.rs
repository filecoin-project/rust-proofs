#![no_main]
use filecoin_proofs::{
    get_unsealed_range, Commitment, PoRepConfig, PoRepProofPartitions, ProverId, SectorSize, Ticket, UnpaddedByteIndex, UnpaddedBytesAmount, SectorShape2KiB,
};
use storage_proofs::sector::SectorId;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    cache_path: PathBuf,
    sealed_path: PathBuf,
    output_path: PathBuf,
    prover_id: ProverId,
    sector_id: SectorId,
    comm_d: Commitment,
    ticket: Ticket,
    offset: UnpaddedByteIndex,
    num_bytes: UnpaddedBytesAmount,
}

fuzz_target!(|wrap: Wrapper| {
    let po_rep_config = PoRepConfig {
        sector_size: SectorSize(2048u64),
        partitions: PoRepProofPartitions(1),
    };

    //println!("{:?}\n", wrap);
    let _ = get_unsealed_range::<_, SectorShape2KiB>(
        po_rep_config,
        &wrap.cache_path,
        &wrap.sealed_path,
        &wrap.output_path,
        wrap.prover_id,
        wrap.sector_id,
        wrap.comm_d,
        wrap.ticket,
        wrap.offset,
        wrap.num_bytes,
    );
});
