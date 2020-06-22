use libfuzzer_sys::arbitrary;

use crate::fr32::to_unpadded_bytes;
use crate::types::*;

#[derive(arbitrary::Arbitrary, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SectorSize(pub u64);

impl From<u64> for SectorSize {
    fn from(size: u64) -> Self {
        SectorSize(size)
    }
}

impl From<SectorSize> for UnpaddedBytesAmount {
    fn from(x: SectorSize) -> Self {
        UnpaddedBytesAmount(to_unpadded_bytes(x.0))
    }
}

impl From<SectorSize> for PaddedBytesAmount {
    fn from(x: SectorSize) -> Self {
        PaddedBytesAmount(x.0)
    }
}

impl From<SectorSize> for u64 {
    fn from(x: SectorSize) -> Self {
        x.0
    }
}
