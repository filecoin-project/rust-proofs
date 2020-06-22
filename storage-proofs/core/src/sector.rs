use std::collections::BTreeSet;
use std::fmt;

use byteorder::ByteOrder;
use ff::PrimeField;
use libfuzzer_sys::arbitrary;
use paired::bls12_381::{Fr, FrRepr};
use serde::{Deserialize, Serialize};

/// An ordered set of `SectorId`s.
pub type OrderedSectorSet = BTreeSet<SectorId>;

/// Identifier for a single sector.
#[derive(
    arbitrary::Arbitrary,
    Default,
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct SectorId(u64);

impl From<u64> for SectorId {
    fn from(n: u64) -> Self {
        SectorId(n)
    }
}

impl From<SectorId> for u64 {
    fn from(n: SectorId) -> Self {
        n.0
    }
}

impl From<SectorId> for Fr {
    fn from(n: SectorId) -> Self {
        Fr::from_repr(FrRepr::from(n.0)).unwrap()
    }
}

impl fmt::Display for SectorId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SectorId({})", self.0)
    }
}

impl SectorId {
    pub fn as_fr_safe(self) -> [u8; 31] {
        let mut buf: [u8; 31] = [0; 31];
        byteorder::LittleEndian::write_u64(&mut buf[0..8], self.0);
        buf
    }
}
