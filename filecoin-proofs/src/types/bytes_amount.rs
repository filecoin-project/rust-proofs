use std::ops::{Add, Sub};

use libfuzzer_sys::arbitrary;
use serde::{Deserialize, Serialize};

use crate::fr32::{to_padded_bytes, to_unpadded_bytes};

pub struct PoStProofBytesAmount(pub usize);

pub struct PoRepProofBytesAmount(pub usize);

#[derive(
    arbitrary::Arbitrary,
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    Eq,
    Ord,
)]
pub struct UnpaddedByteIndex(pub u64);

#[derive(
    arbitrary::Arbitrary,
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    Eq,
    Ord,
)]
pub struct UnpaddedBytesAmount(pub u64);

#[derive(Debug, Default, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub struct PaddedBytesAmount(pub u64);

impl From<UnpaddedBytesAmount> for u64 {
    fn from(n: UnpaddedBytesAmount) -> Self {
        n.0
    }
}

impl From<UnpaddedBytesAmount> for usize {
    fn from(n: UnpaddedBytesAmount) -> Self {
        n.0 as usize
    }
}

impl From<UnpaddedBytesAmount> for PaddedBytesAmount {
    fn from(n: UnpaddedBytesAmount) -> Self {
        PaddedBytesAmount(to_padded_bytes(n.0 as usize) as u64)
    }
}

impl From<PaddedBytesAmount> for u64 {
    fn from(n: PaddedBytesAmount) -> Self {
        n.0
    }
}

impl From<PaddedBytesAmount> for usize {
    fn from(n: PaddedBytesAmount) -> Self {
        n.0 as usize
    }
}

impl From<PaddedBytesAmount> for UnpaddedBytesAmount {
    fn from(n: PaddedBytesAmount) -> Self {
        UnpaddedBytesAmount(to_unpadded_bytes(n.0))
    }
}

impl From<UnpaddedBytesAmount> for UnpaddedByteIndex {
    fn from(n: UnpaddedBytesAmount) -> Self {
        UnpaddedByteIndex(n.0)
    }
}

impl From<UnpaddedByteIndex> for UnpaddedBytesAmount {
    fn from(n: UnpaddedByteIndex) -> Self {
        UnpaddedBytesAmount(n.0)
    }
}

impl From<UnpaddedByteIndex> for u64 {
    fn from(n: UnpaddedByteIndex) -> Self {
        n.0
    }
}

impl From<UnpaddedByteIndex> for usize {
    fn from(n: UnpaddedByteIndex) -> Self {
        n.0 as usize
    }
}

impl Add for UnpaddedBytesAmount {
    type Output = UnpaddedBytesAmount;

    fn add(self, other: UnpaddedBytesAmount) -> UnpaddedBytesAmount {
        UnpaddedBytesAmount(self.0 + other.0)
    }
}

impl Add for PaddedBytesAmount {
    type Output = PaddedBytesAmount;

    fn add(self, other: PaddedBytesAmount) -> PaddedBytesAmount {
        PaddedBytesAmount(self.0 + other.0)
    }
}

impl Sub for UnpaddedBytesAmount {
    type Output = UnpaddedBytesAmount;

    fn sub(self, other: UnpaddedBytesAmount) -> UnpaddedBytesAmount {
        UnpaddedBytesAmount(self.0 - other.0)
    }
}

impl Sub for PaddedBytesAmount {
    type Output = PaddedBytesAmount;

    fn sub(self, other: PaddedBytesAmount) -> PaddedBytesAmount {
        PaddedBytesAmount(self.0 - other.0)
    }
}

impl From<PoStProofBytesAmount> for usize {
    fn from(x: PoStProofBytesAmount) -> Self {
        x.0
    }
}

impl From<PoRepProofBytesAmount> for usize {
    fn from(x: PoRepProofBytesAmount) -> Self {
        x.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_operations() {
        let a = UnpaddedBytesAmount(1);
        let b = UnpaddedBytesAmount(2);
        let c = UnpaddedBytesAmount(3);

        let d = PaddedBytesAmount(1);
        let e = PaddedBytesAmount(2);
        let f = PaddedBytesAmount(3);

        // Operations between UnpaddedBytesAmounts are allowed
        assert_eq!(a + b, c);
        assert_eq!(c - b, a);

        // Operations between PaddedBytesAmounts are allowed
        assert_eq!(d + e, f);
        assert_eq!(f - e, d);

        // Mixed operations fail at compile time.
        // assert_eq!(a + b, f);

        // Coercion to primitives work
        assert_eq!(1u64 + u64::from(b), 3u64);
        assert_eq!(1usize + usize::from(b), 3usize);
        assert_eq!(1u64 + u64::from(e), 3u64);
        assert_eq!(1usize + usize::from(e), 3usize);

        // But not between BytesAmount types
        // assert_eq!(a + UnpaddedBytesAmount::from(e), c);
        // assert_eq!(d + UnpaddedBytesAmount::from(b), f);

        // But must be explicit or won't compile.
        // assert_eq!(1u64 + b, 3u64);
        // assert_eq!(1usize + b, 3usize);
        // assert_eq!(1u64 + u64::from(e), 3u64);
        // assert_eq!(1usize + usize::from(e), 3usize);
    }
}
