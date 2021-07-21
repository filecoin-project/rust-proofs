use std::any::Any;

pub use anyhow::Result;

use bellperson::SynthesisError;

use crate::sector::SectorId;
use neptune::Error as NeptuneError;
#[cfg(any(feature = "gpu"))]
use scheduler_client::Error as SchedulerError;

/// Custom error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Could not create PieceInclusionProof (probably bad piece commitment: comm_p)")]
    BadPieceCommitment,
    #[error("Out of bounds access {} > {}", _0, _1)]
    OutOfBounds(usize, usize),
    #[error("mismatch of data, node_size and nodes {} != {} * {}", _0, _1, _2)]
    InvalidMerkleTreeArgs(usize, usize, usize),
    #[error("{}", _0)]
    Synthesis(#[from] SynthesisError),
    #[error("{}", _0)]
    Io(#[from] std::io::Error),
    #[error("tree root and commitment do not match")]
    InvalidCommitment,
    #[error("malformed input")]
    MalformedInput,
    #[error("malformed merkle tree")]
    MalformedMerkleTree,
    #[error("invalid input size")]
    InvalidInputSize,
    #[error("merkle tree generation error: {}", _0)]
    MerkleTreeGenerationError(String),
    #[error("Cannot (yet) generate inclusion proof for unaligned piece.")]
    UnalignedPiece,
    #[error("{}", _0)]
    Serde(#[from] serde_json::Error),
    #[error("unclassified error: {}", _0)]
    Unclassified(String),
    #[error("Missing Private Input {0} for sector {1}")]
    MissingPrivateInput(&'static str, u64),
    #[error("faulty sectors {:?}", _0)]
    FaultySectors(Vec<SectorId>),
    #[error("Invalid parameters file: {}", _0)]
    InvalidParameters(String),
    #[cfg(any(feature = "gpu"))]
    #[error("Scheduler error: {}", _0)]
    Scheduler(#[from] SchedulerError),
    #[error("{}", _0)]
    Neptune(#[from] NeptuneError),
}

impl From<Box<dyn Any + Send>> for Error {
    fn from(inner: Box<dyn Any + Send>) -> Error {
        Error::Unclassified(format!("{:?}", dbg!(inner)))
    }
}
