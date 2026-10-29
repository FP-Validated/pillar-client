use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TimestampValidity {
    Valid,
    TooEarly,
    TooLate,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BlockConfirmationValidity {
    Sufficient {
        receipt_block_hash: String,
        receipt_block_number: i64,
    },
    Insufficient {
        receipt_block_hash: String,
        receipt_block_number: i64,
    },
    InvalidRange,
    SourceChanged(String),
    Missing,
}

impl BlockConfirmationValidity {
    /// The quorum key. `SourceChanged` carries diagnostic prose that differs between providers
    /// observing the same reorg, so it must not split the vote.
    pub(crate) fn fingerprint(&self) -> String {
        match self {
            Self::Sufficient {
                receipt_block_hash,
                receipt_block_number,
            } => format!("sufficient:{receipt_block_hash}:{receipt_block_number}"),
            Self::Insufficient {
                receipt_block_hash,
                receipt_block_number,
            } => format!("insufficient:{receipt_block_hash}:{receipt_block_number}"),
            Self::InvalidRange => "invalid-range".to_string(),
            Self::SourceChanged(_) => "source-changed".to_string(),
            Self::Missing => "missing".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockConfirmationObservation {
    pub(crate) validity: BlockConfirmationValidity,
    pub(crate) current_confirmations: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockTime {
    pub(crate) number: i64,
    pub(crate) hash: String,
    pub(crate) parent_hash: String,
    pub(crate) timestamp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockTimeObservation {
    pub(crate) fingerprint: String,
    pub(crate) block: BlockTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransactionFromObservation {
    pub(crate) fingerprint: String,
    pub(crate) from: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UlnV2HashInfoObservation {
    pub(crate) fingerprint: String,
    pub(crate) hash_info: UlnV2HashInfo,
}

/// One provider's reading of the source receipt for a ULNv2 MPT proof. A changed or vanished
/// receipt is a vote against the resolved source, not an absent vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UlnV2MptVote {
    HashInfo(UlnV2HashInfoObservation),
    SourceChanged(String),
}

impl UlnV2MptVote {
    pub(crate) fn fingerprint(&self) -> String {
        match self {
            Self::HashInfo(observation) => format!("hash-info:{}", observation.fingerprint),
            Self::SourceChanged(_) => "source-changed".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UlnV2InboundProofTypeObservation {
    pub(crate) fingerprint: String,
    pub(crate) proof_type: String,
    pub(crate) utils_version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PayloadSignedValidity {
    NotSigned {
        required: Option<u64>,
    },
    Signed,
    Missing,
    /// The receiver receives on a library this service cannot validate
    /// against, so whether the payload is already signed there is unknowable.
    /// Distinct from `Missing`, which means the provider did not answer.
    UnsupportedReceiveLibrary,
}
