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
    Missing,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UlnV2InboundProofTypeObservation {
    pub(crate) fingerprint: String,
    pub(crate) proof_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PayloadSignedValidity {
    NotSigned,
    Signed,
    Missing,
    /// The receiver receives on a library this service cannot validate
    /// against, so whether the payload is already signed there is unknowable.
    /// Distinct from `Missing`, which means the provider did not answer.
    UnsupportedReceiveLibrary,
}
