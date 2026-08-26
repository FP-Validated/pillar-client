//! BCS encoding of a Sui / IOTA `TransactionKind` for `devInspect`, ported from
//! the upstream LayerZero TypeScript implementation's use of
//! `@mysten/sui` / `@iota/iota-sdk`.
//!
//! The upstream view helpers build a programmable transaction and send
//! `tx.build({ onlyTransactionKind: true })` to
//! `sui_devInspectTransactionBlock` (TS:
//! `packages/common-suimove/src/utils.ts:72-111`,
//! `packages/common-sui/src/provider.ts:110-114`). Only the transaction *kind*
//! is serialized — no gas data, sender or expiration; the sender is an RPC
//! parameter.
//!
//! Layout, from the SDK's BCS schemas:
//! * `TransactionKind` is an enum whose first variant (tag 0) is
//!   `ProgrammableTransaction { inputs: vector<CallArg>, commands: vector<Command> }`
//! * `CallArg` is an enum: tag 0 `Pure(vector<u8>)`, tag 1 `Object(ObjectArg)`
//! * `ObjectArg` is an enum: tag 0 `ImmOrOwnedObject`, tag 1
//!   `SharedObject { id, initial_shared_version, mutable }`, tag 2 `Receiving`
//! * `Command` tag 0 is `MoveCall { package, module, function, type_arguments,
//!   arguments }`
//! * `Argument` is an enum: tag 0 `GasCoin`, tag 1 `Input(u16)`, tag 2
//!   `Result(u16)`, tag 3 `NestedResult(u16, u16)`
//!
//! BCS encodes enum tags and sequence lengths as ULEB128, integers
//! little-endian, and `String` as ULEB128 length plus UTF-8 bytes.
//!
//! Only shared objects and pure values are supported. Every object the
//! payload-signed views touch is a shared singleton (the ULN 302, its
//! verification store and EndpointV2 are all `owner.Shared` in the pinned
//! deployment artifacts), and guessing an owned object's digest encoding would
//! risk producing a transaction Sui silently misreads, so an owned or receiving
//! object is refused instead.

use pillar_core::AppCoreError;

/// The upstream `MOCK_SENDER` used for every read-only `devInspect`
/// (TS: `packages/common-suimove/src/utils.ts:11-12`). `devInspect` runs Move
/// code that can branch on the sender, so this is copied verbatim rather than
/// approximated.
pub const SUI_DEV_INSPECT_MOCK_SENDER: &str =
    "0x1234567890123456789012345678901234567890123456789012345678901234";

/// A resolved shared object input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiSharedObject {
    pub object_id: [u8; 32],
    pub initial_shared_version: u64,
    /// `true` when the Move signature takes the object by `&mut` or by value.
    pub mutable: bool,
}

/// One `devInspect` transaction input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiCallArg {
    /// A BCS-encoded pure value (already serialized by the caller).
    Pure(Vec<u8>),
    Shared(SuiSharedObject),
}

/// A `MoveCall` argument reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiArgument {
    /// Index into the transaction's `inputs`.
    Input(u16),
    /// The single return value of an earlier command.
    Result(u16),
}

/// One `MoveCall` command. None of the payload-signed views take type
/// arguments, so the type-argument vector is always empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiMoveCall {
    pub package: [u8; 32],
    pub module: String,
    pub function: String,
    pub arguments: Vec<SuiArgument>,
}

fn write_uleb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_uleb128(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn write_call_arg(out: &mut Vec<u8>, arg: &SuiCallArg) {
    match arg {
        SuiCallArg::Pure(bytes) => {
            write_uleb128(out, 0); // CallArg::Pure
            write_uleb128(out, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        SuiCallArg::Shared(object) => {
            write_uleb128(out, 1); // CallArg::Object
            write_uleb128(out, 1); // ObjectArg::SharedObject
            out.extend_from_slice(&object.object_id);
            out.extend_from_slice(&object.initial_shared_version.to_le_bytes());
            out.push(u8::from(object.mutable));
        }
    }
}

fn write_argument(out: &mut Vec<u8>, argument: &SuiArgument) {
    match argument {
        SuiArgument::Input(index) => {
            write_uleb128(out, 1); // Argument::Input
            out.extend_from_slice(&index.to_le_bytes());
        }
        SuiArgument::Result(index) => {
            write_uleb128(out, 2); // Argument::Result
            out.extend_from_slice(&index.to_le_bytes());
        }
    }
}

/// Serialize a programmable transaction as a `TransactionKind`, the exact bytes
/// `tx.build({ onlyTransactionKind: true })` produces.
pub fn encode_sui_transaction_kind(inputs: &[SuiCallArg], commands: &[SuiMoveCall]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    write_uleb128(&mut out, 0); // TransactionKind::ProgrammableTransaction
    write_uleb128(&mut out, inputs.len() as u64);
    for input in inputs {
        write_call_arg(&mut out, input);
    }
    write_uleb128(&mut out, commands.len() as u64);
    for command in commands {
        write_uleb128(&mut out, 0); // Command::MoveCall
        out.extend_from_slice(&command.package);
        write_string(&mut out, &command.module);
        write_string(&mut out, &command.function);
        write_uleb128(&mut out, 0); // type_arguments: always empty here
        write_uleb128(&mut out, command.arguments.len() as u64);
        for argument in &command.arguments {
            write_argument(&mut out, argument);
        }
    }
    out
}

/// `tx.pure.address(value)`: a Sui address is 32 raw bytes.
pub fn sui_pure_address(address: &[u8; 32]) -> Vec<u8> {
    address.to_vec()
}

/// `tx.pure.u32(value)`: little-endian, 4 bytes.
pub fn sui_pure_u32(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// `tx.pure(bcs.vector(bcs.u8()).serialize(bytes))`: ULEB128 length then bytes.
pub fn sui_pure_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 2);
    write_uleb128(&mut out, bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}

/// Parse a `0x`-prefixed Sui object id or address into 32 bytes. Sui accepts
/// short forms such as `0x2`, which are left-padded.
pub fn sui_address_from_hex(value: &str) -> Result<[u8; 32], AppCoreError> {
    let body = value.strip_prefix("0x").unwrap_or(value);
    if body.is_empty() || body.len() > 64 {
        return Err(AppCoreError::Internal(format!(
            "invalid Sui address {value}"
        )));
    }
    let padded = format!("{body:0>64}");
    let bytes = hex::decode(&padded)
        .map_err(|error| AppCoreError::Internal(format!("invalid Sui address {value}: {error}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// The `UlnConfig` a `get_effective_*_uln_config` view returns.
///
/// BCS layout, from the pinned SDK schema: `confirmations: u64`,
/// `required_dvns: vector<address>`, `optional_dvns: vector<address>`,
/// `optional_dvn_threshold: u8`. Nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiUlnConfig {
    pub confirmations: u64,
    pub required_dvns: Vec<[u8; 32]>,
    pub optional_dvns: Vec<[u8; 32]>,
    pub optional_dvn_threshold: u8,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AppCoreError> {
        let end = self.offset.checked_add(len).ok_or_else(overrun)?;
        let slice = self.bytes.get(self.offset..end).ok_or_else(overrun)?;
        self.offset = end;
        Ok(slice)
    }

    fn uleb128(&mut self) -> Result<u64, AppCoreError> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *self.take(1)?.first().ok_or_else(overrun)?;
            result |= u64::from(byte & 0x7f)
                .checked_shl(shift)
                .ok_or_else(|| AppCoreError::Internal("Sui BCS ULEB overflow".to_string()))?;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    fn u64_le(&mut self) -> Result<u64, AppCoreError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| overrun())?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn address(&mut self) -> Result<[u8; 32], AppCoreError> {
        let bytes: [u8; 32] = self.take(32)?.try_into().map_err(|_| overrun())?;
        Ok(bytes)
    }

    fn address_vec(&mut self) -> Result<Vec<[u8; 32]>, AppCoreError> {
        let len = self.uleb128()? as usize;
        let mut out = Vec::with_capacity(len.min(64));
        for _ in 0..len {
            out.push(self.address()?);
        }
        Ok(out)
    }
}

fn overrun() -> AppCoreError {
    AppCoreError::Internal("Sui BCS value ended early".to_string())
}

/// `bcs.U8.parse(...)`: the `verifiable` view's verification state.
pub fn decode_sui_u8(bytes: &[u8]) -> Result<u8, AppCoreError> {
    match bytes {
        [value] => Ok(*value),
        _ => Err(AppCoreError::Internal(format!(
            "expected one BCS u8, got {} bytes",
            bytes.len()
        ))),
    }
}

/// `bcs.U64.parse(...)`: `get_confirmations`.
pub fn decode_sui_u64(bytes: &[u8]) -> Result<u64, AppCoreError> {
    let mut reader = Reader::new(bytes);
    let value = reader.u64_le()?;
    if reader.offset != bytes.len() {
        return Err(AppCoreError::Internal(
            "trailing bytes after BCS u64".to_string(),
        ));
    }
    Ok(value)
}

/// `bcs.toAddress(...)`: `get_messaging_channel`.
pub fn decode_sui_address(bytes: &[u8]) -> Result<[u8; 32], AppCoreError> {
    let mut reader = Reader::new(bytes);
    let value = reader.address()?;
    if reader.offset != bytes.len() {
        return Err(AppCoreError::Internal(
            "trailing bytes after BCS address".to_string(),
        ));
    }
    Ok(value)
}

/// Decode a `UlnConfig`.
pub fn decode_sui_uln_config(bytes: &[u8]) -> Result<SuiUlnConfig, AppCoreError> {
    let mut reader = Reader::new(bytes);
    let config = SuiUlnConfig {
        confirmations: reader.u64_le()?,
        required_dvns: reader.address_vec()?,
        optional_dvns: reader.address_vec()?,
        optional_dvn_threshold: *reader.take(1)?.first().ok_or_else(overrun)?,
    };
    if reader.offset != bytes.len() {
        return Err(AppCoreError::Internal(
            "trailing bytes after BCS UlnConfig".to_string(),
        ));
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Golden vector captured from Sui mainnet: the `TransactionKind` below was
    /// produced by [`encode_sui_transaction_kind`] and accepted by
    /// `sui_devInspectTransactionBlock`, which returned the `UlnConfig` bytes
    /// below for the Ethereum(30101) -> Sui receive config. This locks both the
    /// request encoding and the response layout against a real deployment
    /// rather than a hand-built fixture.
    ///
    /// `sui_getNormalizedMoveFunction` reports the ULN 302 parameter as
    /// `Reference`, i.e. immutable, which is why `mutable` is `false`.
    #[test]
    fn transaction_kind_and_uln_config_match_sui_mainnet() {
        const ULN_302_PACKAGE: &str =
            "0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0";
        const ULN_302_OBJECT: &str =
            "0x8ebd7a0b102a5f7a3d4a08d84dd853fecc4ae0093be6eb02cf0d11dce7d4861f";
        // `owner.Shared.initial_shared_version` observed via
        // `sui_multiGetObjects`, matching the pinned deployment artifact.
        const INITIAL_SHARED_VERSION: u64 = 635_685_319;
        const TX_KIND_HEX: &str = "000301018ebd7a0b102a5f7a3d4a08d84dd853fecc4ae0093be6eb02cf0d11dce7d4861fc7c9e32500000000000020000000000000000000000000000000000000000000000000000000000000000000049575000001003ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb007756c6e5f333032206765745f6566666563746976655f726563656976655f756c6e5f636f6e6669670003010000010100010200";
        const ULN_CONFIG_HEX: &str = "0f00000000000000040c12321ebe562b8fb8a74e6d29f144ea199a8f31a4cea3a417ce72477f6dfebb52aa129049de845353484868d1be6e2df6878b0ed2213d94d3c827309aeae68592128a5edf4a0f696464de66d00986ef41b37faf705ceb3d9d9a4e5c306fbf91fa35508c624925c6f341113f8f9397e5f41750b833af87d0c945a6f5682887f00000";

        let encoded = encode_sui_transaction_kind(
            &[
                SuiCallArg::Shared(SuiSharedObject {
                    object_id: sui_address_from_hex(ULN_302_OBJECT).unwrap(),
                    initial_shared_version: INITIAL_SHARED_VERSION,
                    mutable: false,
                }),
                SuiCallArg::Pure(sui_pure_address(&[0u8; 32])),
                SuiCallArg::Pure(sui_pure_u32(30_101)),
            ],
            &[SuiMoveCall {
                package: sui_address_from_hex(ULN_302_PACKAGE).unwrap(),
                module: "uln_302".to_string(),
                function: "get_effective_receive_uln_config".to_string(),
                arguments: vec![
                    SuiArgument::Input(0),
                    SuiArgument::Input(1),
                    SuiArgument::Input(2),
                ],
            }],
        );
        assert_eq!(hex::encode(&encoded), TX_KIND_HEX);

        let config = decode_sui_uln_config(&hex::decode(ULN_CONFIG_HEX).unwrap()).unwrap();
        assert_eq!(config.confirmations, 15);
        assert_eq!(config.required_dvns.len(), 4);
        assert!(config.optional_dvns.is_empty());
        assert_eq!(config.optional_dvn_threshold, 0);
        assert_eq!(
            hex::encode(config.required_dvns[0]),
            "0c12321ebe562b8fb8a74e6d29f144ea199a8f31a4cea3a417ce72477f6dfebb"
        );
    }

    #[test]
    fn encodes_a_single_move_call_with_shared_and_pure_inputs() {
        let bytes = encode_sui_transaction_kind(
            &[
                SuiCallArg::Shared(SuiSharedObject {
                    object_id: id(0xaa),
                    initial_shared_version: 13,
                    mutable: false,
                }),
                SuiCallArg::Pure(sui_pure_u32(30_101)),
            ],
            &[SuiMoveCall {
                package: id(0xbb),
                module: "uln_302".to_string(),
                function: "verifiable".to_string(),
                arguments: vec![SuiArgument::Input(0), SuiArgument::Input(1)],
            }],
        );

        let mut expected = Vec::new();
        expected.push(0); // TransactionKind::ProgrammableTransaction
        expected.push(2); // 2 inputs
        expected.extend_from_slice(&[1, 1]); // CallArg::Object, ObjectArg::SharedObject
        expected.extend_from_slice(&id(0xaa));
        expected.extend_from_slice(&13u64.to_le_bytes());
        expected.push(0); // mutable = false
        expected.push(0); // CallArg::Pure
        expected.push(4); // 4 bytes
        expected.extend_from_slice(&30_101u32.to_le_bytes());
        expected.push(1); // 1 command
        expected.push(0); // Command::MoveCall
        expected.extend_from_slice(&id(0xbb));
        expected.push(7);
        expected.extend_from_slice(b"uln_302");
        expected.push(10);
        expected.extend_from_slice(b"verifiable");
        expected.push(0); // no type arguments
        expected.push(2); // 2 arguments
        expected.extend_from_slice(&[1, 0, 0]); // Input(0)
        expected.extend_from_slice(&[1, 1, 0]); // Input(1)

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encodes_command_results_as_arguments() {
        // `get_confirmations` refers to the two preceding `bytes32::from_bytes`
        // commands by result index.
        let bytes = encode_sui_transaction_kind(
            &[],
            &[SuiMoveCall {
                package: id(0x01),
                module: "uln_302".to_string(),
                function: "get_confirmations".to_string(),
                arguments: vec![SuiArgument::Result(0), SuiArgument::Result(1)],
            }],
        );
        let tail = &bytes[bytes.len() - 6..];
        assert_eq!(tail, &[2, 0, 0, 2, 1, 0]);
    }

    #[test]
    fn pure_encoders_match_the_sdk() {
        assert_eq!(sui_pure_u32(1), vec![1, 0, 0, 0]);
        assert_eq!(sui_pure_address(&id(0x07)).len(), 32);
        // A 32-byte hash becomes a `vector<u8>`: 0x20 length prefix then bytes.
        let hash = sui_pure_bytes(&id(0x09));
        assert_eq!(hash[0], 0x20);
        assert_eq!(hash.len(), 33);
        // ULEB128 spills into a second byte past 127.
        assert_eq!(sui_pure_bytes(&[0u8; 128])[..2], [0x80, 0x01]);
    }

    /// `devInspect` executes Move code that may branch on the sender, so the
    /// mock sender must stay byte-identical to upstream's `MOCK_SENDER`.
    #[test]
    fn mock_sender_matches_upstream_constant() {
        assert_eq!(
            SUI_DEV_INSPECT_MOCK_SENDER,
            "0x1234567890123456789012345678901234567890123456789012345678901234"
        );
        let bytes = sui_address_from_hex(SUI_DEV_INSPECT_MOCK_SENDER).unwrap();
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[1], 0x34);
        assert_eq!(bytes[31], 0x34);
    }

    #[test]
    fn parses_short_and_full_sui_addresses() {
        assert_eq!(sui_address_from_hex("0x2").unwrap()[31], 2);
        assert_eq!(sui_address_from_hex("0x2").unwrap()[0], 0);
        let full = "0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0";
        assert_eq!(sui_address_from_hex(full).unwrap()[0], 0x3c);
        assert!(sui_address_from_hex("0x").is_err());
        assert!(sui_address_from_hex(&format!("0x{}", "0".repeat(65))).is_err());
    }

    #[test]
    fn decodes_uln_config_in_schema_order() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&15u64.to_le_bytes());
        bytes.push(1); // one required DVN
        bytes.extend_from_slice(&id(0xaa));
        bytes.push(2); // two optional DVNs
        bytes.extend_from_slice(&id(0xbb));
        bytes.extend_from_slice(&id(0xcc));
        bytes.push(1); // threshold

        let config = decode_sui_uln_config(&bytes).unwrap();
        assert_eq!(config.confirmations, 15);
        assert_eq!(config.required_dvns, vec![id(0xaa)]);
        assert_eq!(config.optional_dvns, vec![id(0xbb), id(0xcc)]);
        assert_eq!(config.optional_dvn_threshold, 1);
    }

    #[test]
    fn rejects_truncated_and_overlong_values() {
        assert!(decode_sui_u64(&[0u8; 7]).is_err());
        assert!(decode_sui_u64(&[0u8; 9]).is_err());
        assert!(decode_sui_u8(&[]).is_err());
        assert!(decode_sui_u8(&[1, 2]).is_err());
        assert!(decode_sui_address(&[0u8; 31]).is_err());
        assert!(decode_sui_uln_config(&[0u8; 8]).is_err());
    }

    #[test]
    fn decodes_u64_little_endian() {
        assert_eq!(decode_sui_u64(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap(), 1);
        assert_eq!(
            decode_sui_u64(&[0, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
            1u64 << 56
        );
    }
}
