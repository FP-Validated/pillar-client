use indexmap::IndexMap;
use num_bigint::BigUint;
use pillar_core::AppCoreError;
use serde_json::{json, Map, Value};
use ton_core::cell::TonCell;

use super::cell::map_err;
use super::cl_declare::{cell_name, cl_get_uint_be};

#[derive(Default)]
struct DecodedOptions {
    lz_receive_gas: BigUint,
    lz_receive_value: BigUint,
    lz_compose_gas: BigUint,
    lz_compose_value: BigUint,
    native_drop_address: BigUint,
    native_drop_amount: BigUint,
}

/// Decode and merge LayerZero TON `md::OptionsV1`/`md::OptionsV2` cells into
/// `RelayerOptions` JSON shape consumed by upstream extra-context hooks.
pub fn decode_ton_relayer_options(
    extra_options: &TonCell,
    enforced_options: &TonCell,
    dst_chain_name: &str,
) -> Result<Value, AppCoreError> {
    let extra = decode_options(extra_options)?;
    let enforced = decode_options(enforced_options)?;
    let mut relayer_options = Map::new();

    let lz_receive_gas = &extra.lz_receive_gas + &enforced.lz_receive_gas;
    if lz_receive_gas != BigUint::default() {
        relayer_options.insert(
            "lzReceive".to_string(),
            json!({
                "gas": lz_receive_gas.to_string(),
                "value": (&extra.lz_receive_value + &enforced.lz_receive_value).to_string(),
            }),
        );
    }

    let lz_compose_gas = &extra.lz_compose_gas + &enforced.lz_compose_gas;
    if lz_compose_gas != BigUint::default() {
        relayer_options.insert(
            "compose".to_string(),
            json!([{
                "index": 0,
                "gas": lz_compose_gas.to_string(),
                "value": (&extra.lz_compose_value + &enforced.lz_compose_value).to_string(),
            }]),
        );
    }

    let mut native_drops = IndexMap::<String, BigUint>::new();
    for options in [&extra, &enforced] {
        if options.native_drop_address != BigUint::default()
            && options.native_drop_amount != BigUint::default()
        {
            let receiver = encode_address_by_chain(
                dst_chain_name,
                left_pad_32(options.native_drop_address.to_bytes_be())?,
            );
            *native_drops.entry(receiver).or_default() += &options.native_drop_amount;
        }
    }
    if !native_drops.is_empty() {
        relayer_options.insert(
            "nativeDrop".to_string(),
            Value::Array(
                native_drops
                    .into_iter()
                    .map(|(receiver, amount)| {
                        json!({"receiver": receiver, "amount": amount.to_string()})
                    })
                    .collect(),
            ),
        );
    }

    relayer_options.insert("ordered".to_string(), Value::Bool(false));
    Ok(Value::Object(relayer_options))
}

fn decode_options(cell: &TonCell) -> Result<DecodedOptions, AppCoreError> {
    let mut parser = cell.parser();
    if parser.data_bits_left().map_err(map_err)? == 0 {
        return Ok(DecodedOptions::default());
    }

    let read_uint =
        |index| cl_get_uint_be(cell, index, 256).map(|bytes| BigUint::from_bytes_be(&bytes));
    match cell_name(cell)?.as_str() {
        "OptionsV1" => Ok(DecodedOptions {
            lz_receive_gas: read_uint(0)?,
            lz_receive_value: read_uint(1)?,
            native_drop_address: read_uint(2)?,
            native_drop_amount: read_uint(3)?,
            ..DecodedOptions::default()
        }),
        "OptionsV2" => Ok(DecodedOptions {
            lz_receive_gas: read_uint(0)?,
            lz_receive_value: read_uint(1)?,
            lz_compose_gas: read_uint(2)?,
            lz_compose_value: read_uint(3)?,
            native_drop_address: read_uint(4)?,
            native_drop_amount: read_uint(5)?,
        }),
        name => Err(AppCoreError::Internal(format!(
            "Unknown TON options cell {name}"
        ))),
    }
}

fn left_pad_32(bytes: Vec<u8>) -> Result<[u8; 32], AppCoreError> {
    if bytes.len() > 32 {
        return Err(AppCoreError::Internal(
            "TON native-drop address exceeds 32 bytes".to_string(),
        ));
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(padded)
}

fn encode_address_by_chain(chain_name: &str, address: [u8; 32]) -> String {
    if chain_name == "solana" {
        return bs58::encode(address).into_string();
    }
    if matches!(
        chain_name,
        "aptos" | "movement" | "initia" | "ton" | "sui" | "iotal1" | "starknet" | "stellar"
    ) {
        return format!("0x{}", hex::encode(address));
    }
    format!("0x{}", hex::encode(&address[12..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::other_non_evm::ton::cl_declare::{cl_declare, ClField, T_UINT256};

    fn options_v1(gas: u64, value: u64, receiver: u64, amount: u64) -> TonCell {
        cl_declare(
            "OptionsV1",
            vec![
                ClField::uint(T_UINT256, gas),
                ClField::uint(T_UINT256, value),
                ClField::uint(T_UINT256, receiver),
                ClField::uint(T_UINT256, amount),
            ],
        )
        .unwrap()
    }

    #[test]
    fn ton_options_parity_merges_extra_and_enforced_v1() {
        let decoded = decode_ton_relayer_options(
            &options_v1(10, 2, 0x11, 6),
            &options_v1(5, 4, 0x11, 9),
            "ton",
        )
        .unwrap();

        assert_eq!(
            decoded,
            json!({
                "lzReceive": {"gas": "15", "value": "6"},
                "nativeDrop": [{
                    "receiver": format!("0x{}11", "00".repeat(31)),
                    "amount": "15"
                }],
                "ordered": false
            })
        );
    }

    #[test]
    fn ton_options_parity_empty_and_malformed_boundaries() {
        assert_eq!(
            decode_ton_relayer_options(TonCell::empty(), TonCell::empty(), "ton").unwrap(),
            json!({"ordered": false})
        );
        let malformed = cl_declare(
            "Unknown",
            vec![
                ClField::uint(T_UINT256, 1u64),
                ClField::uint(T_UINT256, 0u64),
            ],
        )
        .unwrap();
        assert_eq!(
            decode_ton_relayer_options(&malformed, TonCell::empty(), "ton")
                .unwrap_err()
                .to_string(),
            "Unknown TON options cell Unknown"
        );
    }

    #[test]
    fn ton_options_parity_encodes_native_drop_for_destination_chain() {
        let extra = options_v1(0, 0, 0x11, 6);
        let empty = TonCell::empty();

        assert_eq!(
            decode_ton_relayer_options(&extra, empty, "ethereum")
                .unwrap()
                .pointer("/nativeDrop/0/receiver"),
            Some(&Value::from(format!("0x{}11", "00".repeat(19))))
        );
        assert_eq!(
            decode_ton_relayer_options(&extra, empty, "solana")
                .unwrap()
                .pointer("/nativeDrop/0/receiver"),
            Some(&Value::from(
                bs58::encode(left_pad_32(vec![0x11]).unwrap()).into_string()
            ))
        );
    }
}
