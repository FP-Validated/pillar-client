//! Upstream's `extractOptionsFromLZSentEvent` for EndpointV2 `PacketSent` options
//! (`lz-v2-sdk/src/endpoint/evm/decoders/index.ts:96-142`) over lz-v2-utilities 3.0.168
//! `Options.fromOptions` and its decoders. Every throw there is an `Err` here: upstream's
//! `getLZSentEvent` swallows it and skips the packet, so an undecodable options field makes a
//! send unresolvable.

use num_bigint::BigUint;
use serde_json::{json, Map, Value};

type Options = Vec<(u64, Vec<(u64, Vec<u8>)>)>;

/// JavaScript `Uint8Array.prototype.slice` with integer bounds.
fn js_slice(bytes: &[u8], start: i64, end: i64) -> &[u8] {
    let clamp = |index: i64| index.clamp(0, bytes.len() as i64) as usize;
    let (start, end) = (clamp(start), clamp(end));
    if end <= start {
        &[]
    } else {
        &bytes[start..end]
    }
}

/// ethers `BigNumber.from(bytes)`: empty bytes hexlify to `0x`, which it refuses.
fn big(bytes: &[u8]) -> Result<BigUint, String> {
    if bytes.is_empty() {
        Err("invalid BigNumber string (argument=\"value\", value=\"0x\", code=INVALID_ARGUMENT, version=bignumber/5.8.0)".to_string())
    } else {
        Ok(BigUint::from_bytes_be(bytes))
    }
}

fn number(bytes: &[u8]) -> Result<u64, String> {
    big(bytes)?.try_into().map_err(|_| "overflow".to_string())
}

fn add_option(options: &mut Options, worker_id: u64, option_type: u64, params: Vec<u8>) {
    match options.iter_mut().find(|(id, _)| *id == worker_id) {
        Some((_, list)) => list.push((option_type, params)),
        None => options.push((worker_id, vec![(option_type, params)])),
    }
}

fn u128_bytes(value: &BigUint, name: &str) -> Result<Vec<u8>, String> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 16 {
        return Err(format!(
            "Invariant failed: {name} shouldn't be greater than MAX_UINT_128"
        ));
    }
    let mut out = vec![0u8; 16 - bytes.len()];
    out.extend(bytes);
    Ok(out)
}

/// `Options.fromOptions`.
fn from_options(bytes: &[u8]) -> Result<Options, String> {
    let mut options = Options::new();
    let len = bytes.len() as i64;
    match number(js_slice(bytes, 0, 2))? {
        3 => {
            let mut cursor: i64 = 2;
            while cursor < len {
                let worker_id = number(js_slice(bytes, cursor, cursor + 1))?;
                cursor += 1;
                let size = number(js_slice(bytes, cursor, cursor + 2))? as i64;
                cursor += 2;
                if worker_id == 1 {
                    let option_type = number(js_slice(bytes, cursor, cursor + 1))?;
                    cursor += 1;
                    let params = js_slice(bytes, cursor, cursor + size - 1).to_vec();
                    cursor += size - 1;
                    add_option(&mut options, 1, option_type, params);
                } else if worker_id == 2 {
                    number(js_slice(bytes, cursor, cursor + 1))?;
                    cursor += 1;
                    let option_type = number(js_slice(bytes, cursor, cursor + 1))?;
                    cursor += 1;
                    let params = js_slice(bytes, cursor, cursor + size - 2).to_vec();
                    cursor += size - 2;
                    add_option(&mut options, 2, option_type, params);
                }
            }
        }
        2 => {
            let gas = big(js_slice(bytes, 2, 34))?;
            let amount = big(js_slice(bytes, 34, 66))?;
            let receiver = js_slice(bytes, 66, len);
            add_option(&mut options, 1, 1, u128_bytes(&gas, "gasLimit")?);
            // `addressToBytes32` takes a `0x` hex string of at most 32 bytes.
            if receiver.len() > 32 {
                return Err("Invalid address".to_string());
            }
            let mut params = u128_bytes(&amount, "nativeDrop")?;
            params.extend(std::iter::repeat_n(0, 32 - receiver.len()));
            params.extend_from_slice(receiver);
            add_option(&mut options, 1, 2, params);
        }
        1 => {
            let gas = big(js_slice(bytes, 2, 34))?;
            add_option(&mut options, 1, 1, u128_bytes(&gas, "gasLimit")?);
        }
        _ => {}
    }
    Ok(options)
}

fn executor_options(options: &Options, option_type: u64) -> Vec<&[u8]> {
    options
        .iter()
        .find(|(id, _)| *id == 1)
        .map(|(_, list)| {
            list.iter()
                .filter(|(kind, _)| *kind == option_type)
                .map(|(_, params)| params.as_slice())
                .collect()
        })
        .unwrap_or_default()
}

/// `getAddressEncodedByChain` over a native drop receiver of at most 32 bytes.
pub(crate) fn native_drop_receiver(dst_chain_name: &str, receiver: &[u8]) -> String {
    match dst_chain_name {
        "solana" => bs58::encode(receiver).into_string(),
        "aptos" | "movement" | "initia" | "ton" | "sui" | "iotal1" | "starknet" | "stellar"
        | "canton" => format!("0x{:0>64}", hex::encode(receiver)),
        _ => {
            let padded = format!("{:0>64}", hex::encode(receiver));
            format!("0x{}", &padded[24..])
        }
    }
}

/// `StaticChainConfigs.getAddressSizeInBytes`: every upstream non-EVM chain is 32 bytes
/// (`static-config/src/staticConfigs.ts:243-371`), anything else EVM's 20.
pub(crate) fn destination_address_size(chain_name: &str) -> usize {
    match chain_name {
        "solana" | "aptos" | "movement" | "initia" | "ton" | "sui" | "iotal1" | "starknet"
        | "stellar" | "canton" => 32,
        _ => 20,
    }
}

/// Decodes `options` as upstream's EVM extractor does into its relayer options.
pub(crate) fn decode_evm_relayer_options(
    options: &[u8],
    dst_chain_name: &str,
) -> Result<Value, String> {
    decode_relayer_options(options, dst_chain_name, true)
}

/// Upstream's Aptos-family extractor (`lz-v2-sdk/src/endpoint/aptos/decoders/index.ts:56-102`):
/// the same decoding without the read option.
pub(crate) fn decode_move_relayer_options(
    options: &[u8],
    dst_chain_name: &str,
) -> Result<Value, String> {
    decode_relayer_options(options, dst_chain_name, false)
}

fn decode_relayer_options(
    options: &[u8],
    dst_chain_name: &str,
    with_read: bool,
) -> Result<Value, String> {
    let options = from_options(options)?;

    let receive = executor_options(&options, 1);
    let lz_receive = if receive.is_empty() {
        None
    } else {
        let (mut gas, mut value) = (BigUint::default(), BigUint::default());
        for params in receive {
            gas += big(js_slice(params, 0, 16))?;
            if params.len() != 16 {
                value += big(js_slice(params, 16, 32))?;
            }
        }
        Some((gas, value))
    };

    let mut drops: Vec<(Vec<u8>, BigUint)> = Vec::new();
    for params in executor_options(&options, 2) {
        let amount = big(js_slice(params, 0, 16))?;
        let receiver = js_slice(params, 16, 48).to_vec();
        match drops.iter_mut().find(|(known, _)| *known == receiver) {
            Some((_, total)) => *total += amount,
            None => drops.push((receiver, amount)),
        }
    }

    // Upstream groups compose options in an object keyed by index, which iterates ascending.
    let mut composes: std::collections::BTreeMap<u64, (BigUint, BigUint)> = Default::default();
    for params in executor_options(&options, 3) {
        let index = number(js_slice(params, 0, 2))?;
        let gas = big(js_slice(params, 2, 18))?;
        let value = if params.len() == 34 {
            big(js_slice(params, 18, 34))?
        } else {
            BigUint::default()
        };
        let entry = composes.entry(index).or_default();
        entry.0 += gas;
        entry.1 += value;
    }

    let ordered = !executor_options(&options, 4).is_empty();

    let read = if with_read {
        executor_options(&options, 5)
    } else {
        Vec::new()
    };
    let lz_read = if read.is_empty() {
        None
    } else {
        let (mut gas, mut size, mut value) =
            (BigUint::default(), BigUint::default(), BigUint::default());
        for params in read {
            gas += big(js_slice(params, 0, 16))?;
            size += big(js_slice(params, 16, 20))?;
            if params.len() != 20 {
                value += big(js_slice(params, 20, 36))?;
            }
        }
        Some((gas, size, value))
    };
    if lz_read.is_some() && lz_receive.is_some() {
        return Err("Cannot have both lzRead and lzReceive options in the same packet".to_string());
    }

    let mut out = Map::new();
    match (lz_read, lz_receive) {
        (Some((gas, size, value)), _) => {
            out.insert(
                "lzReceive".to_string(),
                json!({"gas": gas.to_string(), "value": value.to_string(), "dataSize": size.to_string()}),
            );
        }
        (None, Some((gas, value))) => {
            out.insert(
                "lzReceive".to_string(),
                json!({"gas": gas.to_string(), "value": value.to_string()}),
            );
        }
        (None, None) => {}
    }
    out.insert("ordered".to_string(), Value::Bool(ordered));
    if !drops.is_empty() {
        out.insert(
            "nativeDrop".to_string(),
            drops
                .into_iter()
                .map(|(receiver, amount)| {
                    json!({"amount": amount.to_string(), "receiver": native_drop_receiver(dst_chain_name, &receiver)})
                })
                .collect(),
        );
    }
    if !composes.is_empty() {
        out.insert(
            "compose".to_string(),
            composes
                .into_iter()
                .map(|(index, (gas, value))| {
                    json!({"index": index, "gas": gas.to_string(), "value": value.to_string()})
                })
                .collect(),
        );
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solana_options_ignore_read_option_like_upstream() {
        let mut bytes = vec![0, 3, 1, 0, 21, 5];
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&[0, 0, 0, 8]);
        let decoded = decode_move_relayer_options(&bytes, "ethereum").unwrap();
        assert_eq!(decoded, json!({"ordered": false}));
        assert!(
            decode_evm_relayer_options(&bytes, "ethereum").unwrap()["lzReceive"]["dataSize"]
                .is_string()
        );
    }
}
