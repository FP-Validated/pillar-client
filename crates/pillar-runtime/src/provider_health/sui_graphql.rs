use serde_json::{json, Value};

pub(super) fn request(body: &Value) -> Option<(String, Value)> {
    let method = body.get("method")?.as_str()?;
    let params = body.get("params").and_then(Value::as_array)?;
    let request = match method {
        "suix_queryEvents" => {
            let digest = params.first()?.get("Transaction")?.as_str()?;
            (
                "query($digest: String!) { transaction(digest: $digest) { effects { events(last: 50) { nodes { contents { type { repr } json } } pageInfo { hasNextPage } } } } }".to_string(),
                json!({"digest": digest}),
                method,
            )
        }
        "sui_getTransactionBlock" => {
            let digest = params.first()?.as_str()?;
            (
                "query($digest: String!) { transaction(digest: $digest) { digest sender { address } transactionBcs effects { checkpoint { sequenceNumber } status } } }".to_string(),
                json!({"digest": digest}),
                method,
            )
        }
        "sui_getLatestCheckpointSequenceNumber" => (
            "query { checkpoints(last: 1) { nodes { sequenceNumber } } }".to_string(),
            json!({}),
            method,
        ),
        "sui_getCheckpoint" => {
            let sequence = params.first()?;
            let sequence = sequence
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| sequence.as_u64())?;
            (
                "query($sequence: UInt53) { checkpoint(sequenceNumber: $sequence) { timestamp } }"
                    .to_string(),
                json!({"sequence": sequence}),
                method,
            )
        }
        "sui_getNormalizedMoveFunction" => {
            let package = params.first()?.as_str()?;
            let module = params.get(1)?.as_str()?;
            let function = params.get(2)?.as_str()?;
            (
                "query($package: SuiAddress!, $module: String!, $function: String!) { package(address: $package) { module(name: $module) { function(name: $function) { parameters { repr } } } } }".to_string(),
                json!({"package": package, "module": module, "function": function}),
                method,
            )
        }
        "sui_multiGetObjects" => {
            let ids = params.first()?.as_array()?;
            let address = ids.first()?.as_str()?;
            (
                "query($address: SuiAddress!) { object(address: $address) { asMoveObject { owner { __typename ... on Shared { initialSharedVersion } } } } }".to_string(),
                json!({"address": address}),
                method,
            )
        }
        _ => return None,
    };
    Some((
        request.2.to_string(),
        json!({"query": request.0, "variables": request.1}),
    ))
}

fn error_response(message: &str) -> Value {
    json!({"jsonrpc":"2.0", "id":1, "error":{"code":-32000,"message":message}})
}

pub(super) fn response(method: &str, graphql: Value) -> Value {
    if let Some(error) = graphql.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Sui provider returned a JSON-RPC error");
        return error_response(message);
    }
    if let Some(errors) = graphql.get("errors") {
        let message = errors
            .as_array()
            .and_then(|errors| errors.first())
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("Sui GraphQL request failed");
        return error_response(message);
    }
    let Some(data) = graphql.get("data").filter(|data| data.is_object()) else {
        return error_response("Sui GraphQL response has no data object");
    };
    let result = match method {
        "suix_queryEvents" => {
            let Some(events) = data
                .pointer("/transaction/effects/events/nodes")
                .and_then(Value::as_array)
            else {
                return error_response("Sui GraphQL response has no event page");
            };
            let Some(has_next_page) = data
                .pointer("/transaction/effects/events/pageInfo/hasNextPage")
                .and_then(Value::as_bool)
            else {
                return error_response("Sui GraphQL event page has no pagination state");
            };
            if has_next_page {
                return error_response("Sui GraphQL event page is truncated");
            }
            let Some(mapped) = events
                .iter()
                .map(|event| {
                    let event_type = event.pointer("/contents/type/repr")?.as_str()?;
                    let mut parsed = event.pointer("/contents/json")?.clone();
                    normalize_graphql_event_json(event_type, &mut parsed)
                        .then(|| json!({"type":event_type,"parsedJson":parsed}))
                })
                .collect::<Option<Vec<_>>>()
            else {
                return error_response("Sui GraphQL event contents are malformed");
            };
            json!({"data": mapped, "hasNextPage": false, "nextCursor": null})
        }
        "sui_getTransactionBlock" => {
            let Some(tx) = data.get("transaction").filter(|tx| tx.is_object()) else {
                return error_response("Sui GraphQL transaction is missing");
            };
            let Some(digest) = tx.get("digest").and_then(Value::as_str) else {
                return error_response("Sui GraphQL transaction digest is missing");
            };
            let Some(sender) = tx.pointer("/sender/address").and_then(Value::as_str) else {
                return error_response("Sui GraphQL transaction sender is missing");
            };
            let Some(checkpoint) = tx.pointer("/effects/checkpoint/sequenceNumber") else {
                return error_response("Sui GraphQL transaction checkpoint is missing");
            };
            let Some(status) = tx.pointer("/effects/status").and_then(Value::as_str) else {
                return error_response("Sui GraphQL transaction status is missing");
            };
            let Some(transaction_bcs) = tx.get("transactionBcs").and_then(Value::as_str) else {
                return error_response("Sui GraphQL transaction BCS is missing");
            };
            json!({
                "digest": digest,
                "checkpoint": checkpoint,
                "sender": sender,
                "transaction": {"data":{"sender":sender,"transaction":transaction_bcs}},
                "effects": {"status": {"status": status.to_ascii_lowercase()}}
            })
        }
        "sui_getLatestCheckpointSequenceNumber" => {
            let Some(sequence) = data.pointer("/checkpoints/nodes/0/sequenceNumber") else {
                return error_response("Sui GraphQL latest checkpoint is missing");
            };
            if sequence.as_u64().is_none()
                && sequence
                    .as_str()
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_none()
            {
                return error_response("Sui GraphQL latest checkpoint sequence is invalid");
            }
            sequence.clone()
        }
        "sui_getCheckpoint" => {
            let Some(timestamp) = data
                .pointer("/checkpoint/timestamp")
                .and_then(Value::as_str)
                .and_then(timestamp_millis)
            else {
                return error_response("Sui GraphQL checkpoint timestamp is invalid");
            };
            json!({"timestampMs": timestamp})
        }
        "sui_getNormalizedMoveFunction" => {
            let Some(parameters) = data
                .pointer("/package/module/function/parameters")
                .and_then(Value::as_array)
            else {
                return error_response("Sui GraphQL normalized Move function is missing");
            };
            let Some(parameters) = parameters
                .iter()
                .map(|parameter| {
                    let repr = parameter.get("repr")?.as_str()?;
                    Some(if repr.starts_with('&') && !repr.starts_with("&mut ") {
                        json!({"Reference":repr})
                    } else {
                        json!({"MutableReference":repr})
                    })
                })
                .collect::<Option<Vec<_>>>()
            else {
                return error_response("Sui GraphQL normalized Move parameters are malformed");
            };
            json!({"parameters":parameters})
        }
        "sui_multiGetObjects" => {
            let Some(object) = data.get("object").filter(|object| object.is_object()) else {
                return error_response("Sui GraphQL object is missing");
            };
            let Some(owner) = object
                .pointer("/asMoveObject/owner")
                .filter(|owner| owner.is_object())
            else {
                return error_response("Sui GraphQL object owner is missing");
            };
            let shared = if owner.get("__typename").and_then(Value::as_str) == Some("Shared") {
                let Some(version) = owner.get("initialSharedVersion").filter(|value| {
                    value.as_u64().is_some()
                        || value
                            .as_str()
                            .and_then(|text| text.parse::<u64>().ok())
                            .is_some()
                }) else {
                    return error_response("Sui GraphQL shared-object version is invalid");
                };
                json!({"initial_shared_version":version})
            } else {
                Value::Null
            };
            json!([{"data":{"owner":{"Shared":shared}}}])
        }
        _ => return error_response("Unsupported Sui GraphQL response method"),
    };
    json!({"jsonrpc":"2.0", "id":1, "result":result})
}

fn timestamp_millis(value: &str) -> Option<i64> {
    let (date, time) = value.split_once('T')?;
    let time = time.strip_suffix('Z')?;
    let mut date_parts = date.split('-');
    let year_text = date_parts.next()?;
    let month_text = date_parts.next()?;
    let day_text = date_parts.next()?;
    if date_parts.next().is_some()
        || year_text.len() != 4
        || month_text.len() != 2
        || day_text.len() != 2
        || !year_text.bytes().all(|byte| byte.is_ascii_digit())
        || !month_text.bytes().all(|byte| byte.is_ascii_digit())
        || !day_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let year = year_text.parse::<i64>().ok()?;
    let month = month_text.parse::<i64>().ok()?;
    let day = day_text.parse::<i64>().ok()?;
    if year == 0 || !(1..=12).contains(&month) {
        return None;
    }
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days_in_month).contains(&day) {
        return None;
    }
    let (clock, fraction) = time
        .split_once('.')
        .map_or((time, None), |(clock, fraction)| (clock, Some(fraction)));
    let mut clock_parts = clock.split(':');
    let hour_text = clock_parts.next()?;
    let minute_text = clock_parts.next()?;
    let second_text = clock_parts.next()?;
    if clock_parts.next().is_some()
        || [hour_text, minute_text, second_text]
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let hour = hour_text.parse::<i64>().ok()?;
    let minute = minute_text.parse::<i64>().ok()?;
    let second = second_text.parse::<i64>().ok()?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let millis = match fraction {
        None => 0,
        Some(fraction)
            if !fraction.is_empty()
                && fraction.len() <= 9
                && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let digits = &fraction[..fraction.len().min(3)];
            digits.parse::<i64>().ok()?
                * 10_i64.checked_pow(3_u32.saturating_sub(digits.len() as u32))?
        }
        Some(_) => return None,
    };
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(
        (((era * 146_097 + day_of_era - 719_468) * 24 + hour) * 60 + minute) * 60 * 1000
            + second * 1000
            + millis,
    )
}

fn normalize_graphql_event_json(event_type: &str, parsed: &mut Value) -> bool {
    if !event_type.ends_with("::messaging_channel::PacketSentEvent") {
        return true;
    }
    if parsed.is_null() {
        return true;
    }
    let Some(object) = parsed.as_object_mut() else {
        return false;
    };
    for field in ["encoded_packet", "options"] {
        let Some(encoded) = object.get(field).and_then(Value::as_str) else {
            continue;
        };
        if encoded.starts_with("0x")
            || (field == "options"
                && !encoded.is_empty()
                && encoded.len() % 2 == 0
                && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            continue;
        }
        use base64::Engine;
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return false;
        };
        object.insert(
            field.to_string(),
            Value::Array(bytes.into_iter().map(Value::from).collect()),
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    const CAPTURE: &str = include_str!(
        "../../tests/gasolina_parity/transport/sui-mainnet-graphql-source-transaction.json"
    );

    #[test]
    fn captured_packet_uses_trusted_emitter_and_decodes() {
        let capture: Value = serde_json::from_str(CAPTURE).unwrap();
        let mapped = response("suix_queryEvents", capture["response"].clone());
        let events = crate::layerzero_runtime::decode_sui_packet_sent_events(
            &mapped,
            &HashSet::from([
                "0x31beaef889b08b9c3b37d19280fc1f8b75bae5b2de2410fc3120f403e9a36dac".to_string(),
            ]),
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.src_eid, 30_378);
        assert_eq!(
            capture["provenance"]["digest"],
            "FxnUDMSUMt6wpDB7g7vhvxBEpvVVchvS7oUuDtnMAUw2"
        );
    }

    #[test]
    fn event_query_is_paginated_and_transaction_mapping_keeps_bcs() {
        let (_, query) =
            request(&json!({"method":"suix_queryEvents","params":[{"Transaction":"tx"}]})).unwrap();
        assert!(query["query"]
            .as_str()
            .unwrap()
            .contains("events(last: 50)"));
        assert!(query["query"]
            .as_str()
            .unwrap()
            .contains("pageInfo { hasNextPage }"));
        let mapped = response(
            "sui_getTransactionBlock",
            json!({"data":{"transaction":{"digest":"d","transactionBcs":"AQI=","sender":{"address":"0xs"},"effects":{"checkpoint":{"sequenceNumber":12},"status":"SUCCESS"}}}}),
        );
        assert_eq!(
            mapped["result"]["transaction"]["data"]["transaction"],
            "AQI="
        );
        assert_eq!(mapped["result"]["checkpoint"], 12);
        assert!(request(&json!({"method":"sui_devInspectTransactionBlock","params":[]})).is_none());
    }

    #[test]
    fn required_graphql_data_and_full_event_page_fail_closed() {
        for (method, raw) in [
            (
                "sui_getLatestCheckpointSequenceNumber",
                json!({"data":null}),
            ),
            (
                "sui_getLatestCheckpointSequenceNumber",
                json!({"data":{"checkpoints":{"nodes":[]}}}),
            ),
            (
                "sui_getCheckpoint",
                json!({"errors":[{"message":"field error"}]}),
            ),
            (
                "sui_getTransactionBlock",
                json!({"data":{"transaction":null}}),
            ),
        ] {
            let mapped = response(method, raw);
            assert!(mapped.get("error").is_some());
            assert!(mapped.get("result").is_none());
        }
        let page = json!({"data":{"transaction":{"effects":{"events":{"nodes":[],"pageInfo":{"hasNextPage":true}}}}}});
        assert!(response("suix_queryEvents", page).get("error").is_some());
    }

    #[test]
    fn packet_event_base64_and_checkpoint_timestamps_are_strict() {
        let malformed = json!({"data":{"transaction":{"effects":{"events":{"nodes":[{"contents":{"type":{"repr":"0x1::messaging_channel::PacketSentEvent"},"json":{"encoded_packet":"%%%"}}}],"pageInfo":{"hasNextPage":false}}}}}});
        assert!(response("suix_queryEvents", malformed)
            .get("error")
            .is_some());
        assert_eq!(
            timestamp_millis("2026-10-09T00:00:00.000Z"),
            Some(1_791_504_000_000)
        );
        for bad in [
            "2026-10-09T00:00:00+09:00",
            "2026-13-09T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-10-09T24:00:00Z",
        ] {
            assert_eq!(timestamp_millis(bad), None);
        }
    }
}
