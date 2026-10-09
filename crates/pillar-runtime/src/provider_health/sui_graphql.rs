use serde_json::{json, Value};

pub(super) fn request(body: &Value) -> Option<(String, Value)> {
    let method = body.get("method")?.as_str()?;
    let params = body.get("params").and_then(Value::as_array)?;
    let request = match method {
        "suix_queryEvents" => {
            let digest = params.first()?.get("Transaction")?.as_str()?;
            ("query($digest: String!) { transaction(digest: $digest) { effects { events(first: 50) { nodes { contents { type { repr } json } } } } }".to_string(), json!({"digest": digest}), method)
        }
        "sui_getTransactionBlock" => {
            let digest = params.first()?.as_str()?;
            (
                "query($digest: String!) { transaction(digest: $digest) { digest sender { address } effects { checkpoint { sequenceNumber } status } } }".to_string(),
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
            ("query($package: SuiAddress!, $module: String!, $function: String!) { package(address: $package) { module(name: $module) { function(name: $function) { parameters { repr } } } } }".to_string(), json!({"package": package, "module": module, "function": function}), method)
        }
        "sui_multiGetObjects" => {
            let ids = params.first()?.as_array()?;
            let address = ids.first()?.as_str()?;
            ("query($address: SuiAddress!) { object(address: $address) { asMoveObject { owner { __typename ... on Shared { initialSharedVersion } } } } }".to_string(), json!({"address": address}), method)
        }
        "sui_devInspectTransactionBlock" => {
            let params = body.get("params").and_then(Value::as_array)?;
            let sender = params.first()?.as_str()?;
            let kind = params.get(1)?.as_str()?;
            let transaction = json!({"bcs":{"value":kind}, "sender":sender});
            ("query($transaction: JSON!) { simulateTransaction(transaction: $transaction, checksEnabled: false, doGasSelection: true) { effects { status executionError { message } } outputs { returnValues { value { bcs json } } } } }".to_string(), json!({"transaction": transaction}), method)
        }
        _ => return None,
    };
    Some((
        request.2.to_string(),
        json!({"query": request.0, "variables": request.1}),
    ))
}

pub(super) fn response(method: &str, graphql: Value) -> Value {
    let id = 1;
    if let Some(errors) = graphql.get("errors") {
        let message = errors
            .as_array()
            .and_then(|errors| errors.first())
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("Sui GraphQL request failed");
        return json!({"jsonrpc":"2.0", "id":id, "error":{"code":-32000,"message":message}});
    }
    let data = graphql.get("data").unwrap_or(&Value::Null);
    let result = match method {
        "suix_queryEvents" => {
            let events = data
                .pointer("/transaction/effects/events/nodes")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let data = events
                .into_iter()
                .map(|event| {
                    let event_type = event
                        .pointer("/contents/type/repr")
                        .cloned()
                        .unwrap_or(Value::Null);
                    let mut parsed = event
                        .pointer("/contents/json")
                        .cloned()
                        .unwrap_or(Value::Null);
                    normalize_graphql_event_json(&event_type, &mut parsed);
                    json!({"type":event_type,"parsedJson":parsed})
                })
                .collect::<Vec<_>>();
            json!({"data": data, "hasNextPage": false, "nextCursor": null})
        }
        "sui_getTransactionBlock" => {
            let tx = data.get("transaction").unwrap_or(&Value::Null);
            let sender = tx
                .pointer("/sender/address")
                .cloned()
                .unwrap_or(Value::Null);
            let status = tx
                .pointer("/effects/status")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                .map(Value::String)
                .unwrap_or(Value::Null);
            json!({
                "digest": tx.get("digest"),
                "checkpoint": tx.pointer("/effects/checkpoint/sequenceNumber"),
                "sender": sender,
                "transaction": {"data":{"sender":sender,"transaction":Value::Null}},
                "effects": {"status": {"status": status}}
            })
        }
        "sui_getLatestCheckpointSequenceNumber" => data
            .pointer("/checkpoints/nodes/0/sequenceNumber")
            .cloned()
            .unwrap_or(Value::Null),
        "sui_getCheckpoint" => {
            let timestamp = data
                .pointer("/checkpoint/timestamp")
                .and_then(Value::as_str)
                .and_then(timestamp_millis);
            json!({"timestampMs": timestamp})
        }
        "sui_getNormalizedMoveFunction" => {
            let parameters = data
                .pointer("/package/module/function/parameters")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let parameters = parameters
                .into_iter()
                .map(|parameter| {
                    let repr = parameter.get("repr").and_then(Value::as_str).unwrap_or("");
                    if repr.starts_with('&') && !repr.starts_with("&mut ") {
                        json!({"Reference": repr})
                    } else {
                        json!({"MutableReference": repr})
                    }
                })
                .collect::<Vec<_>>();
            json!({"parameters": parameters})
        }
        "sui_multiGetObjects" => {
            let owner = data
                .pointer("/object/asMoveObject/owner")
                .unwrap_or(&Value::Null);
            let shared = if owner.get("__typename").and_then(Value::as_str) == Some("Shared") {
                json!({"initial_shared_version":owner.get("initialSharedVersion")})
            } else {
                Value::Null
            };
            json!([{"data":{"owner":{"Shared":shared}}}])
        }
        "sui_devInspectTransactionBlock" => {
            let simulation = data.get("simulateTransaction").unwrap_or(&Value::Null);
            let status = simulation
                .pointer("/effects/status")
                .and_then(Value::as_str)
                .unwrap_or("");
            let err = simulation
                .pointer("/effects/executionError/message")
                .and_then(Value::as_str);
            let results = simulation
                .get("outputs")
                .and_then(Value::as_array)
                .map(|outputs| {
                    outputs
                        .iter()
                        .map(|output| {
                            let values = output
                                .get("returnValues")
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default();
                            let values = values
                                .into_iter()
                                .map(|value| {
                                    value
                                        .pointer("/value/bcs")
                                        .and_then(Value::as_str)
                                        .map(|s| json!([s, []]))
                                        .unwrap_or(Value::Null)
                                })
                                .collect::<Vec<_>>();
                            json!({"returnValues": values})
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            json!({"effects":{"statusType":status}, "results":results, "error":err})
        }
        _ => Value::Null,
    };
    json!({"jsonrpc":"2.0", "id":id, "result":result})
}

fn timestamp_millis(value: &str) -> Option<i64> {
    let (date, time) = value.split_once('T')?;
    let mut parts = date.split('-');
    let year = parts.next()?.parse::<i64>().ok()?;
    let month = parts.next()?.parse::<i64>().ok()?;
    let day = parts.next()?.parse::<i64>().ok()?;
    let clock = time.split(['Z', '+', '-']).next()?;
    let mut parts = clock.split(':');
    let hour = parts.next()?.parse::<i64>().ok()?;
    let minute = parts.next()?.parse::<i64>().ok()?;
    let seconds = parts.next()?;
    let (second, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
    let second = second.parse::<i64>().ok()?;
    let millis = fraction.bytes().take(3).try_fold(0_i64, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + i64::from(byte - b'0'))
    })? * 10_i64.checked_pow(3_u32.saturating_sub(fraction.len().min(3) as u32))?;
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
fn normalize_graphql_event_json(event_type: &Value, parsed: &mut Value) {
    if !event_type
        .as_str()
        .is_some_and(|event| event.ends_with("::messaging_channel::PacketSentEvent"))
    {
        return;
    }
    let Some(object) = parsed.as_object_mut() else {
        return;
    };
    for field in ["encoded_packet", "options"] {
        let Some(encoded) = object.get(field).and_then(Value::as_str) else {
            continue;
        };
        use base64::Engine;
        if !encoded.starts_with("0x") {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                object.insert(
                    field.to_string(),
                    Value::Array(bytes.into_iter().map(Value::from).collect()),
                );
            }
        }
    }
}

pub(super) fn transaction_sender_query(url: &str) -> Option<(String, String, Value)> {
    let (endpoint, digest) = url.rsplit_once("/transactions/by_hash/")?;
    if digest.is_empty() || digest.contains('/') {
        return None;
    }
    Some((
        endpoint.to_string(),
        digest.to_string(),
        json!({"query":"query($digest: String!) { transaction(digest: $digest) { digest sender { address } } }","variables":{"digest":digest}}),
    ))
}

pub(super) fn transaction_sender_response(digest: &str, response: Value) -> Value {
    let sender = response
        .pointer("/data/transaction/sender/address")
        .cloned()
        .unwrap_or(Value::Null);
    json!({"hash":digest,"sender":sender,"events":[]})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const CAPTURE: &str = include_str!(
        "../../tests/gasolina_parity/transport/sui-mainnet-graphql-source-transaction.json"
    );

    #[test]
    fn captured_graphql_packet_matches_move_event_decoder() {
        let capture: Value = serde_json::from_str(CAPTURE).unwrap();
        let graphql = capture.get("response").unwrap().clone();
        let mapped = response("suix_queryEvents", graphql);
        let events = crate::layerzero_runtime::decode_sui_packet_sent_events(
            &mapped,
            &HashSet::from(["0x31beaef889b08b9c9".to_string()]),
        );
        assert!(events.is_err());
        let events = crate::layerzero_runtime::decode_sui_packet_sent_events(
            &mapped,
            &HashSet::from([
                "0x31beaef889b08b9c3b37d19280fc1f8b75bae5b2de2410fc3120f403e9a36dac".to_string(),
            ]),
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].endpoint_address,
            "0x31beaef889b08b9c3b37d19280fc1f8b75bae5b2de2410fc3120f403e9a36dac"
        );
        assert_eq!(events[0].packet.src_eid, 30_378);
        assert_eq!(events[0].packet.dst_eid, 30_378);
        assert_eq!(
            events[0].send_library.as_deref(),
            Some("0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0")
        );
        assert_eq!(
            capture["provenance"]["digest"],
            "FxnUDMSUMt6wpDB7g7vhvxBEpvVVchvS7oUuDtnMAUw2"
        );
    }

    #[test]
    fn requests_bind_each_sui_method_to_its_graphql_query() {
        let cases = [
            (
                json!({"method":"suix_queryEvents","params":[{"Transaction":"tx"}]}),
                "transaction(digest: $digest)",
            ),
            (
                json!({"method":"sui_getTransactionBlock","params":["tx",{}]}),
                "sender { address }",
            ),
            (
                json!({"method":"sui_getLatestCheckpointSequenceNumber","params":[]}),
                "checkpoints(last: 1)",
            ),
            (
                json!({"method":"sui_getCheckpoint","params":["42"]}),
                "checkpoint(sequenceNumber: $sequence)",
            ),
            (
                json!({"method":"sui_getNormalizedMoveFunction","params":["0xp","m","f"]}),
                "function(name: $function)",
            ),
            (
                json!({"method":"sui_multiGetObjects","params":[["0xo"],{}]}),
                "object(address: $address)",
            ),
            (
                json!({"method":"sui_devInspectTransactionBlock","params":["0xs","kind"]}),
                "simulateTransaction(transaction: $transaction",
            ),
        ];
        for (request_value, expected) in cases {
            let (_, graphql) = request(&request_value).unwrap();
            assert!(graphql["query"].as_str().unwrap().contains(expected));
            assert!(graphql["variables"].is_object());
        }
    }

    #[test]
    fn unsupported_request_has_no_graphql_translation() {
        assert!(request(&json!({"method":"sui_unknown","params":[]})).is_none());
    }

    #[test]
    fn maps_recorded_graphql_response_shapes() {
        assert_eq!(
            response(
                "sui_getTransactionBlock",
                json!({"data":{"transaction":{"sender":{"address":"0xs"},"effects":{"checkpoint":{"sequenceNumber":12},"status":"SUCCESS"}}}})
            )["result"]["checkpoint"],
            12
        );
        assert_eq!(
            response(
                "sui_getLatestCheckpointSequenceNumber",
                json!({"data":{"checkpoints":{"nodes":[{"sequenceNumber":12}]}}})
            )["result"],
            12
        );
        assert_eq!(
            response(
                "sui_getCheckpoint",
                json!({"data":{"checkpoint":{"timestamp":"2026-10-09T00:00:00.000Z"}}})
            )["result"]["timestampMs"],
            1_791_504_000_000_i64
        );
        assert_eq!(
            response(
                "sui_getNormalizedMoveFunction",
                json!({"data":{"package":{"module":{"function":{"parameters":[{"repr":"&mut TxContext"}]}}}}})
            )["result"]["parameters"][0]["MutableReference"],
            "&mut TxContext"
        );
        assert_eq!(
            response(
                "sui_multiGetObjects",
                json!({"data":{"object":{"asMoveObject":{"owner":{"__typename":"Shared","initialSharedVersion":"7"}}}}})
            )["result"][0]["data"]["owner"]["Shared"]["initial_shared_version"],
            "7"
        );
        assert_eq!(
            response(
                "sui_devInspectTransactionBlock",
                json!({"data":{"simulateTransaction":{"effects":{"status":"SUCCESS"},"outputs":[{"returnValues":[{"value":{"bcs":"AQI="}}]}]}}})
            )["result"]["results"][0]["returnValues"][0][0],
            "AQI="
        );
        assert_eq!(
            transaction_sender_response(
                "tx",
                json!({"data":{"transaction":{"sender":{"address":"0xs"}}}})
            )["sender"],
            "0xs"
        );
    }
}
