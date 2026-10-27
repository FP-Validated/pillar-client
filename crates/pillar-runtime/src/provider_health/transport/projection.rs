use super::*;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::{cell::Cell, io::Read, rc::Rc};

const MAX_WIRE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum Node {
    All,
    Object(&'static [(&'static str, Node)]),
    Array(&'static Node, usize),
    Rpc(&'static Node),
}

const EVM_HEADER: Node = Node::Object(&[
    ("number", Node::All),
    ("hash", Node::All),
    ("parentHash", Node::All),
    ("timestamp", Node::All),
    ("receiptsRoot", Node::All),
]);
const EVM_TRANSACTION: Node = Node::Object(&[
    ("hash", Node::All),
    ("from", Node::All),
    ("blockHash", Node::All),
    ("blockNumber", Node::All),
]);
const STARKNET_TRANSACTION: Node = Node::Object(&[
    ("transaction_hash", Node::All),
    ("sender_address", Node::All),
    ("nonce", Node::All),
    ("version", Node::All),
    ("type", Node::All),
]);
const STELLAR_LEDGER: Node = Node::Object(&[
    ("sequence", Node::All),
    ("closeTime", Node::All),
    ("ledgerCloseTime", Node::All),
]);
const STELLAR_LEDGERS: Node = Node::Object(&[("ledgers", Node::Array(&STELLAR_LEDGER, 1))]);
const MOVE_EVENT_DATA: Node = Node::Object(&[
    ("encoded_packet", Node::All),
    ("packet", Node::All),
    ("options", Node::All),
    ("send_library", Node::All),
    ("guid", Node::All),
    ("adapter_params", Node::All),
]);
const MOVE_EVENT: Node = Node::Object(&[("type", Node::All), ("data", MOVE_EVENT_DATA)]);
const MOVE_TRANSACTION: Node = Node::Object(&[
    ("hash", Node::All),
    ("version", Node::All),
    ("type", Node::All),
    ("success", Node::All),
    ("sender", Node::All),
    ("block_height", Node::All),
    ("timestamp", Node::All),
    ("events", Node::Array(&MOVE_EVENT, usize::MAX)),
]);
const INITIA_ATTRIBUTE: Node = Node::Object(&[("key", Node::All), ("value", Node::All)]);
const INITIA_EVENT: Node = Node::Object(&[
    ("type", Node::All),
    ("attributes", Node::Array(&INITIA_ATTRIBUTE, 2)),
]);
const INITIA_TX_BODY: Node = Node::Object(&[(
    "auth_info",
    Node::Object(&[(
        "signer_infos",
        Node::Array(
            &Node::Object(&[(
                "public_key",
                Node::Object(&[("@type", Node::All), ("key", Node::All)]),
            )]),
            1,
        ),
    )]),
)]);
const INITIA_TX_RESPONSE: Node = Node::Object(&[
    ("txhash", Node::All),
    ("hash", Node::All),
    ("height", Node::All),
    ("code", Node::All),
    ("timestamp", Node::All),
    ("events", Node::Array(&INITIA_EVENT, usize::MAX)),
    ("tx", INITIA_TX_BODY),
]);
const INITIA_TRANSACTION: Node = Node::Object(&[
    ("tx_response", INITIA_TX_RESPONSE),
    ("tx", INITIA_TX_BODY),
    ("code", Node::All),
    ("message", Node::All),
]);
const INITIA_HEADER: Node = Node::Object(&[("height", Node::All), ("time", Node::All)]);
const INITIA_BLOCK: Node = Node::Object(&[
    ("block", Node::Object(&[("header", INITIA_HEADER)])),
    ("sdk_block", Node::Object(&[("header", INITIA_HEADER)])),
    ("code", Node::All),
    ("message", Node::All),
]);

pub(super) fn for_post(body: &Value) -> Option<Node> {
    let result = match body.get("method")?.as_str()? {
        "getLatestLedger" => &STELLAR_LEDGER,
        "getLedgers" => &STELLAR_LEDGERS,
        "eth_getBlockByNumber" | "eth_getBlockByHash" => &EVM_HEADER,
        "eth_getTransactionByHash" => &EVM_TRANSACTION,
        "starknet_getTransactionByHash" => &STARKNET_TRANSACTION,
        _ => return None,
    };
    Some(Node::Rpc(result))
}

pub(super) fn for_get(url: &str) -> Option<Node> {
    let url = url::Url::parse(url).ok()?;
    let path = url.path();
    if path.contains("/transactions/by_hash/") || path.contains("/transactions/by_version/") {
        Some(MOVE_TRANSACTION)
    } else if path.contains("/cosmos/tx/v1beta1/txs/") {
        Some(INITIA_TRANSACTION)
    } else if path.ends_with("/cosmos/base/tendermint/v1beta1/blocks/latest") {
        Some(INITIA_BLOCK)
    } else {
        None
    }
}

pub(super) async fn response(
    response: reqwest::Response,
    projection: Node,
) -> Result<Value, String> {
    if !response.status().is_success() {
        return Err(format!("Provider returned HTTP {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_WIRE_BYTES as u64)
    {
        return Err("Projected provider response exceeds 64 MiB wire limit".into());
    }
    let mut permit = acquire_json_parse_slot().await?;
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let mut worker = tokio::task::spawn_blocking(move || {
        let retained = Rc::new(Cell::new(true));
        let reader = GuardedReader::new(receiver, retained.clone());
        #[allow(clippy::disallowed_methods)]
        let mut decoder = serde_json::Deserializer::from_reader(reader);
        let result = Seed {
            projection,
            retained: &retained,
        }
        .deserialize(&mut decoder)
        .and_then(|value| decoder.end().map(|()| value))
        .map_err(|error| {
            format!(
                "Invalid projected provider JSON at {}:{}",
                error.line(),
                error.column()
            )
        });
        permit.finish(&result);
        result
    });
    let download = async move {
        let mut stream = response.bytes_stream();
        let mut total = 0usize;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| error.without_url().to_string())?;
            total = total
                .checked_add(chunk.len())
                .filter(|bytes| *bytes <= MAX_WIRE_BYTES)
                .ok_or_else(|| {
                    "Projected provider response exceeds 64 MiB wire limit".to_string()
                })?;
            for start in (0..chunk.len()).step_by(16 * 1024) {
                let end = (start + 16 * 1024).min(chunk.len());
                if sender.send(chunk.slice(start..end)).await.is_err() {
                    return Ok::<_, String>(());
                }
            }
        }
        Ok(())
    };
    tokio::select! {
        result = &mut worker => result.map_err(|_| "Provider projection worker failed".to_string())?,
        result = download => {
            result?;
            worker.await.map_err(|_| "Provider projection worker failed".to_string())?
        }
    }
}

struct Seed<'a> {
    projection: Node,
    retained: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        self.retained.set(true);
        if matches!(self.projection, Node::All) {
            pillar_core::json::UntrustedValue::deserialize(decoder).map(|value| value.0)
        } else {
            decoder.deserialize_any(self)
        }
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("the provider response's projected JSON shape")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Value, M::Error> {
        let mut result = serde_json::Map::new();
        loop {
            self.retained.set(true);
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            let child = match self.projection {
                Node::Object(fields) => fields
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, node)| *node),
                Node::Rpc(result) => match key.as_str() {
                    "result" => Some(*result),
                    "error" | "id" | "jsonrpc" => Some(Node::All),
                    _ => None,
                },
                _ => return Err(serde::de::Error::custom("unexpected projected object")),
            };
            if let Some(projection) = child {
                if result.contains_key(&key) {
                    return Err(serde::de::Error::custom("duplicate projected field"));
                }
                result.insert(
                    key,
                    map.next_value_seed(Seed {
                        projection,
                        retained: self.retained,
                    })?,
                );
            } else {
                self.retained.set(false);
                map.next_value::<IgnoredAny>()?;
            }
        }
        self.retained.set(true);
        Ok(Value::Object(result))
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Value, S::Error> {
        let Node::Array(element, limit) = self.projection else {
            return Err(serde::de::Error::custom("unexpected projected array"));
        };
        let mut result = Vec::new();
        while result.len() < limit {
            self.retained.set(true);
            let Some(value) = sequence.next_element_seed(Seed {
                projection: *element,
                retained: self.retained,
            })?
            else {
                return Ok(Value::Array(result));
            };
            result.push(value);
        }
        self.retained.set(false);
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        self.retained.set(true);
        Ok(Value::Array(result))
    }
}

struct GuardedReader {
    receiver: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    chunk: bytes::Bytes,
    retained: Rc<Cell<bool>>,
    bytes: usize,
    nodes: usize,
    depth: usize,
    in_string: bool,
    escaped: bool,
    in_scalar: bool,
}

impl GuardedReader {
    fn new(receiver: tokio::sync::mpsc::Receiver<bytes::Bytes>, retained: Rc<Cell<bool>>) -> Self {
        Self {
            receiver,
            chunk: bytes::Bytes::new(),
            retained,
            bytes: 0,
            nodes: 0,
            depth: 0,
            in_string: false,
            escaped: false,
            in_scalar: false,
        }
    }
    fn account(&mut self, byte: u8) -> std::io::Result<()> {
        let retained = self.retained.get();
        if retained {
            self.bytes += 1;
            if self.bytes > MAX_JSON_RESPONSE_BYTES {
                return Err(std::io::Error::other("retained JSON byte limit"));
            }
        }
        if self.in_string {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.in_string = false;
            }
            return Ok(());
        }
        if self.in_scalar {
            if !matches!(
                byte,
                b' ' | b'\n' | b'\r' | b'\t' | b'{' | b'[' | b'}' | b']' | b',' | b':' | b'"'
            ) {
                return Ok(());
            }
            self.in_scalar = false;
        }
        let node = match byte {
            b'"' => {
                self.in_string = true;
                true
            }
            b'{' | b'[' => {
                self.depth += 1;
                if self.depth > 128 {
                    return Err(std::io::Error::other("JSON nesting limit"));
                }
                true
            }
            b'}' | b']' => {
                self.depth = self.depth.saturating_sub(1);
                false
            }
            b',' | b':' => true,
            b't' | b'f' | b'n' | b'-' | b'0'..=b'9' => {
                self.in_scalar = true;
                true
            }
            _ => false,
        };
        if retained && node {
            self.nodes += 1;
            if self.nodes > MAX_JSON_PARSE_NODES {
                return Err(std::io::Error::other("retained JSON node limit"));
            }
        }
        Ok(())
    }
}

impl Read for GuardedReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.chunk.is_empty() {
            let Some(chunk) = self.receiver.blocking_recv() else {
                return Ok(0);
            };
            self.chunk = chunk;
        }
        let byte = self.chunk[0];
        self.account(byte)?;
        bytes::Buf::advance(&mut self.chunk, 1);
        output[0] = byte;
        Ok(1)
    }
}
