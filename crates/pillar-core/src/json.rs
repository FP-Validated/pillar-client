//! JSON parsing for every byte string this service did not write itself.
//!
//! `serde_json::Value`'s own `Deserialize` treats an object whose first key is
//! [`RAW_VALUE_TOKEN`] as a boxed `RawValue` and re-parses the string under it
//! with a fresh recursion budget whenever the `raw_value` feature is enabled
//! anywhere in the build (axum enables it). Nesting that string N times defeats
//! the 128-level depth limit, and the same re-parse fires again in any later
//! `serde_json::from_value` over a `Value` that still carries the key. This
//! module builds `Value`s with its own visitor and refuses the key outright, so
//! no `Value` produced here can trigger the re-parse downstream.
//!
//! `clippy.toml` disallows the direct `serde_json` parsing entry points so new
//! call sites have to come through here.

use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use std::fmt;

/// The object key `serde_json` reserves for its private `RawValue` encoding.
pub const RAW_VALUE_TOKEN: &str = "$serde_json::private::RawValue";
/// The object key `serde_json` reserves for its private arbitrary-precision number encoding.
pub const NUMBER_TOKEN: &str = "$serde_json::private::Number";

fn reserved_key<E: de::Error>(key: &str) -> Result<(), E> {
    if key == RAW_VALUE_TOKEN || key == NUMBER_TOKEN {
        return Err(E::custom(format!("reserved JSON object key `{key}`")));
    }
    Ok(())
}

/// A `Value` decoded without `serde_json`'s private-token handling and with
/// [`RAW_VALUE_TOKEN`] / [`NUMBER_TOKEN`] refused at every depth.
///
/// Exposed so a caller driving its own deserializer (for example one wrapped in
/// `serde_stacker`) gets the same guarantee as [`parse_value_slice`].
pub struct UntrustedValue(pub Value);

impl<'de> Deserialize<'de> for UntrustedValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(UntrustedValueVisitor)
            .map(UntrustedValue)
    }
}

struct UntrustedValueVisitor;

// Mirrors `serde_json::value::de::ValueVisitor` (1.0.150) except for `visit_map`.
impl<'de> Visitor<'de> for UntrustedValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<Value, E> {
        Number::deserialize(de::value::I128Deserializer::new(value)).map(Value::Number)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<Value, E> {
        Number::deserialize(de::value::U128Deserializer::new(value)).map(Value::Number)
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        UntrustedValue::deserialize(deserializer).map(|value| value.0)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<V: SeqAccess<'de>>(self, mut visitor: V) -> Result<Value, V::Error> {
        let mut values = Vec::new();
        while let Some(UntrustedValue(value)) = visitor.next_element()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<V: MapAccess<'de>>(self, mut visitor: V) -> Result<Value, V::Error> {
        let mut values = Map::new();
        while let Some(key) = visitor.next_key::<String>()? {
            reserved_key::<V::Error>(&key)?;
            let UntrustedValue(value) = visitor.next_value()?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

/// Walks a document without building it, refusing the reserved keys; used before
/// a typed parse whose target may contain a `Value`.
struct ReservedKeyGuard;

impl<'de> Deserialize<'de> for ReservedKeyGuard {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ReservedKeyGuard)
    }
}

impl<'de> Visitor<'de> for ReservedKeyGuard {
    type Value = ReservedKeyGuard;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_i128<E>(self, _: i128) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_u128<E>(self, _: u128) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_none<E>(self) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self, D::Error> {
        ReservedKeyGuard::deserialize(deserializer)
    }
    fn visit_unit<E>(self) -> Result<Self, E> {
        Ok(self)
    }
    fn visit_seq<V: SeqAccess<'de>>(self, mut visitor: V) -> Result<Self, V::Error> {
        while visitor.next_element::<ReservedKeyGuard>()?.is_some() {}
        Ok(self)
    }
    fn visit_map<V: MapAccess<'de>>(self, mut visitor: V) -> Result<Self, V::Error> {
        while let Some(key) = visitor.next_key::<std::borrow::Cow<'de, str>>()? {
            reserved_key::<V::Error>(&key)?;
            visitor.next_value::<ReservedKeyGuard>()?;
        }
        Ok(self)
    }
}

/// `serde_json::from_str::<Value>` with the reserved keys refused.
#[allow(clippy::disallowed_methods)] // The one sanctioned entry point.
pub fn parse_value(text: &str) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let UntrustedValue(value) = UntrustedValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// `serde_json::from_slice::<Value>` with the reserved keys refused.
#[allow(clippy::disallowed_methods)] // The one sanctioned entry point.
pub fn parse_value_slice(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let UntrustedValue(value) = UntrustedValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// `serde_json::from_str::<T>` after a pass that refuses the reserved keys, so a
/// `Value` or flattened map inside `T` cannot be fed the re-parse. The typed
/// parse reads the text itself, which keeps map order for `IndexMap` targets.
#[allow(clippy::disallowed_methods)] // The one sanctioned entry point.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    ReservedKeyGuard::deserialize(&mut deserializer)?;
    deserializer.end()?;
    serde_json::from_str(text)
}
