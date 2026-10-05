//! What Express and Node do to a request before upstream's handlers see it:
//! `express.json()` (Express 5.1.0: body-parser 2.2.2, raw-body 3, iconv-lite 0.7.2)
//! and Express 5's default "simple" query parser (`node:querystring`). Golden:
//! `fixtures/http_framework_golden.json`.

use std::io::Read;

use axum::{
    body::Bytes,
    extract::rejection::BytesRejection,
    http::{header, HeaderMap, StatusCode},
};
use serde_json::Value;

use crate::AppError;

/// `express.json()`'s default `limit: '100kb'`, counted on the bytes after inflation.
pub(crate) const JSON_BODY_LIMIT_BYTES: usize = 100 * 1024;

/// `express.json()` with its defaults (`bootstrap.ts:44`), in its order: no body
/// headers or a non-`application/json` type leave `req.body` undefined (`None`);
/// then the charset (`utf-*` only), the content encoding, a declared length over
/// the limit, iconv-lite's support for the charset, the size limit on inflated
/// bytes, decoding with the BOM dropped, empty → `{}`, and a top level that must
/// be an object or array.
pub(crate) fn read_json_body(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Option<Value>, AppError> {
    // `typeis.hasBody`; on a real HTTP/1.1 connection a body without either
    // framing header cannot exist, so a non-empty buffer stands in for one.
    let has_body = headers.contains_key(header::TRANSFER_ENCODING)
        || headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim().parse::<u64>().is_ok())
        || body.as_ref().map_or(true, |bytes| !bytes.is_empty());
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mut parts = content_type.split(';');
    let media_type = parts.next().unwrap_or_default().trim();
    if !has_body || !media_type.eq_ignore_ascii_case("application/json") {
        return Ok(None);
    }
    let charset = parts
        .rev()
        .find_map(|parameter| {
            let (name, value) = parameter.split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("charset")
                .then(|| value.trim().trim_matches('"').to_ascii_lowercase())
        })
        .filter(|charset| !charset.is_empty())
        .unwrap_or_else(|| "utf-8".to_string());
    if !charset.starts_with("utf-") {
        return Err(unsupported_charset(&charset));
    }
    let coding = content_coding(headers)?;
    let Some(decoder) = Decoder::for_label(&charset) else {
        // raw-body compares a declared length with the limit before it asks
        // iconv-lite for a decoder; a compressed or chunked body has no length.
        let declared = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        if matches!(coding, Coding::Identity)
            && declared.is_some_and(|length| length > JSON_BODY_LIMIT_BYTES as u64)
        {
            return Err(too_large());
        }
        return Err(unsupported_charset(&charset));
    };
    // body-parser 2 answers `br` with `createBrotliDecompress`; no brotli decoder is
    // available here, so every `br` body is refused as undecodable, before it is
    // buffered, as an undecodable stream fails on its first chunk (SECURITY.md).
    if matches!(coding, Coding::Brotli) {
        return Err(AppError::MalformedJson(
            "Failed to inflate the request body: brotli decoding is not supported".to_string(),
        ));
    }
    let raw = body.map_err(|rejection| AppError::Http {
        status: rejection.status(),
        message: rejection.body_text(),
    })?;
    let inflated;
    let bytes: &[u8] = match coding {
        Coding::Identity => &raw,
        Coding::Gzip | Coding::Deflate | Coding::Brotli => {
            inflated = inflate(&raw, coding)?;
            &inflated
        }
    };
    let text = decoder.decode(bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    if text.is_empty() {
        return Ok(Some(Value::Object(serde_json::Map::new())));
    }
    let first = text
        .chars()
        .find(|c| !matches!(c, ' ' | '\t' | '\n' | '\r'));
    if !matches!(first, Some('{' | '[')) {
        return Err(AppError::MalformedJson(
            "Failed to parse the request body as JSON: expected an object or array".to_string(),
        ));
    }
    serde_json::from_str(text).map(Some).map_err(|error| {
        AppError::MalformedJson(format!("Failed to parse the request body as JSON: {error}"))
    })
}

fn unsupported_charset(charset: &str) -> AppError {
    AppError::Http {
        status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
        message: format!("unsupported charset \"{}\"", charset.to_ascii_uppercase()),
    }
}

fn too_large() -> AppError {
    AppError::Http {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        message: "request entity too large".to_string(),
    }
}

#[derive(Clone, Copy)]
enum Coding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
}

/// `read.js` contentstream on `(req.headers['content-encoding'] || 'identity')`:
/// Node joins repeated lines with ", ", so only one line can name a known coding,
/// and an empty one is identity.
fn content_coding(headers: &HeaderMap) -> Result<Coding, AppError> {
    let values = headers.get_all(header::CONTENT_ENCODING);
    let mut lines = values.iter();
    let coding = match (lines.next(), lines.next()) {
        (None, _) => return Ok(Coding::Identity),
        (Some(value), None) if value.is_empty() => return Ok(Coding::Identity),
        (Some(value), None) => String::from_utf8_lossy(value.as_bytes()).to_lowercase(),
        (Some(_), Some(_)) => values
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).to_lowercase())
            .collect::<Vec<_>>()
            .join(", "),
    };
    match coding.as_str() {
        "identity" => Ok(Coding::Identity),
        "gzip" => Ok(Coding::Gzip),
        "deflate" => Ok(Coding::Deflate),
        "br" => Ok(Coding::Brotli),
        _ => Err(AppError::Http {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            message: format!("unsupported content encoding \"{coding}\""),
        }),
    }
}

/// Node's `createGunzip` or `createInflate` (`read.js` contentstream), producing at
/// most one byte past the limit so a decompression bomb costs at most that. gzip
/// reads members back to back until the input ends or the next byte is 0x00
/// (Node's "trailing zero bytes are okay"), and anything else there must be a
/// member; a zlib stream must reach its end and checksum, and bytes after it are
/// ignored. The compressed input is itself capped by the router's body limit,
/// which upstream does not apply to compressed bytes (`SECURITY.md`).
fn inflate(raw: &[u8], coding: Coding) -> Result<Vec<u8>, AppError> {
    let invalid = |reason: String| {
        AppError::MalformedJson(format!("Failed to inflate the request body: {reason}"))
    };
    if raw.is_empty() {
        return Err(invalid("unexpected end of file".to_string()));
    }
    let budget = JSON_BODY_LIMIT_BYTES + 1;
    match coding {
        Coding::Deflate => {
            let mut out = vec![0; budget];
            let mut stream = flate2::Decompress::new(true);
            let status = stream
                .decompress(raw, &mut out, flate2::FlushDecompress::Finish)
                .map_err(|error| invalid(error.to_string()))?;
            let written = stream.total_out() as usize;
            if written > JSON_BODY_LIMIT_BYTES {
                return Err(too_large());
            }
            if status != flate2::Status::StreamEnd {
                return Err(invalid("unexpected end of file".to_string()));
            }
            out.truncate(written);
            Ok(out)
        }
        Coding::Gzip => {
            let mut out = Vec::new();
            let mut input = raw;
            loop {
                let mut member = flate2::bufread::GzDecoder::new(input);
                (&mut member)
                    .take((budget - out.len()) as u64)
                    .read_to_end(&mut out)
                    .map_err(|error| invalid(error.to_string()))?;
                if out.len() > JSON_BODY_LIMIT_BYTES {
                    return Err(too_large());
                }
                input = member.into_inner();
                if input.first().is_none_or(|&byte| byte == 0) {
                    return Ok(out);
                }
            }
        }
        Coding::Identity | Coding::Brotli => unreachable!("handled before inflation"),
    }
}

/// The iconv-lite 0.7.2 decoders a `utf-*` label can reach.
#[derive(Clone, Copy)]
enum Decoder {
    Utf8,
    Utf16Le,
    Utf16Be,
    Utf16Detect,
    Utf32Le,
    Utf32Be,
    Utf32Detect,
    Utf7,
    Utf7Imap,
}

impl Decoder {
    /// iconv-lite's `_canonicalizeEncoding`: lowercase, drop a `:YYYY` suffix and
    /// every character outside `[0-9a-z]`.
    fn for_label(label: &str) -> Option<Self> {
        let lower = label.to_ascii_lowercase();
        let trimmed = match lower.rsplit_once(':') {
            Some((head, year)) if year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit()) => {
                head
            }
            _ => &lower,
        };
        let canonical: String = trimmed
            .chars()
            .filter(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
            .collect();
        match canonical.as_str() {
            "utf8" => Some(Self::Utf8),
            "utf16le" => Some(Self::Utf16Le),
            "utf16be" => Some(Self::Utf16Be),
            "utf16" => Some(Self::Utf16Detect),
            "utf32le" => Some(Self::Utf32Le),
            "utf32be" => Some(Self::Utf32Be),
            "utf32" => Some(Self::Utf32Detect),
            "utf7" => Some(Self::Utf7),
            "utf7imap" => Some(Self::Utf7Imap),
            _ => None,
        }
    }

    fn decode(self, bytes: &[u8]) -> String {
        match self {
            Self::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Self::Utf16Le => utf16_to_string(&utf16_units(bytes, false)),
            Self::Utf16Be => utf16_to_string(&utf16_units(bytes, true)),
            Self::Utf16Detect => {
                utf16_to_string(&utf16_units(bytes, utf16_detect_big_endian(bytes)))
            }
            Self::Utf32Le => utf32_decode(bytes, false),
            Self::Utf32Be => utf32_decode(bytes, true),
            Self::Utf32Detect => utf32_decode(bytes, utf32_detect_big_endian(bytes)),
            Self::Utf7 => utf7_decode(bytes, b'+', false),
            Self::Utf7Imap => utf7_decode(bytes, b'&', true),
        }
    }
}

/// iconv-lite's UTF-32 decoder: whole 4-byte units, anything outside U+0000..U+10FFFF
/// (and a lone surrogate, which Rust cannot hold) as U+FFFD, trailing bytes dropped.
fn utf32_decode(bytes: &[u8], big_endian: bool) -> String {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&unit| {
            let value = if big_endian {
                u32::from_be_bytes(unit)
            } else {
                u32::from_le_bytes(unit)
            };
            char::from_u32(value).unwrap_or(char::REPLACEMENT_CHARACTER)
        })
        .collect()
}

/// `utf32.js` `detectEncoding`: a BOM, else which reading of the first 100 units
/// has more plausible BMP characters, else little-endian.
fn utf32_detect_big_endian(bytes: &[u8]) -> bool {
    match bytes {
        [0xff, 0xfe, 0, 0, ..] => return false,
        [0, 0, 0xfe, 0xff, ..] => return true,
        _ => {}
    }
    let (mut invalid_le, mut invalid_be, mut bmp_le, mut bmp_be) = (0i32, 0i32, 0i32, 0i32);
    for b in bytes.as_chunks::<4>().0.iter().take(100) {
        if b[0] != 0 || b[1] > 0x10 {
            invalid_be += 1;
        }
        if b[3] != 0 || b[2] > 0x10 {
            invalid_le += 1;
        }
        if b[0] == 0 && b[1] == 0 && (b[2] != 0 || b[3] != 0) {
            bmp_be += 1;
        }
        if (b[0] != 0 || b[1] != 0) && b[2] == 0 && b[3] == 0 {
            bmp_le += 1;
        }
    }
    bmp_be - invalid_be > bmp_le - invalid_le
}

/// Code units of a UTF-16 byte run; an odd trailing byte is dropped, as Node's
/// `ucs2` decoding and iconv-lite's BE decoder both do.
fn utf16_units(bytes: &[u8], big_endian: bool) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| {
            if big_endian {
                u16::from_be_bytes(pair)
            } else {
                u16::from_le_bytes(pair)
            }
        })
        .collect()
}

/// A lone surrogate, which a JavaScript string keeps, becomes U+FFFD here.
fn utf16_to_string(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// iconv-lite `utf16.js` detectEncoding: a BOM decides, otherwise the more common
/// ASCII position in the first 64 bytes, with little-endian on a tie.
fn utf16_detect_big_endian(bytes: &[u8]) -> bool {
    match bytes {
        [0xfe, 0xff, ..] => true,
        [0xff, 0xfe, ..] => false,
        _ if bytes.len() < 2 => false,
        _ => {
            let len = (bytes.len() - bytes.len() % 2).min(64);
            let (mut le, mut be) = (0usize, 0usize);
            for &[first, second] in bytes[..len].as_chunks::<2>().0 {
                if first == 0 && second != 0 {
                    be += 1;
                }
                if first != 0 && second == 0 {
                    le += 1;
                }
            }
            be > le
        }
    }
}

/// iconv-lite `utf7.js` decoders over the whole body: direct bytes are ASCII
/// (anything above 0x7f is U+FFFD), a shift byte opens modified base64 that the
/// first non-base64 byte closes, a `-` there is absorbed, and shift-then-`-` is the
/// shift byte itself. Each base64 run goes through its own BOM-stripping UTF-16BE
/// decode, and a run the body ends inside is decoded as `write` then `end` do:
/// its whole 8-character groups, then the rest.
fn utf7_decode(bytes: &[u8], shift: u8, imap: bool) -> String {
    let is_base64 = |byte: u8| {
        byte.is_ascii_alphanumeric() || byte == b'/' || byte == b'+' || (imap && byte == b',')
    };
    let decode_run = |chars: &[u8], units: &mut Vec<u16>| {
        let decoded = base64_lenient(chars, imap);
        let run = decoded.as_chunks::<2>().0;
        let skip = usize::from(run.first() == Some(&[0xfe, 0xff]));
        units.extend(run[skip..].iter().map(|&pair| u16::from_be_bytes(pair)));
    };
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte != shift {
            units.push(if byte < 0x80 { u16::from(byte) } else { 0xfffd });
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && is_base64(bytes[end]) {
            end += 1;
        }
        if end == start && bytes.get(end) == Some(&b'-') {
            units.push(u16::from(shift));
        } else if end == bytes.len() {
            let whole = start + (end - start) / 8 * 8;
            decode_run(&bytes[start..whole], &mut units);
            decode_run(&bytes[whole..end], &mut units);
        } else {
            decode_run(&bytes[start..end], &mut units);
        }
        i = if bytes.get(end) == Some(&b'-') {
            end + 1
        } else {
            end
        };
    }
    utf16_to_string(&units)
}

/// Node's `Buffer.from(text, 'base64')` over characters already known to be in
/// the alphabet (`,` standing for `/` in the IMAP variant): whole quads give three
/// bytes, a trailing pair one and a trailing triple two.
fn base64_lenient(chars: &[u8], imap: bool) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b',' if imap => 63,
            _ => 63,
        }
    };
    let mut out = Vec::with_capacity(chars.len() * 3 / 4);
    for quad in chars.chunks(4) {
        let mut acc = 0u32;
        for (index, &c) in quad.iter().enumerate() {
            acc |= value(c) << (18 - 6 * index);
        }
        let take = match quad.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => 0,
        };
        out.extend_from_slice(&acc.to_be_bytes()[1..1 + take]);
    }
    out
}

/// `req.query.chainName` under Express 5's default "simple" query parser,
/// `querystring.parse`, reduced to what upstream's signer-info handler does with
/// it (`bootstrap.ts:96-103`, `app.ts:181-184`).
pub(crate) enum ChainNameQuery {
    /// Absent or the empty string: upstream's missing-parameter 400.
    Missing,
    /// A plain string, checked against the roster.
    Name(String),
    /// A repeated key, so an array: never in the roster; its `${value}` rendering.
    Unsupported(String),
}

/// Pairs split on `&` then the first `=`, `+` as a space, keys and values
/// percent-decoded, and a repeated key collected into an array. Bracket syntax
/// has no meaning here: `chainName[]` is just another key.
pub(crate) fn chain_name_query(raw: Option<&str>) -> ChainNameQuery {
    let mut values = Vec::new();
    for part in raw.unwrap_or_default().split('&').take(1000) {
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        if querystring_decode(key) == "chainName" {
            values.push(querystring_decode(value));
        }
    }
    match values.as_slice() {
        [] => ChainNameQuery::Missing,
        [single] if single.is_empty() => ChainNameQuery::Missing,
        [single] => ChainNameQuery::Name(single.clone()),
        many => ChainNameQuery::Unsupported(many.join(",")),
    }
}

/// `querystring.unescape` with spaces decoded: `decodeURIComponent`, or where that
/// throws, `unescapeBuffer` - every well-formed `%XX` becomes its byte and the rest
/// stays as written - read back as UTF-8 with U+FFFD. Both agree wherever the first
/// succeeds, so the second alone is the rule.
fn querystring_decode(text: &str) -> String {
    let spaced = text.replace('+', " ");
    let bytes = spaced.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let byte = bytes
                .get(i + 1..i + 3)
                .filter(|pair| pair.iter().all(u8::is_ascii_hexdigit))
                .and_then(|pair| std::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok());
            if let Some(byte) = byte {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
