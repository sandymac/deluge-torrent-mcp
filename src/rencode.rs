// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

/// Internal rencode serializer/deserializer for the Deluge RPC wire format.
///
/// rencode is a compact binary encoding similar to bencoding but supporting
/// more types. Deluge uses it to serialize RPC request/response tuples before
/// zlib-compressing and framing them.
///
/// Reference: https://github.com/aresch/rencode

// Type tags
const CHR_LIST: u8 = 59;
const CHR_DICT: u8 = 60;
const CHR_INT: u8 = 61;
const CHR_INT1: u8 = 62;
const CHR_INT2: u8 = 63;
const CHR_INT4: u8 = 64;
const CHR_INT8: u8 = 65;
const CHR_FLOAT32: u8 = 66;
const CHR_FLOAT64: u8 = 44;
const CHR_TRUE: u8 = 67;
const CHR_FALSE: u8 = 68;
const CHR_NONE: u8 = 69;
const CHR_TERM: u8 = 127;

// Fixed-length small integer range encoded directly as a single byte
const INT_POS_FIXED_START: u8 = 0;
const INT_POS_FIXED_COUNT: u8 = 44;
const INT_NEG_FIXED_START: u8 = 70;
const INT_NEG_FIXED_COUNT: u8 = 32;

// Fixed-length short string: tag byte encodes both type and length
const STR_FIXED_START: u8 = 128;
const STR_FIXED_COUNT: u8 = 64; // lengths 0..=63

// Fixed-length short dict
const DICT_FIXED_START: u8 = 102;
const DICT_FIXED_COUNT: u8 = 25; // lengths 0..=24 (tags 102–126)

// Fixed-length short list
const LIST_FIXED_START: u8 = 192;
const LIST_FIXED_COUNT: u8 = 64; // lengths 0..=63

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RencodeError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("unknown type tag: {0}")]
    UnknownTag(u8),
    #[error("integer overflow")]
    IntegerOverflow,
    #[error("invalid utf-8 in string")]
    InvalidUtf8,
    #[error("nesting depth limit exceeded (max 128)")]
    DepthLimitExceeded,
}

const MAX_DEPTH: usize = 128;

/// A dynamically-typed rencode value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    None,
    Bool(bool),
    Int(i64),
    Float32(f32),
    Float64(f64),
    Bytes(Vec<u8>),
    String(String),
    List(Vec<Value>),
    Dict(Vec<(Value, Value)>),
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

pub fn encode(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_into(value, &mut buf);
    buf
}

fn encode_into(value: &Value, buf: &mut Vec<u8>) {
    match value {
        Value::None => buf.push(CHR_NONE),
        Value::Bool(true) => buf.push(CHR_TRUE),
        Value::Bool(false) => buf.push(CHR_FALSE),

        Value::Int(n) => encode_int(*n, buf),

        Value::Float32(f) => {
            buf.push(CHR_FLOAT32);
            buf.extend_from_slice(&f.to_be_bytes());
        }
        Value::Float64(f) => {
            buf.push(CHR_FLOAT64);
            buf.extend_from_slice(&f.to_be_bytes());
        }

        Value::Bytes(b) => encode_bytes(b, buf),
        Value::String(s) => encode_bytes(s.as_bytes(), buf),

        Value::List(items) => {
            if items.len() < LIST_FIXED_COUNT as usize {
                buf.push(LIST_FIXED_START + items.len() as u8);
            } else {
                buf.push(CHR_LIST);
            }
            for item in items {
                encode_into(item, buf);
            }
            if items.len() >= LIST_FIXED_COUNT as usize {
                buf.push(CHR_TERM);
            }
        }

        Value::Dict(pairs) => {
            if pairs.len() < DICT_FIXED_COUNT as usize {
                buf.push(DICT_FIXED_START + pairs.len() as u8);
            } else {
                buf.push(CHR_DICT);
            }
            for (k, v) in pairs {
                encode_into(k, buf);
                encode_into(v, buf);
            }
            if pairs.len() >= DICT_FIXED_COUNT as usize {
                buf.push(CHR_TERM);
            }
        }
    }
}

fn encode_int(n: i64, buf: &mut Vec<u8>) {
    if n >= 0 && n < INT_POS_FIXED_COUNT as i64 {
        buf.push(INT_POS_FIXED_START + n as u8);
    } else if n >= -(INT_NEG_FIXED_COUNT as i64) && n < 0 {
        buf.push(INT_NEG_FIXED_START + (-n - 1) as u8);
    } else if n >= i8::MIN as i64 && n <= i8::MAX as i64 {
        buf.push(CHR_INT1);
        buf.push(n as i8 as u8);
    } else if n >= i16::MIN as i64 && n <= i16::MAX as i64 {
        buf.push(CHR_INT2);
        buf.extend_from_slice(&(n as i16).to_be_bytes());
    } else if n >= i32::MIN as i64 && n <= i32::MAX as i64 {
        buf.push(CHR_INT4);
        buf.extend_from_slice(&(n as i32).to_be_bytes());
    } else {
        buf.push(CHR_INT8);
        buf.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_bytes(b: &[u8], buf: &mut Vec<u8>) {
    if b.len() < STR_FIXED_COUNT as usize {
        buf.push(STR_FIXED_START + b.len() as u8);
    } else {
        // Variable-length: ASCII decimal length followed by ':'
        let len_str = b.len().to_string();
        buf.extend_from_slice(len_str.as_bytes());
        buf.push(b':');
    }
    buf.extend_from_slice(b);
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

pub fn decode(data: &[u8]) -> Result<Value, RencodeError> {
    let (value, _) = decode_from(data, 0, 0)?;
    Ok(value)
}

fn decode_from(data: &[u8], pos: usize, depth: usize) -> Result<(Value, usize), RencodeError> {
    if depth > MAX_DEPTH {
        return Err(RencodeError::DepthLimitExceeded);
    }
    let tag = *data.get(pos).ok_or(RencodeError::UnexpectedEof)?;

    // Fixed positive integer
    if tag < INT_POS_FIXED_COUNT {
        return Ok((Value::Int(tag as i64), pos + 1));
    }

    // Fixed list (must be checked before fixed string — LIST_FIXED_START >= STR_FIXED_START)
    if tag >= LIST_FIXED_START {
        let count = (tag - LIST_FIXED_START) as usize;
        let mut items = Vec::with_capacity(count);
        let mut cur = pos + 1;
        for _ in 0..count {
            let (v, next) = decode_from(data, cur, depth + 1)?;
            items.push(v);
            cur = next;
        }
        return Ok((Value::List(items), cur));
    }

    // Fixed string (short bytes)
    if tag >= STR_FIXED_START {
        let len = (tag - STR_FIXED_START) as usize;
        let start = pos + 1;
        let end = start + len;
        if data.len() < end {
            return Err(RencodeError::UnexpectedEof);
        }
        let bytes = data[start..end].to_vec();
        // Try to interpret as UTF-8 string; fall back to raw bytes
        let value = match String::from_utf8(bytes.clone()) {
            Ok(s) => Value::String(s),
            Err(_) => Value::Bytes(bytes),
        };
        return Ok((value, end));
    }

    // Fixed dict (tags 102–126, must be checked before fixed negative ints which start at 70)
    if tag >= DICT_FIXED_START && tag < DICT_FIXED_START + DICT_FIXED_COUNT {
        let count = (tag - DICT_FIXED_START) as usize;
        let mut pairs = Vec::with_capacity(count);
        let mut cur = pos + 1;
        for _ in 0..count {
            let (k, next) = decode_from(data, cur, depth + 1)?;
            let (v, next2) = decode_from(data, next, depth + 1)?;
            pairs.push((k, v));
            cur = next2;
        }
        return Ok((Value::Dict(pairs), cur));
    }

    // Fixed negative integer
    if tag >= INT_NEG_FIXED_START && tag < INT_NEG_FIXED_START + INT_NEG_FIXED_COUNT {
        let n = -((tag - INT_NEG_FIXED_START) as i64) - 1;
        return Ok((Value::Int(n), pos + 1));
    }

    // Named type tags
    match tag {
        CHR_NONE => Ok((Value::None, pos + 1)),
        CHR_TRUE => Ok((Value::Bool(true), pos + 1)),
        CHR_FALSE => Ok((Value::Bool(false), pos + 1)),

        CHR_INT => {
            // Big integer encoded as ASCII digits terminated by 'e'
            let start = pos + 1;
            let end = data[start..]
                .iter()
                .position(|&b| b == b'e')
                .ok_or(RencodeError::UnexpectedEof)?
                + start;
            let s = std::str::from_utf8(&data[start..end]).map_err(|_| RencodeError::InvalidUtf8)?;
            let n: i64 = s.parse().map_err(|_| RencodeError::IntegerOverflow)?;
            Ok((Value::Int(n), end + 1))
        }

        CHR_INT1 => {
            let b = *data.get(pos + 1).ok_or(RencodeError::UnexpectedEof)?;
            Ok((Value::Int(b as i8 as i64), pos + 2))
        }
        CHR_INT2 => {
            let bytes = data.get(pos + 1..pos + 3).ok_or(RencodeError::UnexpectedEof)?;
            let n = i16::from_be_bytes([bytes[0], bytes[1]]);
            Ok((Value::Int(n as i64), pos + 3))
        }
        CHR_INT4 => {
            let bytes = data.get(pos + 1..pos + 5).ok_or(RencodeError::UnexpectedEof)?;
            let n = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Ok((Value::Int(n as i64), pos + 5))
        }
        CHR_INT8 => {
            let bytes = data.get(pos + 1..pos + 9).ok_or(RencodeError::UnexpectedEof)?;
            let n = i64::from_be_bytes(bytes.try_into().unwrap());
            Ok((Value::Int(n), pos + 9))
        }

        CHR_FLOAT32 => {
            let bytes = data.get(pos + 1..pos + 5).ok_or(RencodeError::UnexpectedEof)?;
            let f = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Ok((Value::Float32(f), pos + 5))
        }
        CHR_FLOAT64 => {
            let bytes = data.get(pos + 1..pos + 9).ok_or(RencodeError::UnexpectedEof)?;
            let f = f64::from_be_bytes(bytes.try_into().unwrap());
            Ok((Value::Float64(f), pos + 9))
        }

        CHR_LIST => {
            let mut items = Vec::new();
            let mut cur = pos + 1;
            loop {
                if data.get(cur) == Some(&CHR_TERM) {
                    cur += 1;
                    break;
                }
                let (v, next) = decode_from(data, cur, depth + 1)?;
                items.push(v);
                cur = next;
            }
            Ok((Value::List(items), cur))
        }

        CHR_DICT => {
            let mut pairs = Vec::new();
            let mut cur = pos + 1;
            loop {
                if data.get(cur) == Some(&CHR_TERM) {
                    cur += 1;
                    break;
                }
                let (k, next) = decode_from(data, cur, depth + 1)?;
                let (v, next2) = decode_from(data, next, depth + 1)?;
                pairs.push((k, v));
                cur = next2;
            }
            Ok((Value::Dict(pairs), cur))
        }

        // Variable-length string: digits + ':' + bytes
        b if b.is_ascii_digit() => {
            let start = pos;
            let colon = data[start..]
                .iter()
                .position(|&b| b == b':')
                .ok_or(RencodeError::UnexpectedEof)?
                + start;
            let len_str = std::str::from_utf8(&data[start..colon])
                .map_err(|_| RencodeError::InvalidUtf8)?;
            let len: usize = len_str.parse().map_err(|_| RencodeError::IntegerOverflow)?;
            let data_start = colon + 1;
            let data_end = data_start + len;
            if data.len() < data_end {
                return Err(RencodeError::UnexpectedEof);
            }
            let bytes = data[data_start..data_end].to_vec();
            let value = match String::from_utf8(bytes.clone()) {
                Ok(s) => Value::String(s),
                Err(_) => Value::Bytes(bytes),
            };
            Ok((value, data_end))
        }

        other => Err(RencodeError::UnknownTag(other)),
    }
}

// ---------------------------------------------------------------------------
// JSON conversion
// ---------------------------------------------------------------------------

/// Convert a rencode [`Value`] to a [`serde_json::Value`].
/// Dict keys that are not strings are rendered via their `Debug` representation.
/// Binary byte sequences are base64-encoded.
pub fn value_to_json(v: Value) -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    match v {
        Value::None => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(b),
        Value::Int(n) => serde_json::Value::Number(n.into()),
        Value::Float32(f) => serde_json::json!(f),
        Value::Float64(f) => serde_json::json!(f),
        Value::String(s) => serde_json::Value::String(s),
        Value::Bytes(b) => serde_json::Value::String(BASE64.encode(b)),
        Value::List(items) => {
            serde_json::Value::Array(items.into_iter().map(value_to_json).collect())
        }
        Value::Dict(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                let key = match k {
                    Value::String(s) => s,
                    other => format!("{other:?}"),
                };
                map.insert(key, value_to_json(v));
            }
            serde_json::Value::Object(map)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: Value) {
        let encoded = encode(&v);
        let decoded = decode(&encoded).expect("decode failed");
        assert_eq!(v, decoded);
    }

    #[test]
    fn test_none() { roundtrip(Value::None); }

    #[test]
    fn test_bool() {
        roundtrip(Value::Bool(true));
        roundtrip(Value::Bool(false));
    }

    #[test]
    fn test_integers() {
        for n in [0i64, 1, 43, 44, -1, -32, -33, 127, -128, 32767, -32768, i32::MAX as i64, i64::MIN] {
            roundtrip(Value::Int(n));
        }
    }

    #[test]
    fn test_string() {
        roundtrip(Value::String(String::new()));
        roundtrip(Value::String("hello".into()));
        roundtrip(Value::String("a".repeat(64)));
    }

    #[test]
    fn test_list() {
        roundtrip(Value::List(vec![
            Value::Int(1),
            Value::String("two".into()),
            Value::Bool(true),
            Value::None,
        ]));
    }

    #[test]
    fn test_dict() {
        // Small dict — uses fixed dict encoding (< 25 entries)
        roundtrip(Value::Dict(vec![
            (Value::String("key".into()), Value::Int(42)),
        ]));
        // Dict with 24 entries — still fixed
        let large = (0..24).map(|i| (Value::Int(i), Value::Bool(true))).collect();
        roundtrip(Value::Dict(large));
        // Dict with 25 entries — uses CHR_DICT + CHR_TERM
        let overflow = (0..25).map(|i| (Value::Int(i), Value::Bool(false))).collect();
        roundtrip(Value::Dict(overflow));
    }

    #[test]
    fn test_nested() {
        roundtrip(Value::List(vec![
            Value::Int(1),
            Value::List(vec![Value::String("inner".into())]),
            Value::Dict(vec![(Value::String("k".into()), Value::Bool(false))]),
        ]));
    }
}
