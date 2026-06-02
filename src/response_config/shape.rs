// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! The pure JSON shaping transform. Given a tool's output [`Value`](serde_json::Value) and a
//! [`ResponseConfig`], produce the serialized string the consumer asked for — minified or
//! pretty whitespace, optionally sparse (a one-time `defaults` block with per-row default
//! fields omitted). No I/O; fully unit-testable.

use serde_json::{Map, Value};

use super::{ResponseConfig, Whitespace};

/// One entry in [`TORRENT_DEFAULTS`]: a field name and a constructor for its default value.
/// A constructor (rather than a literal) keeps the default a runtime `Value` without needing a
/// `const`-compatible `Value`.
type DefaultEntry = (&'static str, fn() -> Value);

/// The v1 sparse default set for torrent rows, from the measured distribution in issue #9.
/// A field is omitted from a row only when (a) every row carries it and (b) its value equals
/// the default here, so the consumer reconstructs a row as `{...defaults, ...row}` losslessly.
const TORRENT_DEFAULTS: &[DefaultEntry] = &[
    ("download_payload_rate", || Value::from(0)),
    ("eta", || Value::from(0)),
    ("label", || Value::from("")),
    ("progress", || Value::from(100.0)),
    ("state", || Value::from("Seeding")),
    ("upload_payload_rate", || Value::from(0)),
];

/// Shape a tool's JSON output for the declared consumer. Pure transform; never touches I/O.
pub(crate) fn shape_response(value: Value, cfg: &ResponseConfig) -> String {
    let value = if cfg.shape.sparse {
        sparsify(value)
    } else {
        value
    };
    let serialized = match cfg.shape.whitespace {
        Whitespace::Minified => serde_json::to_string(&value),
        Whitespace::Pretty => serde_json::to_string_pretty(&value),
    };
    serialized.unwrap_or_default()
}

/// Apply the sparse transform: emit a sibling `defaults` block and omit per-row default-valued
/// fields. Operates only on a `{ "torrents": { <hash>: {fields} }, ... }`-shaped object — i.e.
/// `list_torrents` output and the `deluge://torrents` resource (which is wrapped in that
/// envelope). Any other shape passes through unchanged, including the bare `{ <hash>: {fields} }`
/// map that `get_torrent_status` (batch) and the single-torrent resource emit — sparse only
/// applies to the explicit `torrents` envelope.
fn sparsify(value: Value) -> Value {
    let Value::Object(mut top) = value else {
        return value;
    };
    // Require a "torrents" object whose every value is itself an object.
    let is_torrent_map = top
        .get("torrents")
        .and_then(Value::as_object)
        .is_some_and(|m| !m.is_empty() && m.values().all(Value::is_object));
    if !is_torrent_map {
        return Value::Object(top);
    }

    // A default key is eligible only if EVERY row carries it; otherwise omitting it and
    // recovering from `defaults` could add a key a row never had (not lossless).
    let rows = top["torrents"].as_object().unwrap();
    let eligible: Vec<(&str, Value)> = TORRENT_DEFAULTS
        .iter()
        .filter(|(key, _)| rows.values().all(|row| row.get(*key).is_some()))
        .map(|(key, mk)| (*key, mk()))
        .collect();

    if eligible.is_empty() {
        return Value::Object(top);
    }

    // Omit each eligible field from rows where it equals the default.
    if let Some(Value::Object(rows)) = top.get_mut("torrents") {
        for row in rows.values_mut() {
            if let Value::Object(fields) = row {
                for (key, default) in &eligible {
                    if fields.get(*key).is_some_and(|v| value_eq(v, default)) {
                        fields.remove(*key);
                    }
                }
            }
        }
    }

    // Emit the defaults block as a sibling of "torrents".
    let defaults: Map<String, Value> = eligible
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    top.insert("defaults".to_string(), Value::Object(defaults));
    Value::Object(top)
}

/// Equality for default comparison. Numbers compare numerically so a serde integer `100` and a
/// float `100.0` are treated as equal (Deluge may send either); other values compare directly.
fn value_eq(a: &Value, b: &Value) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response_config::{IdSelector, Format, ShapeOpts};
    use serde_json::json;

    fn cfg(whitespace: Whitespace, sparse: bool) -> ResponseConfig {
        ResponseConfig {
            format: Format::Json,
            shape: ShapeOpts { whitespace, sparse },
            ids: IdSelector::Full,
        }
    }

    fn sample() -> Value {
        json!({
            "total": 2,
            "torrents": {
                "aaaa": {
                    "name": "A", "save_path": "/data", "total_size": 100,
                    "state": "Seeding", "progress": 100.0, "label": "",
                    "eta": 0, "download_payload_rate": 0, "upload_payload_rate": 0
                },
                "bbbb": {
                    "name": "B", "save_path": "/data", "total_size": 200,
                    "state": "Downloading", "progress": 42.5, "label": "tv",
                    "eta": 99, "download_payload_rate": 500, "upload_payload_rate": 0
                }
            }
        })
    }

    #[test]
    fn pretty_is_byte_identical_to_to_string_pretty() {
        let v = sample();
        let got = shape_response(v.clone(), &cfg(Whitespace::Pretty, false));
        assert_eq!(got, serde_json::to_string_pretty(&v).unwrap());
    }

    #[test]
    fn minified_has_no_whitespace() {
        let got = shape_response(sample(), &cfg(Whitespace::Minified, false));
        assert!(!got.contains('\n'));
        assert!(!got.contains("  "));
    }

    #[test]
    fn sparse_emits_defaults_and_omits_defaulted_fields() {
        let got = shape_response(sample(), &cfg(Whitespace::Pretty, true));
        let parsed: Value = serde_json::from_str(&got).unwrap();

        // defaults block present with the full v1 set.
        let defaults = parsed["defaults"].as_object().unwrap();
        assert_eq!(defaults["state"], json!("Seeding"));
        assert_eq!(defaults["progress"], json!(100.0));

        // Row "aaaa" matched all defaults → those fields omitted, content kept.
        let a = parsed["torrents"]["aaaa"].as_object().unwrap();
        assert!(!a.contains_key("state"));
        assert!(!a.contains_key("progress"));
        assert!(!a.contains_key("download_payload_rate"));
        assert_eq!(a["name"], json!("A"));

        // Row "bbbb" differs → non-default fields kept; the one matching default (ul_rate=0) omitted.
        let b = parsed["torrents"]["bbbb"].as_object().unwrap();
        assert_eq!(b["state"], json!("Downloading"));
        assert_eq!(b["progress"], json!(42.5));
        assert!(!b.contains_key("upload_payload_rate"));
    }

    #[test]
    fn sparse_round_trips_to_full_rows() {
        // Merging defaults into each sparse row must reproduce the original rows exactly.
        let original = sample();
        let shaped: Value =
            serde_json::from_str(&shape_response(original.clone(), &cfg(Whitespace::Minified, true)))
                .unwrap();

        let defaults = shaped["defaults"].as_object().unwrap();
        for (hash, orig_row) in original["torrents"].as_object().unwrap() {
            let sparse_row = shaped["torrents"][hash].as_object().unwrap();
            // row = {...defaults, ...sparse_row}
            let mut merged = defaults.clone();
            for (k, v) in sparse_row {
                merged.insert(k.clone(), v.clone());
            }
            assert_eq!(
                &Value::Object(merged),
                orig_row,
                "row {hash} did not round-trip"
            );
        }
    }

    /// T7 lean regression guard: with the default config, every shape a handler actually emits
    /// must serialize byte-identically to the pre-change `to_string_pretty` call. Covers the
    /// add_torrent array, the remove/set_label flat object, and the pause/resume_label object.
    #[test]
    fn default_config_is_byte_identical_for_handler_output_shapes() {
        let shapes = [
            // add_torrent batch (array of per-source results)
            json!([{"info_hash": "aaaa"}, {"error": "bad source"}]),
            // remove_torrent / set_torrent_label multi (flat hash -> status object)
            json!({"aaaa": "ok", "bbbb": {"error": "not found"}}),
            // bulk_act_on_label (pause/resume_label) summary object
            json!({"label": "tv", "action": "paused", "count": 3,
                   "info_hashes": ["aaaa", "bbbb", "cccc"]}),
            // get_torrent_status single (hash -> fields)
            json!({"aaaa": {"name": "A", "files": [{"index": 0, "path": "a.mkv"}]}}),
        ];
        let default = ResponseConfig::default();
        for v in shapes {
            assert_eq!(
                shape_response(v.clone(), &default),
                serde_json::to_string_pretty(&v).unwrap(),
                "default-config output drifted from to_string_pretty for {v}"
            );
        }
    }

    #[test]
    fn non_torrent_shape_passes_through_under_sparse() {
        let scalar = json!({"free_space": 12345});
        let got = shape_response(scalar.clone(), &cfg(Whitespace::Pretty, true));
        assert_eq!(got, serde_json::to_string_pretty(&scalar).unwrap());

        let arr = json!([1, 2, 3]);
        let got = shape_response(arr.clone(), &cfg(Whitespace::Minified, true));
        assert_eq!(got, serde_json::to_string(&arr).unwrap());
    }

    #[test]
    fn sparse_skips_default_key_absent_from_some_rows() {
        // If a default key isn't present in every row, it must not be declared/omitted —
        // otherwise the merge would add a key a row never had.
        let v = json!({
            "torrents": {
                "aaaa": { "name": "A", "state": "Seeding" },
                "bbbb": { "name": "B" }   // no "state"
            }
        });
        let shaped: Value =
            serde_json::from_str(&shape_response(v, &cfg(Whitespace::Minified, true))).unwrap();
        // "state" not eligible (absent from bbbb) → not in defaults, kept in aaaa.
        assert!(shaped.get("defaults").is_none_or(|d| d.get("state").is_none()));
        assert_eq!(shaped["torrents"]["aaaa"]["state"], json!("Seeding"));
    }
}
