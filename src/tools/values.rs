// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

//! Stateless helpers for reading, filtering, sorting, and serializing the
//! [`Value`] dicts Deluge returns for torrent status. Kept as `pub(super)`
//! methods on [`DelugeServer`] so the tool handlers call them as `Self::…`.

use rmcp::serde_json;

use super::params::{SortField, SortOrder};
use super::DelugeServer;
use crate::rencode::Value;

impl DelugeServer {
    /// Extract a named field from a torrent status Value (a `Value::Dict`).
    /// Returns None for non-Dict values or missing keys.
    pub(super) fn extract_field<'a>(v: &'a Value, field: &str) -> Option<&'a Value> {
        if let Value::Dict(fields) = v {
            for (k, val) in fields {
                if matches!(k, Value::String(s) if s == field) {
                    return Some(val);
                }
            }
        }
        None
    }

    /// Extract a string field. Non-string or missing fields return None.
    pub(super) fn extract_str<'a>(v: &'a Value, field: &str) -> Option<&'a str> {
        match Self::extract_field(v, field) {
            Some(Value::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Extract a numeric field as f64. Coerces Int, Float32, and Float64.
    /// Non-numeric or missing fields return None.
    pub(super) fn extract_num(v: &Value, field: &str) -> Option<f64> {
        match Self::extract_field(v, field) {
            Some(Value::Int(i)) => Some(*i as f64),
            Some(Value::Float32(f)) => Some(*f as f64),
            Some(Value::Float64(f)) => Some(*f),
            _ => None,
        }
    }

    /// Extract the torrent name. Used as a stable tie-breaker during sort.
    pub(super) fn torrent_name(v: &Value) -> &str {
        Self::extract_str(v, "name").unwrap_or("")
    }

    /// Compare two torrent dicts by a numeric field. Missing or non-numeric values
    /// sort as Equal. Uses partial_cmp; NaN compares as Equal.
    pub(super) fn cmp_num(a: &Value, b: &Value, field: &str) -> std::cmp::Ordering {
        let av = Self::extract_num(a, field);
        let bv = Self::extract_num(b, field);
        match (av, bv) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
            _ => std::cmp::Ordering::Equal,
        }
    }

    /// Retain only torrent pairs whose `save_path` contains `needle` (case-insensitive).
    /// Pairs missing a string `save_path` are dropped.
    pub(super) fn filter_by_save_path_substring(pairs: &mut Vec<(Value, Value)>, needle: &str) {
        let needle = needle.to_lowercase();
        pairs.retain(|(_, v)| {
            Self::extract_str(v, "save_path")
                .map(|s| s.to_lowercase().contains(&needle))
                .unwrap_or(false)
        });
    }

    /// Sort torrent pairs by `sort_by` in `sort_order`, with name-asc as a stable
    /// tiebreaker. The tiebreak is preserved under desc — only the primary
    /// comparator is inverted, so torrents tied on the primary key still come back
    /// in name-asc order, giving deterministic pagination in both directions.
    pub(super) fn sort_torrent_pairs(
        pairs: &mut [(Value, Value)],
        sort_by: SortField,
        sort_order: SortOrder,
    ) {
        pairs.sort_by(|(_, a), (_, b)| {
            use std::cmp::Ordering;
            let primary = match sort_by {
                SortField::Name => Self::torrent_name(a).cmp(Self::torrent_name(b)),
                SortField::SavePath => Self::extract_str(a, "save_path")
                    .unwrap_or("")
                    .cmp(Self::extract_str(b, "save_path").unwrap_or("")),
                SortField::Progress => Self::cmp_num(a, b, "progress"),
                SortField::TotalSize => Self::cmp_num(a, b, "total_size"),
                SortField::DownloadPayloadRate => Self::cmp_num(a, b, "download_payload_rate"),
                SortField::UploadPayloadRate => Self::cmp_num(a, b, "upload_payload_rate"),
                SortField::Eta => Self::cmp_num(a, b, "eta"),
                SortField::TimeAdded => Self::cmp_num(a, b, "time_added"),
                SortField::Ratio => Self::cmp_num(a, b, "ratio"),
            };
            let primary = if matches!(sort_order, SortOrder::Desc) {
                primary.reverse()
            } else {
                primary
            };
            match primary {
                Ordering::Equal => Self::torrent_name(a).cmp(Self::torrent_name(b)),
                other => other,
            }
        });
    }

    /// Strip helper keys from a torrent status `Value::Dict` in place. No-op for
    /// non-Dict values or when `helper_keys` is empty.
    pub(super) fn strip_helper_keys(v: &mut Value, helper_keys: &[&str]) {
        if helper_keys.is_empty() {
            return;
        }
        if let Value::Dict(ref mut fields) = v {
            fields.retain(|(fk, _)| match fk {
                Value::String(s) => !helper_keys.iter().any(|h| h == s),
                _ => true,
            });
        }
    }

    /// Serialize a Deluge [`Value`] to a compact JSON string.
    pub(super) fn value_to_json_string(v: Value) -> String {
        serde_json::to_string(&crate::rencode::value_to_json(v)).unwrap_or_default()
    }

    /// Pagination header for `list_torrents`. `next_offset` appears only when a further
    /// page exists *and* this page advanced: a `limit` of 0 is a count-only request, so
    /// it reports `has_more` truthfully but gives no `next_offset` a loop could spin on.
    pub(super) fn page_summary(
        total: usize,
        offset: usize,
        returned: usize,
        limit: usize,
    ) -> serde_json::Map<String, serde_json::Value> {
        let has_more = offset.saturating_add(returned) < total;
        let mut out = serde_json::Map::new();
        out.insert("total".into(), serde_json::json!(total));
        out.insert("returned".into(), serde_json::json!(returned));
        out.insert("offset".into(), serde_json::json!(offset));
        out.insert("limit".into(), serde_json::json!(limit));
        out.insert("has_more".into(), serde_json::json!(has_more));
        if has_more && returned > 0 {
            out.insert("next_offset".into(), serde_json::json!(offset + returned));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a torrent dict with the given fields. Numeric values default to
    /// `Value::Float64` so they round-trip through `cmp_num` like Deluge's wire
    /// values.
    fn td(name: &str, save_path: &str, num_fields: &[(&str, f64)]) -> Value {
        let mut fields: Vec<(Value, Value)> = vec![
            (Value::String("name".into()), Value::String(name.into())),
            (
                Value::String("save_path".into()),
                Value::String(save_path.into()),
            ),
        ];
        for (k, v) in num_fields {
            fields.push((Value::String((*k).into()), Value::Float64(*v)));
        }
        Value::Dict(fields)
    }

    fn pair(hash: &str, dict: Value) -> (Value, Value) {
        (Value::String(hash.into()), dict)
    }

    fn names(pairs: &[(Value, Value)]) -> Vec<&str> {
        pairs
            .iter()
            .map(|(_, v)| DelugeServer::torrent_name(v))
            .collect()
    }

    #[test]
    fn page_summary_limit_zero_is_count_only() {
        let s = DelugeServer::page_summary(23, 0, 0, 0);
        assert_eq!(s["total"], 23);
        assert_eq!(s["returned"], 0);
        assert_eq!(s["limit"], 0);
        assert_eq!(s["has_more"], true);
        assert!(!s.contains_key("next_offset"), "count-only must not invite paging");
    }

    #[test]
    fn page_summary_pages_forward() {
        let s = DelugeServer::page_summary(23, 10, 10, 10);
        assert_eq!(s["has_more"], true);
        assert_eq!(s["next_offset"], 20);

        let last = DelugeServer::page_summary(23, 20, 3, 10);
        assert_eq!(last["has_more"], false);
        assert!(!last.contains_key("next_offset"));
    }

    #[test]
    fn filter_by_save_path_substring_is_case_insensitive() {
        let mut pairs = vec![
            pair("a", td("AlphaBook", "/srv/Media/audiobooks", &[])),
            pair("b", td("BetaBook", "/srv/media/ebooks", &[])),
            pair("c", td("GammaBook", "/srv/data/other", &[])),
            // Missing save_path: dropped.
            pair(
                "d",
                Value::Dict(vec![(
                    Value::String("name".into()),
                    Value::String("DeltaBook".into()),
                )]),
            ),
        ];
        DelugeServer::filter_by_save_path_substring(&mut pairs, "MEDIA");
        assert_eq!(names(&pairs), vec!["AlphaBook", "BetaBook"]);
    }

    #[test]
    fn filter_by_save_path_substring_empty_needle_keeps_all_with_save_path() {
        let mut pairs = vec![
            pair("a", td("Alpha", "/x", &[])),
            pair("b", td("Beta", "/y", &[])),
        ];
        let before = pairs.len();
        DelugeServer::filter_by_save_path_substring(&mut pairs, "");
        assert_eq!(pairs.len(), before);
    }

    #[test]
    fn sort_torrent_pairs_asc_by_total_size_tiebreaks_by_name() {
        let mut pairs = vec![
            pair("a", td("Charlie", "/x", &[("total_size", 100.0)])),
            pair("b", td("Alpha", "/x", &[("total_size", 100.0)])),
            pair("c", td("Bravo", "/x", &[("total_size", 50.0)])),
        ];
        DelugeServer::sort_torrent_pairs(&mut pairs, SortField::TotalSize, SortOrder::Asc);
        // 50 first, then the 100s in name-asc order.
        assert_eq!(names(&pairs), vec!["Bravo", "Alpha", "Charlie"]);
    }

    #[test]
    fn sort_torrent_pairs_desc_inverts_primary_only() {
        // Regression test: under desc the primary comparator must be inverted,
        // but the name-asc tiebreak must be preserved. A naive `pairs.reverse()`
        // after an asc sort would invert both, making tied groups come back in
        // name-desc order.
        let mut pairs = vec![
            pair("a", td("Charlie", "/x", &[("total_size", 100.0)])),
            pair("b", td("Alpha", "/x", &[("total_size", 100.0)])),
            pair("c", td("Bravo", "/x", &[("total_size", 50.0)])),
        ];
        DelugeServer::sort_torrent_pairs(&mut pairs, SortField::TotalSize, SortOrder::Desc);
        // 100s first (desc on primary), but tied group is still Alpha < Charlie.
        assert_eq!(names(&pairs), vec!["Alpha", "Charlie", "Bravo"]);
    }

    #[test]
    fn sort_torrent_pairs_desc_by_name_is_pure_name_desc() {
        // When the primary key IS name, desc gives a straight name-desc ordering.
        let mut pairs = vec![
            pair("a", td("Alpha", "/x", &[])),
            pair("b", td("Charlie", "/x", &[])),
            pair("c", td("Bravo", "/x", &[])),
        ];
        DelugeServer::sort_torrent_pairs(&mut pairs, SortField::Name, SortOrder::Desc);
        assert_eq!(names(&pairs), vec!["Charlie", "Bravo", "Alpha"]);
    }

    #[test]
    fn sort_torrent_pairs_missing_numeric_fields_sort_as_equal() {
        // When neither side has the numeric field, primary is Equal and the
        // tiebreak (name-asc) decides regardless of asc/desc on the primary.
        let mut pairs = vec![
            pair("a", td("Charlie", "/x", &[])),
            pair("b", td("Alpha", "/x", &[])),
            pair("c", td("Bravo", "/x", &[])),
        ];
        DelugeServer::sort_torrent_pairs(&mut pairs, SortField::Ratio, SortOrder::Desc);
        assert_eq!(names(&pairs), vec!["Alpha", "Bravo", "Charlie"]);
    }

    #[test]
    fn strip_helper_keys_removes_listed_keys_only() {
        let mut v = td(
            "Alpha",
            "/x",
            &[("total_size", 100.0), ("time_added", 12345.0), ("ratio", 1.5)],
        );
        DelugeServer::strip_helper_keys(&mut v, &["time_added", "ratio"]);
        let Value::Dict(fields) = &v else {
            panic!("expected Dict");
        };
        let keys: Vec<&str> = fields
            .iter()
            .filter_map(|(k, _)| match k {
                Value::String(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert!(keys.contains(&"name"));
        assert!(keys.contains(&"save_path"));
        assert!(keys.contains(&"total_size"));
        assert!(!keys.contains(&"time_added"));
        assert!(!keys.contains(&"ratio"));
    }

    #[test]
    fn strip_helper_keys_empty_list_is_noop() {
        let mut v = td("Alpha", "/x", &[("time_added", 12345.0)]);
        let before = v.clone();
        DelugeServer::strip_helper_keys(&mut v, &[]);
        // Field set is identical.
        let Value::Dict(after_fields) = &v else {
            panic!("expected Dict");
        };
        let Value::Dict(before_fields) = &before else {
            panic!("expected Dict");
        };
        assert_eq!(before_fields.len(), after_fields.len());
    }
}
