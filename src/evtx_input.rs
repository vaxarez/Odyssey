//! Reading Windows Event Log (`.evtx`) files into normalized [`Entry`] values.
//!
//! Each record is rendered to JSON by the `evtx` crate and mapped onto the
//! same `Entry` type the text parser produces. Login classification uses
//! event IDs from the Security provider rather than message wording.

use std::path::Path;

use evtx::EvtxParser;
use serde_json::Value;

use crate::{Entry, LoginOutcome, Report, is_ipv4};

/// Signature at the start of every `.evtx` file.
pub const MAGIC: &[u8; 8] = b"ElfFile\0";

const SECURITY_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";
const EVENT_LOGON_SUCCESS: u64 = 4624;
const EVENT_LOGON_FAILURE: u64 = 4625;

/// Parse every record in an `.evtx` file and count it into `report`.
///
/// Records that cannot be read or mapped are counted as malformed and
/// skipped. Returns an error only if the file cannot be opened as `.evtx`.
pub fn analyze_file(path: &Path, report: &mut Report) -> Result<(), String> {
    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("cannot read '{}' as evtx: {e}", path.display()))?;

    for record in parser.records_json_value() {
        match record {
            Ok(rec) => match entry_from_document(&rec.data) {
                Some(entry) => report.record(&entry),
                None => report.record_malformed(),
            },
            Err(_) => report.record_malformed(),
        }
    }
    Ok(())
}

/// Map one rendered event document (`{"Event": {...}}`) to an [`Entry`].
pub fn entry_from_document(doc: &Value) -> Option<Entry> {
    let event = doc.get("Event")?;
    let system = event.get("System")?;

    // SystemTime looks like "2026-10-27T21:27:54.7395325Z"; keep the
    // fixed-width `YYYY-MM-DDTHH:MM:SS` prefix so ordering matches text logs.
    let system_time = system
        .get("TimeCreated")?
        .get("#attributes")?
        .get("SystemTime")?
        .as_str()?;
    let timestamp = system_time.get(..19)?;
    if !timestamp.contains('T') {
        return None;
    }

    let level = level_name(system.get("Level").and_then(Value::as_u64));

    let provider = system
        .get("Provider")
        .and_then(|p| p.get("#attributes"))
        .and_then(|a| a.get("Name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let event_id = system.get("EventID").and_then(event_id_value);

    let (login, source_ip) = if provider == SECURITY_PROVIDER {
        classify_security_event(event_id, event.get("EventData"))
    } else {
        (None, None)
    };

    Some(Entry {
        timestamp: timestamp.to_string(),
        level: level.to_string(),
        component: provider.to_string(),
        login,
        source_ip,
    })
}

/// Map the numeric Windows event level to the names used in text logs.
fn level_name(level: Option<u64>) -> &'static str {
    match level {
        Some(1) => "CRITICAL",
        Some(2) => "ERROR",
        Some(3) => "WARN",
        Some(0) | Some(4) => "INFO",
        Some(5) => "VERBOSE",
        _ => "UNKNOWN",
    }
}

/// `EventID` is either a bare number or an object with the number in `#text`.
fn event_id_value(v: &Value) -> Option<u64> {
    match v {
        Value::Object(_) => v.get("#text").and_then(scalar_u64),
        other => scalar_u64(other),
    }
}

fn scalar_u64(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

/// Login outcome and source address for a Security-provider event.
fn classify_security_event(
    event_id: Option<u64>,
    event_data: Option<&Value>,
) -> (Option<LoginOutcome>, Option<String>) {
    match event_id {
        Some(EVENT_LOGON_SUCCESS) => (Some(LoginOutcome::Succeeded), None),
        Some(EVENT_LOGON_FAILURE) => {
            let ip = event_data
                .and_then(|d| d.get("IpAddress"))
                .and_then(Value::as_str)
                .filter(|ip| is_ipv4(ip))
                .map(str::to_string);
            (Some(LoginOutcome::Failed), ip)
        }
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn security_event(event_id: Value, ip: Option<&str>) -> Value {
        let mut data = json!({ "TargetUserName": "bob", "LogonType": "3" });
        if let Some(ip) = ip {
            data["IpAddress"] = json!(ip);
        }
        json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": SECURITY_PROVIDER } },
                    "EventID": event_id,
                    "Level": 0,
                    "TimeCreated": { "#attributes": { "SystemTime": "2026-10-27T21:27:54.7395325Z" } }
                },
                "EventData": data
            }
        })
    }

    #[test]
    fn failed_logon_extracts_ip_and_time() {
        let e = entry_from_document(&security_event(json!(4625), Some("10.1.2.3"))).unwrap();
        assert_eq!(e.timestamp, "2026-10-27T21:27:54");
        assert_eq!(e.component, SECURITY_PROVIDER);
        assert_eq!(e.login, Some(LoginOutcome::Failed));
        assert_eq!(e.source_ip.as_deref(), Some("10.1.2.3"));
    }

    #[test]
    fn event_id_as_object_with_text() {
        let id = json!({ "#attributes": { "Qualifiers": 0 }, "#text": 4625 });
        let e = entry_from_document(&security_event(id, Some("10.1.2.3"))).unwrap();
        assert_eq!(e.login, Some(LoginOutcome::Failed));
    }

    #[test]
    fn event_id_as_string() {
        let e = entry_from_document(&security_event(json!("4624"), None)).unwrap();
        assert_eq!(e.login, Some(LoginOutcome::Succeeded));
        assert_eq!(e.source_ip, None);
    }

    #[test]
    fn failed_logon_without_valid_ip_has_no_address() {
        // Windows writes "-" or an IPv6 loopback when there is no IPv4 source.
        for ip in ["-", "::1"] {
            let e = entry_from_document(&security_event(json!(4625), Some(ip))).unwrap();
            assert_eq!(e.login, Some(LoginOutcome::Failed));
            assert_eq!(e.source_ip, None, "ip {ip}");
        }
    }

    #[test]
    fn other_security_events_are_not_logins() {
        let e = entry_from_document(&security_event(json!(4672), Some("10.1.2.3"))).unwrap();
        assert_eq!(e.login, None);
        assert_eq!(e.source_ip, None);
    }

    #[test]
    fn logon_ids_from_other_providers_are_ignored() {
        let mut doc = security_event(json!(4625), Some("10.1.2.3"));
        doc["Event"]["System"]["Provider"]["#attributes"]["Name"] = json!("Some-Other-Provider");
        let e = entry_from_document(&doc).unwrap();
        assert_eq!(e.login, None);
        assert_eq!(e.source_ip, None);
    }

    #[test]
    fn level_numbers_map_to_names() {
        assert_eq!(level_name(Some(1)), "CRITICAL");
        assert_eq!(level_name(Some(2)), "ERROR");
        assert_eq!(level_name(Some(3)), "WARN");
        assert_eq!(level_name(Some(4)), "INFO");
        assert_eq!(level_name(Some(5)), "VERBOSE");
        assert_eq!(level_name(Some(99)), "UNKNOWN");
        assert_eq!(level_name(None), "UNKNOWN");
    }

    #[test]
    fn missing_system_time_is_rejected() {
        let doc = json!({ "Event": { "System": { "EventID": 4625 } } });
        assert!(entry_from_document(&doc).is_none());
    }

    #[test]
    fn missing_provider_is_reported_as_unknown() {
        let doc = json!({
            "Event": {
                "System": {
                    "Level": 2,
                    "TimeCreated": { "#attributes": { "SystemTime": "2026-10-27T21:27:54Z" } }
                }
            }
        });
        let e = entry_from_document(&doc).unwrap();
        assert_eq!(e.component, "unknown");
        assert_eq!(e.level, "ERROR");
    }
}
