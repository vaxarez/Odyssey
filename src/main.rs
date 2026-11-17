//! Simple log analyzer.
//!
//! Usage: odyssey <logfile> [--top N]
//!
//! Expects lines in the form: `YYYY-MM-DDTHH:MM:SS LEVEL component: message`.
//! Malformed lines are counted and skipped.

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process;

#[derive(Default, Debug)]
struct Report {
    total_lines: usize,
    parsed_lines: usize,
    malformed_lines: usize,
    levels: HashMap<String, usize>,
    components: HashMap<String, usize>,
    failed_logins: usize,
    successful_logins: usize,
    failed_by_ip: HashMap<String, usize>,
    first_ts: Option<String>,
    last_ts: Option<String>,
}

/// Classification of a login-related record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginOutcome {
    Failed,
    Succeeded,
}

/// A single normalized log record, independent of the source format.
///
/// Parsers are responsible for filling in `login` and `source_ip`; the
/// report only counts entries and never inspects format-specific text.
#[derive(Debug)]
struct Entry {
    timestamp: String,
    level: String,
    component: String,
    /// `Some` when the record is a login attempt.
    login: Option<LoginOutcome>,
    /// Source address of a failed login, when one could be extracted.
    source_ip: Option<String>,
}

impl Report {
    /// Count a line that could not be parsed.
    fn record_malformed(&mut self) {
        self.total_lines += 1;
        self.malformed_lines += 1;
    }

    /// Count a successfully parsed entry.
    fn record(&mut self, entry: &Entry) {
        self.total_lines += 1;
        self.parsed_lines += 1;

        *self.levels.entry(entry.level.clone()).or_insert(0) += 1;
        *self.components.entry(entry.component.clone()).or_insert(0) += 1;

        if self
            .first_ts
            .as_deref()
            .is_none_or(|t| entry.timestamp.as_str() < t)
        {
            self.first_ts = Some(entry.timestamp.clone());
        }
        if self
            .last_ts
            .as_deref()
            .is_none_or(|t| entry.timestamp.as_str() > t)
        {
            self.last_ts = Some(entry.timestamp.clone());
        }

        match entry.login {
            Some(LoginOutcome::Failed) => {
                self.failed_logins += 1;
                if let Some(ip) = &entry.source_ip {
                    *self.failed_by_ip.entry(ip.clone()).or_insert(0) += 1;
                }
            }
            Some(LoginOutcome::Succeeded) => self.successful_logins += 1,
            None => {}
        }
    }
}

/// Classify a plain-text message by its wording.
fn classify_text_login(message: &str) -> Option<LoginOutcome> {
    let msg = message.to_ascii_lowercase();
    if msg.contains("failed password") || msg.contains("login failed") {
        Some(LoginOutcome::Failed)
    } else if msg.contains("accepted password") || msg.contains("login succeeded") {
        Some(LoginOutcome::Succeeded)
    } else {
        None
    }
}

/// Parse `YYYY-MM-DDTHH:MM:SS LEVEL component: message`.
fn parse_line(line: &str) -> Option<Entry> {
    let (timestamp, rest) = line.split_once(' ')?;
    if timestamp.len() != 19 || !timestamp.contains('T') {
        return None;
    }
    let (level, rest) = rest.split_once(' ')?;
    let (component, message) = rest.split_once(": ")?;
    if level.is_empty() || component.is_empty() {
        return None;
    }

    let login = classify_text_login(message);
    let source_ip = match login {
        Some(LoginOutcome::Failed) => extract_ip(message).map(str::to_string),
        _ => None,
    };

    Some(Entry {
        timestamp: timestamp.to_string(),
        level: level.to_string(),
        component: component.to_string(),
        login,
        source_ip,
    })
}

/// Extract the IPv4 address that follows "from " in a login message.
fn extract_ip(message: &str) -> Option<&str> {
    let idx = message.find(" from ")?;
    let ip = message[idx + 6..].split_whitespace().next()?;
    if ip.split('.').count() == 4 && ip.split('.').all(|p| p.parse::<u8>().is_ok()) {
        Some(ip)
    } else {
        None
    }
}

fn analyze<R: BufRead>(reader: R) -> io::Result<Report> {
    let mut report = Report::default();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        match parse_line(line) {
            Some(entry) => report.record(&entry),
            None => report.record_malformed(),
        }
    }

    Ok(report)
}

fn sorted_desc(map: &HashMap<String, usize>) -> Vec<(&String, &usize)> {
    let mut v: Vec<_> = map.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    v
}

fn print_report(report: &Report, top: usize) {
    println!("=== Log analysis ===");
    println!("Total lines:      {}", report.total_lines);
    println!("Parsed lines:     {}", report.parsed_lines);
    println!("Malformed lines:  {}", report.malformed_lines);
    if let (Some(first), Some(last)) = (&report.first_ts, &report.last_ts) {
        println!("Time range:       {first} .. {last}");
    }

    println!("\n-- Levels --");
    for (level, count) in sorted_desc(&report.levels) {
        println!("  {level:<8} {count}");
    }

    println!("\n-- Top {top} components --");
    for (component, count) in sorted_desc(&report.components).into_iter().take(top) {
        println!("  {component:<20} {count}");
    }

    println!("\n-- Logins --");
    println!("  Failed:     {}", report.failed_logins);
    println!("  Successful: {}", report.successful_logins);

    if !report.failed_by_ip.is_empty() {
        println!("\n-- Top {top} failing source IPs --");
        for (ip, count) in sorted_desc(&report.failed_by_ip).into_iter().take(top) {
            println!("  {ip:<18} {count}");
        }
    }
}

fn usage() -> ! {
    eprintln!("Usage: odyssey <logfile> [--top N]");
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut path: Option<String> = None;
    let mut top: usize = 5;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--top" => {
                i += 1;
                top = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "-h" | "--help" => usage(),
            other if path.is_none() => path = Some(other.to_string()),
            _ => usage(),
        }
        i += 1;
    }

    let Some(path) = path else { usage() };

    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: cannot open '{path}': {e}");
            process::exit(1);
        }
    };

    match analyze(BufReader::new(file)) {
        Ok(report) => print_report(&report, top),
        Err(e) => {
            eprintln!("error: failed reading '{path}': {e}");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_line() {
        let e = parse_line("2026-11-17T10:00:01 WARN sshd: Failed password for bob from 1.2.3.4")
            .unwrap();
        assert_eq!(e.timestamp, "2026-11-17T10:00:01");
        assert_eq!(e.level, "WARN");
        assert_eq!(e.component, "sshd");
        assert_eq!(e.login, Some(LoginOutcome::Failed));
        assert_eq!(e.source_ip.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn rejects_malformed_line() {
        assert!(parse_line("garbage line without format").is_none());
    }

    #[test]
    fn extracts_ip() {
        assert_eq!(extract_ip("Failed password for bob from 10.0.0.9 port 22"), Some("10.0.0.9"));
        assert_eq!(extract_ip("no address here"), None);
        assert_eq!(extract_ip("from notanip"), None);
    }

    #[test]
    fn counts_logins() {
        let input = "\
2026-11-17T10:00:00 WARN sshd: Failed password for a from 1.1.1.1
2026-11-17T10:00:01 WARN sshd: Failed password for a from 1.1.1.1
2026-11-17T10:00:02 INFO sshd: Accepted password for a from 2.2.2.2
2026-11-17T10:00:03 ERROR app: login failed for user x: invalid credentials
bad line
";
        let r = analyze(input.as_bytes()).unwrap();
        assert_eq!(r.total_lines, 5);
        assert_eq!(r.parsed_lines, 4);
        assert_eq!(r.malformed_lines, 1);
        assert_eq!(r.failed_logins, 3);
        assert_eq!(r.successful_logins, 1);
        assert_eq!(r.failed_by_ip.get("1.1.1.1"), Some(&2));
        assert_eq!(r.first_ts.as_deref(), Some("2026-11-17T10:00:00"));
        assert_eq!(r.last_ts.as_deref(), Some("2026-11-17T10:00:03"));
    }

    #[test]
    fn rejects_timestamp_of_wrong_length() {
        assert!(parse_line("2026-11-17 WARN sshd: msg").is_none());
    }

    #[test]
    fn rejects_timestamp_without_t_separator() {
        assert!(parse_line("2026-11-17_10:00:00 INFO sshd: msg").is_none());
    }

    #[test]
    fn rejects_missing_component_separator() {
        assert!(parse_line("2026-11-17T10:00:00 INFO sshd no separator").is_none());
    }

    #[test]
    fn rejects_empty_component() {
        assert!(parse_line("2026-11-17T10:00:00 INFO : msg").is_none());
    }

    #[test]
    fn component_ends_at_first_separator() {
        let e = parse_line("2026-11-17T10:00:00 INFO app: Failed password for a: b from 1.2.3.4")
            .unwrap();
        assert_eq!(e.component, "app");
        assert_eq!(e.login, Some(LoginOutcome::Failed));
        assert_eq!(e.source_ip.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn rejects_ip_octet_out_of_range() {
        assert_eq!(extract_ip("Failed password for bob from 256.1.1.1"), None);
    }

    #[test]
    fn rejects_ip_with_too_few_octets() {
        assert_eq!(extract_ip("Failed password for bob from 1.2.3"), None);
    }

    #[test]
    fn extracts_ip_at_end_of_message() {
        assert_eq!(extract_ip("failed from 1.2.3.4"), Some("1.2.3.4"));
    }

    #[test]
    fn failure_detection_is_case_insensitive() {
        let r = analyze("2026-11-17T10:00:00 WARN sshd: FAILED PASSWORD for a from 9.9.9.9\n".as_bytes()).unwrap();
        assert_eq!(r.failed_logins, 1);
        assert_eq!(r.failed_by_ip.get("9.9.9.9"), Some(&1));
    }

    #[test]
    fn failed_login_without_ip_is_counted_but_not_tabulated() {
        let r = analyze("2026-11-17T10:00:00 ERROR app: login failed for user x\n".as_bytes()).unwrap();
        assert_eq!(r.failed_logins, 1);
        assert!(r.failed_by_ip.is_empty());
    }

    #[test]
    fn login_succeeded_is_counted_as_success() {
        let r = analyze("2026-11-17T10:00:00 INFO app: login succeeded for user x\n".as_bytes()).unwrap();
        assert_eq!(r.successful_logins, 1);
        assert_eq!(r.failed_logins, 0);
    }

    #[test]
    fn empty_input_yields_empty_report() {
        let r = analyze("".as_bytes()).unwrap();
        assert_eq!(r.total_lines, 0);
        assert_eq!(r.parsed_lines, 0);
        assert!(r.first_ts.is_none());
        assert!(r.last_ts.is_none());
    }

    #[test]
    fn blank_lines_are_not_counted() {
        let r = analyze("\n\n2026-11-17T10:00:00 INFO a: b\n\n".as_bytes()).unwrap();
        assert_eq!(r.total_lines, 1);
        assert_eq!(r.malformed_lines, 0);
    }

    #[test]
    fn time_range_independent_of_line_order() {
        let input = "2026-11-17T10:00:05 INFO a: x\n2026-11-17T09:00:00 INFO a: y\n2026-11-17T11:00:00 INFO a: z\n";
        let r = analyze(input.as_bytes()).unwrap();
        assert_eq!(r.first_ts.as_deref(), Some("2026-11-17T09:00:00"));
        assert_eq!(r.last_ts.as_deref(), Some("2026-11-17T11:00:00"));
    }

    #[test]
    fn counts_levels_and_components() {
        let input = "\
2026-11-17T10:00:00 INFO sshd: a
2026-11-17T10:00:01 INFO sshd: b
2026-11-17T10:00:02 ERROR app: c
";
        let r = analyze(input.as_bytes()).unwrap();
        assert_eq!(r.levels.get("INFO"), Some(&2));
        assert_eq!(r.levels.get("ERROR"), Some(&1));
        assert_eq!(r.components.get("sshd"), Some(&2));
        assert_eq!(r.components.get("app"), Some(&1));
    }

    #[test]
    fn invalid_utf8_is_an_error() {
        assert!(analyze(&[0xff, 0xfe, 0x0a][..]).is_err());
    }

    #[test]
    fn sorted_desc_orders_by_count_then_name() {
        let mut m = HashMap::new();
        m.insert("beta".to_string(), 2);
        m.insert("alpha".to_string(), 2);
        m.insert("gamma".to_string(), 5);
        let names: Vec<&str> = sorted_desc(&m).into_iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["gamma", "alpha", "beta"]);
    }
}
