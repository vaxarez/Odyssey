//! End-to-end tests: run the compiled binary on inputs written by each test.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output};

const AUTH_LOG: &str = "\
2026-11-17T08:00:01 INFO app: service started on port 8080
2026-11-17T08:00:03 DEBUG app: cache refreshed in 12ms
2026-11-17T08:00:15 WARN sshd: Failed password for root from 203.0.113.7
2026-11-17T08:00:17 WARN sshd: Failed password for root from 203.0.113.7
2026-11-17T08:00:19 WARN sshd: Failed password for admin from 203.0.113.7
2026-11-17T08:00:42 INFO sshd: Accepted password for deploy from 192.0.2.44
2026-11-17T08:01:05 WARN sshd: Failed password for ubuntu from 198.51.100.23
2026-11-17T08:01:07 WARN sshd: Failed password for ubuntu from 198.51.100.23
2026-11-17T08:01:30 INFO sudo: session opened for user root
2026-11-17T08:02:11 DEBUG app: cache refreshed in 9ms
2026-11-17T08:02:45 ERROR app: login failed for user alice: invalid credentials
2026-11-17T08:03:02 WARN sshd: Failed password for root from 203.0.113.7
2026-11-17T08:03:40 INFO sshd: Accepted password for alice from 192.0.2.19
2026-11-17T08:04:12 INFO cron: job nightly-backup started
2026-11-17T08:05:00 WARN disk: usage on /var at 87 percent
2026-11-17T08:05:33 ERROR kernel: Out of memory: killed process 4242 (java)
2026-11-17T08:06:10 DEBUG app: cache refreshed in 14ms
2026-11-17T08:06:48 ERROR app: login failed for user bob: invalid credentials
2026-11-17T08:07:15 WARN sshd: Failed password for guest from 198.51.100.23
2026-11-17T08:07:21 INFO sshd: Accepted password for deploy from 192.0.2.44
2026-11-17T08:08:00 INFO sudo: session opened for user root
2026-11-17T08:08:37 WARN app: slow query detected (842ms)
2026-11-17T08:09:05 WARN sshd: Failed password for oracle from 203.0.113.7
2026-11-17T08:10:02 INFO cron: job nightly-backup finished
2026-11-17T08:10:30 ERROR app: login failed for user carol: invalid credentials
2026-11-17T08:11:14 INFO systemd: nginx.service reloaded
2026-11-17T08:12:44 WARN sshd: Failed password for root from 198.51.100.23
2026-11-17T08:13:25 INFO kernel: eth0 link up at 1000 Mbps
2026-11-17T08:13:50 INFO sshd: Accepted password for ubuntu from 192.0.2.61
2026-11-17T08:14:09 WARN sshd: Failed password for root from 203.0.113.7
2026-11-17T08:15:00 INFO app: health check ok
2026-11-17T08:16:31 INFO systemd: sshd.service restarted
2026-11-17T08:17:08 WARN app: retry scheduled for queue worker-3
2026-11-17T08:18:20 INFO sshd: Accepted password for alice from 192.0.2.19
2026-11-17T08:19:44 WARN sshd: Failed password for pi from 198.51.100.23
2026-11-17T08:19:50 INFO sshd: Connection closed by 192.0.2.19 port 51234
garbage line without format
2026-11-17T08:20:05 INFO systemd: rotated journal files
2026-11-17T08:20:30 WARN app: rate limit exceeded for 203.0.113.7
2026-11-17T08:21:10 INFO app: session expired for user alice
2026-11-17T08:21:55 INFO cron: job log-rotate finished
";

const SUCCESS_ONLY_LOG: &str = "\
2026-11-17T09:00:00 INFO sshd: Accepted password for carol from 10.0.0.5
2026-11-17T09:00:05 INFO app: login succeeded for user carol
";

/// A scratch directory for one test, removed when the test ends.
struct Workdir(PathBuf);

impl Workdir {
    fn new(test: &str) -> Self {
        let dir = env::temp_dir().join(format!("odyssey-e2e-{}-{test}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        Workdir(dir)
    }

    fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Workdir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_Odyssey"))
        .args(args)
        .output()
        .expect("failed to launch binary")
}

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn analyzes_log_end_to_end() {
    let dir = Workdir::new("analyzes_log");
    let log = dir.write("auth.log", AUTH_LOG.as_bytes());
    let out = run(&[path_str(&log)]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    assert!(s.contains("Total lines:      41"), "{s}");
    assert!(s.contains("Parsed lines:     40"), "{s}");
    assert!(s.contains("Malformed lines:  1"), "{s}");
    assert!(s.contains("Failed:     14"), "{s}");
    assert!(s.contains("Successful: 5"), "{s}");
    assert!(s.contains("203.0.113.7"), "{s}");
}

#[test]
fn top_flag_limits_component_listing() {
    let dir = Workdir::new("top_flag");
    let log = dir.write("auth.log", AUTH_LOG.as_bytes());
    let out = run(&[path_str(&log), "--top", "1"]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    assert!(s.contains("-- Top 1 components --"), "{s}");
    assert!(s.contains("sshd"), "{s}");
    assert!(!s.contains("app "), "{s}");
}

#[test]
fn ip_section_omitted_when_no_failures() {
    let dir = Workdir::new("no_failures");
    let log = dir.write("success_only.log", SUCCESS_ONLY_LOG.as_bytes());
    let out = run(&[path_str(&log)]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    assert!(s.contains("Failed:     0"), "{s}");
    assert!(s.contains("Successful: 2"), "{s}");
    assert!(!s.contains("failing source IPs"), "{s}");
}

#[test]
fn missing_file_exits_with_1() {
    let dir = Workdir::new("missing");
    let missing = dir.0.join("does-not-exist.log");
    let out = run(&[path_str(&missing)]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("cannot open"), "{}", stderr(&out));
    assert!(stdout(&out).is_empty());
}

#[test]
fn no_arguments_exits_with_2() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("Usage"), "{}", stderr(&out));
}

#[test]
fn invalid_top_value_exits_with_2() {
    let dir = Workdir::new("invalid_top");
    let log = dir.write("auth.log", AUTH_LOG.as_bytes());
    let out = run(&[path_str(&log), "--top", "abc"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_top_value_exits_with_2() {
    let dir = Workdir::new("missing_top");
    let log = dir.write("auth.log", AUTH_LOG.as_bytes());
    let out = run(&[path_str(&log), "--top"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn extra_positional_argument_exits_with_2() {
    let dir = Workdir::new("extra_arg");
    let a = dir.write("auth.log", AUTH_LOG.as_bytes());
    let b = dir.write("success_only.log", SUCCESS_ONLY_LOG.as_bytes());
    let out = run(&[path_str(&a), path_str(&b)]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_prints_usage_and_exits_with_2() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("Usage"), "{}", stderr(&out));
}

#[test]
fn corrupt_evtx_signature_exits_with_1() {
    // A file with the .evtx signature but no valid chunks must fail cleanly.
    let dir = Workdir::new("corrupt_evtx");
    let mut bytes = b"ElfFile\0".to_vec();
    bytes.extend_from_slice(&[0u8; 64]);
    let path = dir.write("corrupt.evtx", &bytes);

    let out = run(&[path_str(&path)]);

    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("as evtx"), "{}", stderr(&out));
}
