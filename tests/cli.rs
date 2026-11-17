//! End-to-end tests that run the compiled binary against the fixtures in `tests/`.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_Odyssey"))
        .args(args)
        .output()
        .expect("failed to launch binary")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn analyzes_fixture_end_to_end() {
    let path = fixture("auth.log");
    let out = run(&[path.to_str().unwrap()]);
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
    let path = fixture("auth.log");
    let out = run(&[path.to_str().unwrap(), "--top", "1"]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    assert!(s.contains("-- Top 1 components --"), "{s}");
    assert!(s.contains("sshd"), "{s}");
    assert!(!s.contains("app "), "{s}");
}

#[test]
fn ip_section_omitted_when_no_failures() {
    let path = fixture("success_only.log");
    let out = run(&[path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    assert!(s.contains("Failed:     0"), "{s}");
    assert!(s.contains("Successful: 2"), "{s}");
    assert!(!s.contains("failing source IPs"), "{s}");
}

#[test]
fn missing_file_exits_with_1() {
    let out = run(&["tests/does-not-exist.log"]);
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
    let path = fixture("auth.log");
    let out = run(&[path.to_str().unwrap(), "--top", "abc"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_top_value_exits_with_2() {
    let path = fixture("auth.log");
    let out = run(&[path.to_str().unwrap(), "--top"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn extra_positional_argument_exits_with_2() {
    let a = fixture("auth.log");
    let b = fixture("success_only.log");
    let out = run(&[a.to_str().unwrap(), b.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_prints_usage_and_exits_with_2() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("Usage"), "{}", stderr(&out));
}
