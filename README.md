# Odyssey

Odyssey is a dependency-free command-line log analyzer written in Rust. It reads a plain-text log file, parses each line into a timestamp, level, component and message, and prints an aggregate report covering line statistics, severity and component distributions, login outcomes, and the most frequent failing source addresses.

## Contents

- [Requirements](#requirements)
- [Build](#build)
- [Usage](#usage)
- [Input format](#input-format)
- [Output](#output)
- [Exit codes](#exit-codes)
- [Parsing and classification rules](#parsing-and-classification-rules)
- [Testing](#testing)
- [Repository layout](#repository-layout)
- [Limitations](#limitations)
- [Dependencies](#dependencies)
- [License](#license)

## Requirements

- Rust toolchain supporting **edition 2024** (Rust 1.85 or later).
- Cargo.

No external crates are required for the analyzer itself.

## Build

```sh
cargo build --release
```

The binary is produced at `target/release/Odyssey` (`Odyssey.exe` on Windows). The package name is `Odyssey`, so Cargo names the executable accordingly.

## Usage

```sh
cargo run -- <logfile> [--top N]
```

or, after building:

```sh
Odyssey <logfile> [--top N]
```

| Argument        | Required | Default | Description                                                      |
|-----------------|----------|---------|------------------------------------------------------------------|
| `<logfile>`     | yes      | —       | Path to the log file to analyze.                                 |
| `--top N`       | no       | `5`     | Number of entries shown in the top-component and top-IP sections. `N` must be a non-negative integer. |
| `-h`, `--help`  | no       | —       | Prints the usage line and exits with code `2`.                   |

Only one positional argument is accepted. Any additional positional argument, unknown option, or `--top` without a valid integer value prints the usage line and exits with code `2`.

### Example

```sh
cargo run -- tests/auth.log --top 3
```

## Input format

Each line is expected to have the form:

```
YYYY-MM-DDTHH:MM:SS LEVEL component: message
```

- `timestamp` — exactly 19 characters and containing a `T` separator. The contents are not validated as a calendar date; ordering is lexicographic.
- `LEVEL` — a single whitespace-free token (e.g. `INFO`, `WARN`, `ERROR`, `DEBUG`). Any token is accepted.
- `component` — the text between the first space after the level and the first `: `.
- `message` — everything after the first `: ` following the component.

Trailing whitespace is trimmed. Empty lines are ignored and are not counted. Lines that do not match the format are counted as malformed and skipped.

A sample file conforming to this format is provided at `tests/auth.log`.

## Output

The report has the following sections:

| Section              | Content                                                                                 |
|----------------------|-----------------------------------------------------------------------------------------|
| Header statistics    | Total non-empty lines, parsed lines, malformed lines, and the first and last timestamps. |
| Levels               | Count per level, sorted by count descending.                                            |
| Top components       | Up to `N` components by count, sorted by count descending, then name ascending.         |
| Logins               | Number of failed and successful login events.                                           |
| Top failing IPs      | Up to `N` source IPv4 addresses by failure count. Printed only when at least one failure with an address was found. |

Ties in counts are broken alphabetically (components and IPs) or lexicographically (levels), so output is deterministic for a given input.

### Sample output

```
=== Log analysis ===
Total lines:      41
Parsed lines:     40
Malformed lines:  1
Time range:       2026-11-17T08:00:01 .. 2026-11-17T08:21:55

-- Levels --
  INFO     18
  WARN     15
  ERROR    4
  DEBUG    3

-- Top 3 components --
  sshd                 17
  app                  12
  cron                 3

-- Logins --
  Failed:     14
  Successful: 5

-- Top 3 failing source IPs --
  203.0.113.7        6
  198.51.100.23      5
```

## Exit codes

| Code | Meaning                                                                 |
|------|-------------------------------------------------------------------------|
| `0`  | Report produced successfully.                                           |
| `1`  | The file could not be opened, or reading failed (for example, invalid UTF-8 input). |
| `2`  | Invalid usage: missing path, unknown or duplicate argument, invalid `--top` value, or `--help`. |

Error messages are written to standard error.

## Parsing and classification rules

**Failed login.** A parsed line whose message contains `failed password` or `login failed`, compared case-insensitively.

**Successful login.** A parsed line whose message contains `accepted password` or `login succeeded`, compared case-insensitively. A line matching the failure patterns is never counted as successful.

**Source IP extraction.** Applied only to failed-login lines. The first occurrence of ` from ` is located; the following whitespace-delimited token is accepted only if it has exactly four dot-separated components, each parsing as an unsigned 8-bit integer. Failed logins without a valid address are counted in the failure total but not in the per-IP table.

**Time range.** The minimum and maximum timestamps across all parsed lines, compared as strings.

## Testing

```sh
cargo test
```

The suite has two layers:

- **Unit tests** (`src/main.rs`, 21 tests) cover line parsing, including malformed timestamps and separators, IPv4 extraction and range checks, login classification, time-range computation, level and component counting, invalid UTF-8 handling, and result ordering.
- **Integration tests** (`tests/cli.rs`, 9 tests) run the compiled binary against the fixtures in `tests/` and check stdout, stderr and exit codes. They cover the full report on `tests/auth.log`, the `--top` option, omission of the IP section when there are no failures, missing files, and every usage-error path.

Fixtures:

- `tests/auth.log` — mixed-level sample with failures, successes and one malformed line.
- `tests/success_only.log` — successful logins only.

## Repository layout

```
.
├── Cargo.toml        Package manifest
├── src/
│   └── main.rs       Parser, aggregator, report printer, CLI, unit tests
├── tests/
│   ├── cli.rs        Integration tests (run the compiled binary)
│   ├── auth.log      Mixed sample input
│   └── success_only.log  Sample input with no failed logins
└── README.md
```

`target/` is excluded by `.gitignore`.

## Limitations

- Timestamps are not parsed or validated; the time range is determined by string comparison, which is correct only for fixed-width ISO-8601 values.
- The input format is fixed. Syslog, JSON, Apache/Nginx access logs, and other formats are not recognized and will be reported as malformed.
- The entire file is read in a single pass with streaming line reads; no output is produced until the end of the input.
- Only IPv4 source addresses are extracted. IPv6 addresses are not recognized.
- Login detection relies on substring matches against fixed phrases.
- Windows Event Log (`.evtx`) files are not supported.
- Input must be valid UTF-8; otherwise reading fails with exit code `1`.

## Dependencies

Odyssey has no external dependencies. It uses only the Rust standard library.

## License

No license has been specified. All rights are reserved by the author until a license is added.
