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

Cargo fetches the two dependencies listed under [Dependencies](#dependencies) automatically.

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

Odyssey accepts two kinds of input and detects which one from the file's contents, not its extension:

- **Windows Event Log (`.evtx`)** files, recognized by the `ElfFile\0` file signature. Each record is rendered by the `evtx` crate and mapped to the same internal form as text lines. See [Windows Event Log input](#windows-event-log-input).
- **Plain-text logs** in the form below.

### Plain-text logs

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

### Windows Event Log input

For `.evtx` files, each record is mapped as follows:

| Report field     | Source in the event                                                       |
|------------------|---------------------------------------------------------------------------|
| Timestamp        | `System/TimeCreated/@SystemTime`, truncated to `YYYY-MM-DDTHH:MM:SS` (UTC) |
| Level            | `System/Level`: 1 CRITICAL, 2 ERROR, 3 WARN, 4 and 0 INFO, 5 VERBOSE, other UNKNOWN |
| Component        | `System/Provider/@Name` (`unknown` if absent)                             |
| Failed login     | Event ID 4625 from provider `Microsoft-Windows-Security-Auditing`         |
| Successful login | Event ID 4624 from provider `Microsoft-Windows-Security-Auditing`         |
| Source IP        | `EventData/IpAddress` of a failed login, when it is a valid IPv4 address  |

Login classification uses event IDs from the Security provider only. Other providers never count as logins, even if their messages contain login wording. Records that cannot be read or mapped are counted as malformed.

Reading the Security log normally requires administrator rights. Access-denied errors are reported as `cannot open` (exit code `1`).

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

- **Unit tests** (`src/main.rs`, 21 tests; `src/evtx_input.rs`, 9 tests) cover line parsing, including malformed timestamps and separators, IPv4 extraction and range checks, login classification, time-range computation, level and component counting, invalid UTF-8 handling, and result ordering.
- **Integration tests** (`tests/cli.rs`, 10 tests) run the compiled binary against the fixtures in `tests/` and check stdout, stderr and exit codes. They cover the full report on `tests/auth.log`, the `--top` option, omission of the IP section when there are no failures, missing files, every usage-error path, and a file with the `.evtx` signature but corrupt contents.

The `.evtx` mapping is tested with synthetic rendered records, because no sample `.evtx` file is committed. Real Windows logs have been verified only where the analyzer could read them.

Fixtures:

- `tests/auth.log` — mixed-level sample with failures, successes and one malformed line.
- `tests/success_only.log` — successful logins only.

## Repository layout

```
.
├── Cargo.toml        Package manifest
├── src/
│   ├── main.rs       Entry model, text parser, report, CLI, unit tests
│   └── evtx_input.rs Windows Event Log reader and mapping, unit tests
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
- Login classification for `.evtx` covers only Security events 4624 and 4625. Other authentication events are not counted.
- Input text must be valid UTF-8; otherwise reading fails with exit code `1`.

## Dependencies

Odyssey has two dependencies:

- `evtx` (0.15.1) — parses Windows Event Log files.
- `serde_json` (1) — reads the JSON rendered for each `.evtx` record.

Plain-text analysis uses only the standard library.

## License

No license has been specified. All rights are reserved by the author until a license is added.
