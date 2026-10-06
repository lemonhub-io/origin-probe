# origin-probe

Rust CLI that asks for explicit `yes` consent, collects environment, device,
and network signals, and reports a probability that the device user is
Chinese. Evidence is combined as likelihood ratios in log-odds space with a
per-category cap (`src/score.rs`).

Dependencies: `ureq` (TLS via rustls, `json` feature) + `serde`/`serde_json`.
HTTP geolocation is done in-process — do not shell out to curl.

## Build / test

```sh
cargo build            # debug  -> target/debug/origin-probe
cargo build --release  # 2.9M binary
cargo test             # scoring + classifier unit tests
```

If `/` ever fills up again, spill the target dir to the second disk:
`CARGO_TARGET_DIR=/www/devin-target cargo build`.

## Run

```sh
./origin-probe              # interactive consent prompt, then full scan
./origin-probe --offline    # skip all network checks
./origin-probe --json       # machine-readable report on stdout
echo yes | ./origin-probe --offline   # non-interactive consent
```

Consent/prompt text goes to stderr so piped stdout stays clean. The report
uses ANSI colors only when stdout is a TTY.
