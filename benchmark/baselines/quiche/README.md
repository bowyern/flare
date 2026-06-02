# quiche HTTP/3 baseline -- pending wiring

Cloudflare's `quiche` ships a reference HTTP/3 server with a
clean Rust binary surface (`quiche-server` from the `quiche/apps/`
crate). Pairs with the `benchmark/baselines/quinn/` baseline as
a second independent reference implementation for the v0.8
Phase D Track Q7 hard-gate HTTP/3 throughput bench.

## Status

This directory is the scaffold layout only:

- `Cargo.toml` + a `src/main.rs` wrapper around `quiche-server`
  are not yet checked in.
- `check.sh` + `run.sh` are not yet checked in.
- The pinned `quiche` version goes in `Cargo.toml` when the
  baseline lands.

See `benchmark/baselines/quinn/README.md` for the full status
explanation: the cross-framework HTTP/3 bench is a hard release
gate, but flare's own h3 server requires the rustls + AEAD +
reactor follow-up commits before the comparison is meaningful.
This baseline lands alongside those follow-ups.

## Pin guidance (when the baseline lands)

```toml
[dependencies]
quiche   = "0.18"   # pin major.minor
mio      = "0.8"    # pollable UDP listener
ring     = "0.16"   # transitive but worth pinning
```

Build flags: enable the `boringssl-vendored` feature flag so the
baseline binary doesn't depend on a system-wide BoringSSL / OpenSSL
version that may not be present on the EPYC dev-box. Cross-
validate by running `quiche-client --no-verify` against both
flare's h3 server and `quiche-server` itself and comparing the
emitted byte streams; any divergence flags a wire-encoding bug.
