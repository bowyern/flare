# quinn HTTP/3 baseline -- pending wiring

`quinn` is the canonical Rust QUIC implementation; pairing it with
`h3-quinn` gives a clean reference HTTP/3 server to compare flare's
own h3 throughput against. The intent is the same as the
`benchmark/baselines/hyper/` baseline: a small Rust binary built
via `cargo build --release --locked` that serves the same
"hello, world" body the v0.6 throughput harness uses, but over
UDP + QUIC + h3 instead of TCP + TLS + h2.

## Status

This directory is the scaffold layout only:

- `Cargo.toml` + a `src/main.rs` skeleton are not yet checked in.
- `check.sh` + `run.sh` are not yet checked in.
- The pinned versions for `quinn` / `h3` / `h3-quinn` go in
  `Cargo.toml` when the baseline lands.

The reason: the cross-framework HTTP/3 bench is a hard release
gate per the v0.8 Phase D plan, but it requires the flare h3
server itself to be wired end-to-end before the comparison is
meaningful. The flare-side wiring is in flight:

- Track Q1 follow-up -- the OpenSSL AEAD backend behind the
  `QuicCrypto` trait (currently `StubQuicCrypto`).
- Track Q2 follow-up -- the rustls Rust crate behind
  `RustlsQuicAcceptor` (currently raises `NOT_BUILT`).
- Track Q3 follow-up -- the QUIC reactor's UDP read loop +
  per-datagram dispatch (currently `QuicListener.run` raises).
- Track Q4 follow-up -- the H3 driver's per-stream
  `H3RequestReader -> Handler -> response-writer` wiring
  (currently `H3Connection.feed_stream_chunk` raises).

When those follow-ups land, the bench harness consults this
directory + `benchmark/baselines/quiche/` for the matching
external baseline binaries. Each baseline serves the same
hello-world body the v0.6 throughput harness uses; the harness
runs the same `h2load --npn-list=h3` workload against flare,
quinn, and quiche, computes the five-run median + p99 / p99.9 /
p99.99, and writes the result table to
`benchmark/results/v0.8/h3/`.

## Pin guidance (when the baseline lands)

```toml
[dependencies]
quinn      = "0.10"   # pin major.minor
h3         = "0.0.4"  # pin major.minor.patch
h3-quinn   = "0.0.5"
rustls     = "0.21"
tokio      = { version = "1", features = ["full"] }
bytes      = "1"
```

Cross-validate: bench against `quiche-client` from the
`benchmark/baselines/quiche/` baseline as a second reference;
publish both columns in the result table so any flare-side
regression is bracketed by two independent implementations.
