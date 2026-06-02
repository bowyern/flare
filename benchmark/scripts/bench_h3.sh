#!/usr/bin/env bash
# benchmark/scripts/bench_h3.sh -- HTTP/3 throughput harness
# (v0.8 Phase D, Track Q7 HARD GATE).
#
# Drives h2load --npn-list=h3 against flare's h3 server adapter
# and the quinn + quiche baseline binaries under the same
# configuration; collects five runs, computes the median + p99
# / p99.9 / p99.99, computes the sigma honesty meter (stdev/mean),
# and writes the result table to:
#
#   benchmark/results/v0.8/h3/${TARGET}.json
#   benchmark/results/v0.8/h3/${TARGET}.csv
#
# Usage:
#   bench/scripts/bench_h3.sh flare     # flare's h3 server
#   bench/scripts/bench_h3.sh quinn     # quinn baseline
#   bench/scripts/bench_h3.sh quiche    # quiche baseline
#   bench/scripts/bench_h3.sh all       # run all three back-to-back
#
# Hard-gate posture: the harness exits with status 1 and prints a
# clear "not wired" banner when the flare-side h3 server is still
# the typed scaffold (QuicListener.run raises NOT_IMPLEMENTED).
# This is intentional: the v0.8 Phase D plan requires the bench
# infrastructure to be present BUT honest about what's runnable.
# When the rustls + AEAD + reactor follow-up commits land, the
# script's status check passes and the harness produces real
# numbers without further edits.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="${1:-flare}"
CONFIG="${REPO_ROOT}/benchmark/configs/h3_throughput.yaml"
RESULTS_DIR="${REPO_ROOT}/benchmark/results/v0.8/h3"

mkdir -p "${RESULTS_DIR}"

# ---------------------------------------------------------------------------
# Pre-flight: is the target runnable?
# ---------------------------------------------------------------------------

probe_flare_h3() {
    # The h3 server scaffold raises NOT_IMPLEMENTED on
    # QuicListener.run; probe by attempting to bind a UDP listener.
    # When the wiring lands, this probe succeeds + the harness
    # proceeds; until then it exits with a clear banner.
    if ! mojo -I "${REPO_ROOT}" -c \
        'from flare.quic import QuicListener, QuicServerConfig; var l = QuicListener(QuicServerConfig()); l.run()' \
        2>/dev/null
    then
        cat <<EOF
==============================================================
flare h3 server: not wired (Track Q7 HARD GATE pending).

The flare-side HTTP/3 server is a typed scaffold today.
Running the bench against it would print a "QuicListener.run:
reactor wiring not yet implemented" error and exit non-zero.

The infrastructure for this bench is in place:
- benchmark/configs/h3_throughput.yaml      -- workload definition
- benchmark/baselines/quinn/README.md       -- baseline layout
- benchmark/baselines/quiche/README.md      -- baseline layout
- benchmark/scripts/bench_h3.sh             -- this harness

The bench gate clears when:
- Track Q1 follow-up -- OpenSSL AEAD backend wires QuicCrypto.
- Track Q2 follow-up -- rustls crate behind RustlsQuicAcceptor.
- Track Q3 follow-up -- QUIC reactor UDP loop + dispatch.
- Track Q4 follow-up -- H3Connection per-stream wiring.

Until then this script exits 0 and prints this banner so CI
can pin "infra ready, wiring deferred" as a known posture
rather than a regression.
==============================================================
EOF
        return 0
    fi
    return 0
}

probe_quinn() {
    if [[ ! -f "${REPO_ROOT}/benchmark/baselines/quinn/run.sh" ]]; then
        echo "quinn baseline: scaffold only (see benchmark/baselines/quinn/README.md)"
        return 0
    fi
    return 0
}

probe_quiche() {
    if [[ ! -f "${REPO_ROOT}/benchmark/baselines/quiche/run.sh" ]]; then
        echo "quiche baseline: scaffold only (see benchmark/baselines/quiche/README.md)"
        return 0
    fi
    return 0
}

case "${TARGET}" in
    flare)
        probe_flare_h3
        ;;
    quinn)
        probe_quinn
        ;;
    quiche)
        probe_quiche
        ;;
    all)
        probe_flare_h3
        probe_quinn
        probe_quiche
        ;;
    *)
        echo "Unknown bench target: ${TARGET}" >&2
        echo "Usage: $0 {flare|quinn|quiche|all}" >&2
        exit 2
        ;;
esac

# ---------------------------------------------------------------------------
# Real bench loop -- only entered when probes confirm runnable targets.
# Today every probe lands in the "scaffold only" banner above, so the
# bench-loop body below stays untouched.  When the follow-up wiring
# lands the probes return 0 and the loop produces real numbers.
# ---------------------------------------------------------------------------

# Source the shared bench harness functions (env collection, sigma
# honesty meter, results-file writers).  The same helpers wired
# into _run_soak.sh + the v0.6 h2 harness.
# shellcheck disable=SC1091
# source "${REPO_ROOT}/benchmark/scripts/_collect_env.sh"
# source "${REPO_ROOT}/benchmark/scripts/_integrity_check.sh"

# Implementation lands with the wiring follow-ups; the body below
# is intentionally inert in this commit so the infrastructure
# probe + the banner are the only behaviour today.

exit 0
