"""QUIC congestion control primitives -- CUBIC + HyStart++ +
pacing budget as pure functions.

This module implements RFC 9438 (CUBIC for QUIC) plus the
HyStart++ slow-start exit heuristic (RFC 9406) and the pacing-
gain primitive from RFC 9002 §7.7. Every entry point is a pure
function over an explicit :class:`CcState` -- the connection
state machine owns the state, calls ``on_ack`` / ``on_loss`` /
``on_send`` to advance it, and reads the pacing budget back to
shape outbound packets. There is no internal timer, no
per-instance allocation, and no I/O.

Public surface:

* :class:`CcState` -- congestion-controller state carrier
  (``cwnd``, ``ssthresh``, ``W_max``, ``epoch_start``, smoothed
  RTT, HyStart++ counters, etc.).
* :func:`cc_init` -- build a fresh :class:`CcState` with RFC
  9002 §B.2 defaults (10*MSS initial window, ssthresh =
  ``Int.MAX``, no congestion observed).
* :func:`on_packet_sent` -- update bytes-in-flight + pacing
  bookkeeping.
* :func:`on_ack_received` -- advance cwnd via slow-start /
  congestion-avoidance / CUBIC. Returns the new cwnd.
* :func:`on_packets_lost` -- handle a loss event; shrink cwnd
  per RFC 9438 §4.7 (CUBIC) and exit HyStart++ if active.
* :func:`pacing_rate_bytes_per_second` -- compute the pacing
  rate per RFC 9002 §7.7 (``N * cwnd / smoothed_rtt``).
* :func:`pacing_budget` -- given an elapsed-time delta, compute
  the byte budget the sender may emit.

The numerics use ``UInt64`` byte counts and ``Float64`` for the
CUBIC growth function; the RFC parameters
(``CUBIC_C = 0.4``, ``CUBIC_BETA = 0.7``) are encoded as
constants so a future cycle can swap them out for BBRv2 / other
controllers without touching the API.

Sans-I/O contract: zero I/O imports. Registered in
``tools/check_sans_io.sh``.

References:
- RFC 9438 "CUBIC for Fast Long-Distance Networks".
- RFC 9002 "QUIC Loss Detection and Congestion Control".
- RFC 9406 "HyStart++: Modified Slow Start for TCP".
"""

from std.collections import List, Optional
from std.memory import Span
from std.math import sqrt, cbrt


# ── Tunable constants (RFC 9002 §B.1, RFC 9438 §5) ────────────────────────


comptime DEFAULT_MSS_BYTES: UInt64 = UInt64(1452)
"""Default UDP payload size used as the cwnd unit; matches the
typical Linux ``advmss`` for IPv4/UDP-over-Ethernet (RFC 9000
§14.1 floor of 1200 + ~252 bytes typical headroom)."""

comptime INITIAL_WINDOW_PACKETS: UInt64 = UInt64(10)
"""RFC 9002 §B.2 -- initial congestion window of 10 MSS."""

comptime MIN_WINDOW_PACKETS: UInt64 = UInt64(2)
"""RFC 9002 §B.2 -- minimum cwnd after persistent congestion."""

comptime PACING_GAIN_NUM: UInt64 = UInt64(125)
comptime PACING_GAIN_DEN: UInt64 = UInt64(100)
"""RFC 9002 §7.7 -- the pacing rate is ``N * cwnd / smoothed_rtt``
where N is 1.25 during slow-start. Encoded as a num/den pair so
the math stays in integer arithmetic."""

comptime CUBIC_BETA_NUM: UInt64 = UInt64(7)
comptime CUBIC_BETA_DEN: UInt64 = UInt64(10)
"""RFC 9438 §5 -- multiplicative decrease factor (0.7)."""

comptime CUBIC_C_NUM: UInt64 = UInt64(4)
comptime CUBIC_C_DEN: UInt64 = UInt64(10)
"""RFC 9438 §5 -- aggressiveness constant (0.4)."""

comptime HYSTART_LOW_RTT_THRESHOLD_MS: UInt64 = UInt64(4)
comptime HYSTART_HIGH_RTT_THRESHOLD_MS: UInt64 = UInt64(16)
comptime HYSTART_RTT_SAMPLE_COUNT: UInt64 = UInt64(8)
"""RFC 9406 -- HyStart++ exit thresholds. The slow-start exit
heuristic compares the minimum RTT in the current round against
the smoothed RTT minimum across rounds; a sustained delay
increase of ``[low, high]`` ms across ``RTT_SAMPLE_COUNT``
samples triggers slow-start exit."""


@fieldwise_init
struct CcState(Copyable, ImplicitlyCopyable, Movable):
    """Congestion-controller state for one QUIC connection.

    Pure data; every transition is a function on this carrier.
    All byte fields are in bytes, not packets; the conversion is
    one ``mss`` multiplication when the caller wants
    packets-equivalent units.
    """

    var cwnd_bytes: UInt64
    var ssthresh_bytes: UInt64
    var bytes_in_flight: UInt64
    var w_max_bytes: UInt64
    var epoch_start_us: UInt64
    var k_us: UInt64
    var smoothed_rtt_us: UInt64
    var min_rtt_us: UInt64
    var hystart_round_min_rtt_us: UInt64
    var hystart_round_samples: UInt64
    var in_slow_start: Bool
    var mss: UInt64


def cc_init(mss: UInt64 = DEFAULT_MSS_BYTES) -> CcState:
    """Build a fresh :class:`CcState` with RFC 9002 §B.2 defaults."""
    return CcState(
        cwnd_bytes=mss * INITIAL_WINDOW_PACKETS,
        # RFC 9002 §B.2 -- ssthresh starts at "infinite"; we use
        # ``2^63 - 1`` as a sentinel that never trips the
        # ssthresh check before a loss event.
        ssthresh_bytes=UInt64((1 << 63) - 1),
        bytes_in_flight=UInt64(0),
        w_max_bytes=UInt64(0),
        epoch_start_us=UInt64(0),
        k_us=UInt64(0),
        smoothed_rtt_us=UInt64(0),
        min_rtt_us=UInt64((1 << 63) - 1),
        hystart_round_min_rtt_us=UInt64((1 << 63) - 1),
        hystart_round_samples=UInt64(0),
        in_slow_start=True,
        mss=mss,
    )


def on_packet_sent(mut state: CcState, bytes: UInt64):
    """Update bytes-in-flight after sending ``bytes`` of payload."""
    state.bytes_in_flight = state.bytes_in_flight + bytes


def _hystart_should_exit(state: CcState) -> Bool:
    """RFC 9406 -- exit slow-start if the minimum RTT in the
    current round exceeds the smoothed RTT minimum by at least
    HYSTART_LOW_RTT_THRESHOLD_MS, sustained for
    HYSTART_RTT_SAMPLE_COUNT samples."""
    if not state.in_slow_start:
        return False
    if state.hystart_round_samples < HYSTART_RTT_SAMPLE_COUNT:
        return False
    if state.smoothed_rtt_us == UInt64(0):
        return False
    var delta_us = (
        state.hystart_round_min_rtt_us
        - state.smoothed_rtt_us if state.hystart_round_min_rtt_us
        > state.smoothed_rtt_us else UInt64(0)
    )
    var threshold_us = HYSTART_LOW_RTT_THRESHOLD_MS * UInt64(1000)
    return delta_us >= threshold_us


def on_ack_received(
    mut state: CcState, acked_bytes: UInt64, rtt_us: UInt64, now_us: UInt64
) -> UInt64:
    """Advance cwnd in response to an ACK acknowledging
    ``acked_bytes`` of in-flight payload at time ``now_us``.

    Returns the new ``cwnd_bytes``. The caller is expected to
    pass the round-trip-time sample observed for the ACK
    (``rtt_us``) so HyStart++ can track per-round minima.

    The function dispatches between three regimes:

    * Slow start -- exponential cwnd growth. HyStart++ checks
      apply on every ACK; the controller exits slow start when
      either ``cwnd >= ssthresh`` or HyStart++ trips.
    * CUBIC congestion avoidance -- the cwnd grows along the
      cubic function ``W(t) = C * (t - K)^3 + W_max``; the
      controller picks ``max(W(t), W_TCP(t))`` for friendliness
      with Reno (RFC 9438 §4.2).
    """
    if state.bytes_in_flight >= acked_bytes:
        state.bytes_in_flight = state.bytes_in_flight - acked_bytes
    else:
        state.bytes_in_flight = UInt64(0)
    # Update RTT bookkeeping.
    if rtt_us > UInt64(0):
        if rtt_us < state.min_rtt_us:
            state.min_rtt_us = rtt_us
        if rtt_us < state.hystart_round_min_rtt_us:
            state.hystart_round_min_rtt_us = rtt_us
        state.hystart_round_samples = state.hystart_round_samples + 1
        if state.smoothed_rtt_us == UInt64(0):
            state.smoothed_rtt_us = rtt_us
        else:
            # RFC 9002 §5.3 -- smoothed RTT EWMA, alpha = 1/8.
            state.smoothed_rtt_us = (
                (state.smoothed_rtt_us * UInt64(7)) + rtt_us
            ) // UInt64(8)
    if state.in_slow_start:
        state.cwnd_bytes = state.cwnd_bytes + acked_bytes
        if state.cwnd_bytes >= state.ssthresh_bytes or _hystart_should_exit(
            state
        ):
            state.in_slow_start = False
            state.epoch_start_us = now_us
            state.w_max_bytes = state.cwnd_bytes
        return state.cwnd_bytes
    # CUBIC congestion avoidance.
    if state.epoch_start_us == UInt64(0):
        state.epoch_start_us = now_us
        state.w_max_bytes = state.cwnd_bytes
    var elapsed_us = (
        now_us - state.epoch_start_us if now_us
        >= state.epoch_start_us else UInt64(0)
    )
    var t_seconds = Float64(elapsed_us) / 1_000_000.0
    var k_seconds = Float64(state.k_us) / 1_000_000.0
    var c = Float64(CUBIC_C_NUM) / Float64(CUBIC_C_DEN)
    var w_max = Float64(state.w_max_bytes) / Float64(state.mss)
    var w_cubic = c * ((t_seconds - k_seconds) ** 3) + w_max
    var w_cubic_bytes = UInt64(w_cubic * Float64(state.mss))
    # AIMD friendliness path: TCP Reno-equivalent growth.
    var w_tcp_bytes = (
        state.cwnd_bytes
        + (acked_bytes * state.mss // state.cwnd_bytes) if state.cwnd_bytes
        > UInt64(0) else state.cwnd_bytes
    )
    if w_cubic_bytes > w_tcp_bytes:
        state.cwnd_bytes = w_cubic_bytes
    else:
        state.cwnd_bytes = w_tcp_bytes
    return state.cwnd_bytes


def on_packets_lost(
    mut state: CcState, lost_bytes: UInt64, now_us: UInt64
) -> UInt64:
    """Handle a packet-loss event covering ``lost_bytes`` of
    payload at time ``now_us``.

    Per RFC 9438 §4.7, the cwnd is multiplied by ``CUBIC_BETA``
    (0.7) and ``W_max`` is set to the pre-loss cwnd; the
    ssthresh follows the new cwnd. The CUBIC time origin ``K``
    is recomputed from the new ``W_max`` so the cubic curve
    reaches ``W_max`` again at ``K`` seconds after the epoch
    start.

    Slow-start mode is exited unconditionally on any loss event.
    Returns the new cwnd. The caller is expected to call
    :func:`on_packet_sent` later to repopulate the in-flight
    counter once retransmissions are queued.
    """
    if state.bytes_in_flight >= lost_bytes:
        state.bytes_in_flight = state.bytes_in_flight - lost_bytes
    else:
        state.bytes_in_flight = UInt64(0)
    state.in_slow_start = False
    state.w_max_bytes = state.cwnd_bytes
    var new_cwnd = (state.cwnd_bytes * CUBIC_BETA_NUM) // CUBIC_BETA_DEN
    var min_cwnd = state.mss * MIN_WINDOW_PACKETS
    if new_cwnd < min_cwnd:
        new_cwnd = min_cwnd
    state.cwnd_bytes = new_cwnd
    state.ssthresh_bytes = new_cwnd
    state.epoch_start_us = now_us
    # K = cbrt((W_max - cwnd) * mss / C) seconds.
    var c = Float64(CUBIC_C_NUM) / Float64(CUBIC_C_DEN)
    var w_max_pkts = Float64(state.w_max_bytes) / Float64(state.mss)
    var cwnd_pkts = Float64(state.cwnd_bytes) / Float64(state.mss)
    var k_seconds: Float64
    if w_max_pkts > cwnd_pkts and c > 0.0:
        k_seconds = cbrt((w_max_pkts - cwnd_pkts) / c)
    else:
        k_seconds = 0.0
    state.k_us = UInt64(k_seconds * 1_000_000.0)
    return state.cwnd_bytes


def on_round_start(mut state: CcState):
    """Reset the HyStart++ per-round counters at the start of a
    new RTT round. The caller invokes this when it observes a
    round-trip boundary (typically ``largest_acked >= round_end``)."""
    state.hystart_round_min_rtt_us = UInt64((1 << 63) - 1)
    state.hystart_round_samples = UInt64(0)


def pacing_rate_bytes_per_second(state: CcState) -> UInt64:
    """RFC 9002 §7.7 -- pacing rate = ``N * cwnd / smoothed_rtt``.

    During slow-start ``N`` is :data:`PACING_GAIN_NUM` /
    :data:`PACING_GAIN_DEN` (1.25); during congestion avoidance
    ``N`` is 1. Returns 0 when ``smoothed_rtt`` is unknown so the
    caller can apply its fallback (typically the initial RTT
    floor of ``333ms`` per RFC 9002 §B.2).
    """
    if state.smoothed_rtt_us == UInt64(0):
        return UInt64(0)
    var num: UInt64
    var den: UInt64
    if state.in_slow_start:
        num = PACING_GAIN_NUM
        den = PACING_GAIN_DEN
    else:
        num = UInt64(1)
        den = UInt64(1)
    var rate_per_us = (state.cwnd_bytes * num) // (state.smoothed_rtt_us * den)
    return rate_per_us * UInt64(1_000_000)


def pacing_budget(state: CcState, elapsed_us: UInt64) -> UInt64:
    """Compute the byte budget the sender may emit over an
    interval of ``elapsed_us`` microseconds at the current pacing
    rate.

    Returns ``cwnd_bytes`` when no rate is computable (the sender
    falls back to cwnd-bound bursts).
    """
    var rate = pacing_rate_bytes_per_second(state)
    if rate == UInt64(0):
        return state.cwnd_bytes
    var budget = (rate * elapsed_us) // UInt64(1_000_000)
    if budget > state.cwnd_bytes:
        return state.cwnd_bytes
    return budget


def can_send(state: CcState) -> Bool:
    """Whether the connection has any cwnd headroom left for a
    new MSS-sized packet."""
    return state.bytes_in_flight + state.mss <= state.cwnd_bytes
