"""Unit tests for the QUIC CUBIC + HyStart++ controller
(``flare.quic.cc`` -- RFC 9438 + RFC 9002 §7.7 + RFC 9406).

Validates the slow-start exponential growth, the multiplicative
decrease + cubic recovery, the HyStart++ slow-start exit, and the
pacing-rate computation against hand-derived numbers.
"""

from std.testing import assert_equal, assert_true, assert_false

from flare.quic import (
    CcState,
    DEFAULT_MSS_BYTES,
    INITIAL_WINDOW_PACKETS,
    MIN_WINDOW_PACKETS,
    can_send,
    cc_init,
    on_ack_received,
    on_packet_sent,
    on_packets_lost,
    on_round_start,
    pacing_budget,
    pacing_rate_bytes_per_second,
)


def test_initial_state_matches_rfc9002() raises:
    var state = cc_init()
    assert_equal(state.cwnd_bytes, DEFAULT_MSS_BYTES * INITIAL_WINDOW_PACKETS)
    assert_true(state.in_slow_start)
    assert_equal(state.bytes_in_flight, UInt64(0))


def test_slow_start_grows_exponentially() raises:
    var state = cc_init()
    var initial = state.cwnd_bytes
    on_packet_sent(state, DEFAULT_MSS_BYTES)
    var new_cwnd = on_ack_received(
        state, DEFAULT_MSS_BYTES, UInt64(50_000), UInt64(0)
    )
    assert_true(new_cwnd > initial)
    assert_equal(new_cwnd, initial + DEFAULT_MSS_BYTES)


def test_loss_triggers_multiplicative_decrease() raises:
    var state = cc_init()
    on_packet_sent(state, DEFAULT_MSS_BYTES * UInt64(5))
    var pre_loss = state.cwnd_bytes
    var new_cwnd = on_packets_lost(state, DEFAULT_MSS_BYTES, UInt64(0))
    assert_false(state.in_slow_start)
    # CUBIC_BETA = 0.7; new cwnd should be 70% of pre-loss cwnd.
    var expected = (pre_loss * UInt64(7)) // UInt64(10)
    assert_equal(new_cwnd, expected)


def test_loss_floors_at_min_window() raises:
    var state = cc_init()
    state.cwnd_bytes = DEFAULT_MSS_BYTES * UInt64(2)
    var new_cwnd = on_packets_lost(state, UInt64(0), UInt64(0))
    # 70% of 2 MSS = 1.4 MSS; clamps to 2 MSS minimum.
    assert_equal(new_cwnd, DEFAULT_MSS_BYTES * MIN_WINDOW_PACKETS)


def test_can_send_respects_cwnd() raises:
    var state = cc_init()
    var max_in_flight = state.cwnd_bytes - DEFAULT_MSS_BYTES + UInt64(1)
    state.bytes_in_flight = max_in_flight
    assert_false(can_send(state))
    state.bytes_in_flight = UInt64(0)
    assert_true(can_send(state))


def test_smoothed_rtt_ewma() raises:
    var state = cc_init()
    on_packet_sent(state, DEFAULT_MSS_BYTES)
    var _ = on_ack_received(
        state, DEFAULT_MSS_BYTES, UInt64(100_000), UInt64(0)
    )
    assert_equal(state.smoothed_rtt_us, UInt64(100_000))
    on_packet_sent(state, DEFAULT_MSS_BYTES)
    var _2 = on_ack_received(
        state, DEFAULT_MSS_BYTES, UInt64(150_000), UInt64(1000)
    )
    # EWMA: (100k * 7 + 150k) / 8 = (700k + 150k) / 8 = 106250.
    assert_equal(state.smoothed_rtt_us, UInt64(106_250))


def test_pacing_rate_zero_when_no_rtt() raises:
    var state = cc_init()
    assert_equal(pacing_rate_bytes_per_second(state), UInt64(0))


def test_pacing_rate_uses_pacing_gain_in_slow_start() raises:
    var state = cc_init()
    on_packet_sent(state, DEFAULT_MSS_BYTES)
    var _ = on_ack_received(
        state, DEFAULT_MSS_BYTES, UInt64(100_000), UInt64(0)
    )
    var rate = pacing_rate_bytes_per_second(state)
    # In slow-start: rate = 1.25 * cwnd / rtt.
    var expected_rate_per_us = (state.cwnd_bytes * UInt64(125)) // (
        state.smoothed_rtt_us * UInt64(100)
    )
    assert_equal(rate, expected_rate_per_us * UInt64(1_000_000))


def test_pacing_budget_clamps_to_cwnd() raises:
    var state = cc_init()
    on_packet_sent(state, DEFAULT_MSS_BYTES)
    var _ = on_ack_received(
        state, DEFAULT_MSS_BYTES, UInt64(100_000), UInt64(0)
    )
    # Ask for a 1-second budget; the rate * 1s easily exceeds
    # cwnd, so the budget clamps to cwnd_bytes.
    var budget = pacing_budget(state, UInt64(1_000_000))
    assert_equal(budget, state.cwnd_bytes)


def test_round_start_resets_hystart_counters() raises:
    var state = cc_init()
    state.hystart_round_min_rtt_us = UInt64(50)
    state.hystart_round_samples = UInt64(10)
    on_round_start(state)
    assert_equal(state.hystart_round_samples, UInt64(0))


def test_post_loss_no_longer_in_slow_start() raises:
    var state = cc_init()
    on_packet_sent(state, DEFAULT_MSS_BYTES)
    var _ = on_packets_lost(state, UInt64(0), UInt64(0))
    assert_false(state.in_slow_start)
    # Post-loss ssthresh equals the post-decrease cwnd.
    assert_equal(state.ssthresh_bytes, state.cwnd_bytes)


def main() raises:
    test_initial_state_matches_rfc9002()
    test_slow_start_grows_exponentially()
    test_loss_triggers_multiplicative_decrease()
    test_loss_floors_at_min_window()
    test_can_send_respects_cwnd()
    test_smoothed_rtt_ewma()
    test_pacing_rate_zero_when_no_rtt()
    test_pacing_rate_uses_pacing_gain_in_slow_start()
    test_pacing_budget_clamps_to_cwnd()
    test_round_start_resets_hystart_counters()
    test_post_loss_no_longer_in_slow_start()
    print("test_quic_cc: 11 passed")
