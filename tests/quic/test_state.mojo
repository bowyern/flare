"""Unit tests for QUIC connection + stream state machines
(``flare.quic.state`` -- RFC 9000 §3 + §10).

The state machine is exercised through :func:`handle_frame_buf`,
which parses one wire frame from the supplied buffer and routes
the matching :trait:`FrameHandler` callback into the connection's
state transitions. Each test builds the frame bytes with the
per-type encoder and asserts the resulting :class:`ConnectionEvents`
plus the connection-level bookkeeping (``last_activity_us``,
``ack_pending``, the stream map).
"""

from std.testing import assert_equal, assert_true, assert_false
from std.collections import List
from std.memory import Span

from flare.quic import (
    CONN_STATE_DRAINING,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_HANDSHAKE,
    Connection,
    ConnectionEvents,
    STREAM_STATE_HALF_CLOSED_REMOTE,
    STREAM_STATE_OPEN,
    Stream,
    apply_handshake_done,
    apply_max_data,
    connection_close,
    empty_events,
    handle_frame_buf,
    is_idle_timeout_expired,
    mark_handshake_complete,
    new_connection,
    new_stream,
)
from flare.quic.frame import (
    AckFrame,
    AckRange,
    ConnectionCloseFrame,
    EcnCounts,
    FRAME_TYPE_ACK,
    FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
    FRAME_TYPE_HANDSHAKE_DONE,
    FRAME_TYPE_MAX_DATA,
    FRAME_TYPE_PADDING,
    FRAME_TYPE_PING,
    FRAME_TYPE_STREAM_BASE,
    MaxDataFrame,
    StreamFrame,
    encode_ack,
    encode_connection_close,
    encode_handshake_done,
    encode_max_data,
    encode_padding,
    encode_ping,
    encode_stream,
)


def test_initial_connection_state() raises:
    var conn = new_connection()
    assert_equal(conn.state, CONN_STATE_HANDSHAKE)
    assert_false(conn.handshake_complete)
    assert_equal(conn.last_activity_us, UInt64(0))


def test_handshake_done_advances_state() raises:
    var conn = new_connection()
    var events = empty_events()
    var buf = List[UInt8]()
    encode_handshake_done(buf)
    var consumed = handle_frame_buf(
        conn, Span[UInt8, _](buf), UInt64(100), events
    )
    assert_equal(consumed, 1)
    assert_true(events.handshake_done)
    assert_true(conn.handshake_complete)
    assert_equal(conn.state, CONN_STATE_ESTABLISHED)


def test_mark_handshake_complete_explicit_hook() raises:
    var conn = new_connection()
    var events = empty_events()
    mark_handshake_complete(conn, UInt64(50), events)
    assert_true(events.handshake_done)
    assert_equal(conn.state, CONN_STATE_ESTABLISHED)


def test_stream_frame_opens_stream() raises:
    var conn = new_connection()
    var data = List[UInt8]()
    data.append(UInt8(0x41))
    var buf = List[UInt8]()
    encode_stream(
        StreamFrame(
            stream_id=UInt64(4), offset=UInt64(0), data=data^, fin=False
        ),
        buf,
    )
    var events = empty_events()
    _ = handle_frame_buf(conn, Span[UInt8, _](buf), UInt64(100), events)
    assert_equal(len(events.new_streams), 1)
    assert_equal(events.new_streams[0], UInt64(4))
    assert_equal(len(events.finished_streams), 0)


def test_stream_frame_with_fin_finishes_stream() raises:
    var conn = new_connection()
    var data = List[UInt8]()
    data.append(UInt8(0x41))
    var buf = List[UInt8]()
    encode_stream(
        StreamFrame(
            stream_id=UInt64(0), offset=UInt64(0), data=data^, fin=True
        ),
        buf,
    )
    var events = empty_events()
    _ = handle_frame_buf(conn, Span[UInt8, _](buf), UInt64(100), events)
    assert_equal(len(events.finished_streams), 1)
    var s_opt = conn.streams.get(UInt64(0))
    assert_true(Bool(s_opt))
    assert_equal(s_opt.value().state, STREAM_STATE_HALF_CLOSED_REMOTE)


def test_ack_eliciting_flag_flips_pending() raises:
    var conn = new_connection()
    var events = empty_events()
    var buf = List[UInt8]()
    encode_ping(buf)
    _ = handle_frame_buf(conn, Span[UInt8, _](buf), UInt64(100), events)
    assert_true(conn.ack_pending)


def test_padding_does_not_flip_ack_pending() raises:
    var conn = new_connection()
    var events = empty_events()
    var buf = List[UInt8]()
    encode_padding(1, buf)
    _ = handle_frame_buf(conn, Span[UInt8, _](buf), UInt64(100), events)
    assert_false(conn.ack_pending)


def test_max_data_advances_send_limit() raises:
    var conn = new_connection(initial_max_data=UInt64(1000))
    var buf = List[UInt8]()
    encode_max_data(MaxDataFrame(maximum_data=UInt64(5000)), buf)
    var events = empty_events()
    _ = handle_frame_buf(conn, Span[UInt8, _](buf), UInt64(100), events)
    assert_equal(conn.max_data_send, UInt64(5000))


def test_connection_close_frame_drains() raises:
    var conn = new_connection()
    var hs_events = empty_events()
    mark_handshake_complete(conn, UInt64(50), hs_events)
    var reason = List[UInt8]()
    for b in String("oops").as_bytes():
        reason.append(b)
    var buf = List[UInt8]()
    encode_connection_close(
        ConnectionCloseFrame(
            application=False,
            error_code=UInt64(0x100),
            frame_type=UInt64(0),
            reason_phrase=reason^,
        ),
        buf,
    )
    var events = empty_events()
    _ = handle_frame_buf(conn, Span[UInt8, _](buf), UInt64(200), events)
    assert_true(events.connection_closed)
    assert_equal(events.error_code, UInt64(0x100))
    assert_equal(conn.state, CONN_STATE_DRAINING)


def test_connection_close_explicit_helper() raises:
    var conn = new_connection()
    connection_close(conn, UInt64(0x42), "bye")
    assert_equal(conn.close_error_code, UInt64(0x42))
    assert_equal(len(conn.close_reason), 3)


def test_idle_timeout_detection() raises:
    var conn = new_connection(idle_timeout_us=UInt64(1_000_000))
    var events = empty_events()
    var buf = List[UInt8]()
    encode_ping(buf)
    _ = handle_frame_buf(conn, Span[UInt8, _](buf), UInt64(100), events)
    assert_false(is_idle_timeout_expired(conn, UInt64(500_000)))
    assert_true(is_idle_timeout_expired(conn, UInt64(2_000_000)))


def test_flow_control_violation_raises() raises:
    var conn = new_connection(initial_max_data=UInt64(2))
    var data = List[UInt8]()
    for _ in range(10):
        data.append(UInt8(0x41))
    var buf = List[UInt8]()
    encode_stream(
        StreamFrame(
            stream_id=UInt64(0), offset=UInt64(0), data=data^, fin=False
        ),
        buf,
    )
    var events = empty_events()
    var raised = False
    try:
        _ = handle_frame_buf(conn, Span[UInt8, _](buf), UInt64(100), events)
    except:
        raised = True
    assert_true(raised)


def test_ack_frame_advances_largest_received() raises:
    var conn = new_connection()
    var ack = AckFrame(
        largest_acknowledged=UInt64(42),
        ack_delay=UInt64(0),
        first_ack_range=UInt64(0),
        ranges=List[AckRange](),
        ecn=List[EcnCounts](),
    )
    var buf = List[UInt8]()
    encode_ack(ack, buf)
    var events = empty_events()
    _ = handle_frame_buf(conn, Span[UInt8, _](buf), UInt64(100), events)
    assert_equal(conn.largest_received_packet, UInt64(42))


def main() raises:
    test_initial_connection_state()
    test_handshake_done_advances_state()
    test_mark_handshake_complete_explicit_hook()
    test_stream_frame_opens_stream()
    test_stream_frame_with_fin_finishes_stream()
    test_ack_eliciting_flag_flips_pending()
    test_padding_does_not_flip_ack_pending()
    test_max_data_advances_send_limit()
    test_connection_close_frame_drains()
    test_connection_close_explicit_helper()
    test_idle_timeout_detection()
    test_flow_control_violation_raises()
    test_ack_frame_advances_largest_received()
    print("test_quic_state: 13 passed")
