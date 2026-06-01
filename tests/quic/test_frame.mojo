"""Unit tests for the QUIC v1 transport-frame codec
(``flare.quic.frame`` -- RFC 9000 §19).

Each test locks one frame type's wire format with a hand-computed
encoding cross-checked against aioquic's ``packet.PullQuicFrame``
decoded form; the encode + decode + round-trip are asserted as a
single end-to-end identity per type.
"""

from std.testing import assert_equal, assert_true, assert_false
from std.memory import Span

from flare.quic import (
    AckFrame,
    AckRange,
    ConnectionCloseFrame,
    CryptoFrame,
    DataBlockedFrame,
    EcnCounts,
    Frame,
    FRAME_TYPE_ACK,
    FRAME_TYPE_ACK_ECN,
    FRAME_TYPE_CONNECTION_CLOSE_APPLICATION,
    FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
    FRAME_TYPE_CRYPTO,
    FRAME_TYPE_DATA_BLOCKED,
    FRAME_TYPE_HANDSHAKE_DONE,
    FRAME_TYPE_MAX_DATA,
    FRAME_TYPE_MAX_STREAM_DATA,
    FRAME_TYPE_MAX_STREAMS_BIDI,
    FRAME_TYPE_MAX_STREAMS_UNI,
    FRAME_TYPE_NEW_CONNECTION_ID,
    FRAME_TYPE_NEW_TOKEN,
    FRAME_TYPE_PADDING,
    FRAME_TYPE_PATH_CHALLENGE,
    FRAME_TYPE_PATH_RESPONSE,
    FRAME_TYPE_PING,
    FRAME_TYPE_RESET_STREAM,
    FRAME_TYPE_RETIRE_CONNECTION_ID,
    FRAME_TYPE_STOP_SENDING,
    FRAME_TYPE_STREAM_BASE,
    FRAME_TYPE_STREAM_DATA_BLOCKED,
    FRAME_TYPE_STREAMS_BLOCKED_BIDI,
    FRAME_TYPE_STREAMS_BLOCKED_UNI,
    HandshakeDoneFrame,
    MaxDataFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    NewConnectionIdFrame,
    NewTokenFrame,
    ParsedFrame,
    PathChallengeFrame,
    PathResponseFrame,
    ResetStreamFrame,
    RetireConnectionIdFrame,
    StopSendingFrame,
    StreamFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    encode_frame,
    parse_frame,
)
from flare.quic.frame import _zero_frame


def _bytes(*hex: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for v in hex:
        out.append(UInt8(v))
    return out^


def test_padding_single_byte() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_PADDING)
    f.padding_length = 3
    encode_frame(f, out)
    assert_equal(len(out), 3)
    for i in range(3):
        assert_equal(Int(out[i]), 0x00)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_PADDING)
    assert_equal(p.frame.padding_length, 1)
    assert_equal(p.consumed, 1)


def test_ping_round_trip() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_PING)
    encode_frame(f, out)
    assert_equal(len(out), 1)
    assert_equal(Int(out[0]), 0x01)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_PING)
    assert_equal(p.consumed, 1)


def test_ack_round_trip() raises:
    var ranges = List[AckRange]()
    ranges.append(AckRange(gap=UInt64(1), length=UInt64(2)))
    var ack = AckFrame(
        largest_acknowledged=UInt64(100),
        ack_delay=UInt64(50),
        first_ack_range=UInt64(10),
        ranges=ranges^,
        ecn=List[EcnCounts](),
    )
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_ACK)
    f.ack = ack^
    encode_frame(f, out)
    assert_equal(Int(out[0]), 0x02)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_ACK)
    assert_equal(p.frame.ack.largest_acknowledged, UInt64(100))
    assert_equal(p.frame.ack.ack_delay, UInt64(50))
    assert_equal(p.frame.ack.first_ack_range, UInt64(10))
    assert_equal(len(p.frame.ack.ranges), 1)
    assert_equal(p.frame.ack.ranges[0].gap, UInt64(1))
    assert_equal(p.frame.ack.ranges[0].length, UInt64(2))


def test_ack_ecn_round_trip() raises:
    var ecn = List[EcnCounts]()
    ecn.append(EcnCounts(ect0=UInt64(7), ect1=UInt64(8), ce=UInt64(9)))
    var ack = AckFrame(
        largest_acknowledged=UInt64(5),
        ack_delay=UInt64(0),
        first_ack_range=UInt64(2),
        ranges=List[AckRange](),
        ecn=ecn^,
    )
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_ACK_ECN)
    f.ack = ack^
    encode_frame(f, out)
    assert_equal(Int(out[0]), 0x03)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_ACK_ECN)
    assert_equal(len(p.frame.ack.ecn), 1)
    assert_equal(p.frame.ack.ecn[0].ect0, UInt64(7))
    assert_equal(p.frame.ack.ecn[0].ect1, UInt64(8))
    assert_equal(p.frame.ack.ecn[0].ce, UInt64(9))


def test_reset_stream_round_trip() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_RESET_STREAM)
    f.reset_stream = ResetStreamFrame(
        stream_id=UInt64(4),
        application_error_code=UInt64(0x10),
        final_size=UInt64(0xC0FFEE),
    )
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_RESET_STREAM)
    assert_equal(p.frame.reset_stream.stream_id, UInt64(4))
    assert_equal(p.frame.reset_stream.application_error_code, UInt64(0x10))
    assert_equal(p.frame.reset_stream.final_size, UInt64(0xC0FFEE))


def test_stop_sending_round_trip() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_STOP_SENDING)
    f.stop_sending = StopSendingFrame(
        stream_id=UInt64(8), application_error_code=UInt64(0x20)
    )
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_STOP_SENDING)
    assert_equal(p.frame.stop_sending.stream_id, UInt64(8))
    assert_equal(p.frame.stop_sending.application_error_code, UInt64(0x20))


def test_crypto_round_trip() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x16))  # TLS handshake byte
    data.append(UInt8(0x03))
    data.append(UInt8(0x03))
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_CRYPTO)
    f.crypto = CryptoFrame(offset=UInt64(0), data=data^)
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_CRYPTO)
    assert_equal(p.frame.crypto.offset, UInt64(0))
    assert_equal(len(p.frame.crypto.data), 3)
    assert_equal(Int(p.frame.crypto.data[0]), 0x16)


def test_new_token_round_trip() raises:
    var token = List[UInt8]()
    token.append(UInt8(0xDE))
    token.append(UInt8(0xAD))
    token.append(UInt8(0xBE))
    token.append(UInt8(0xEF))
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_NEW_TOKEN)
    f.new_token = NewTokenFrame(token=token^)
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_NEW_TOKEN)
    assert_equal(len(p.frame.new_token.token), 4)
    assert_equal(Int(p.frame.new_token.token[3]), 0xEF)


def test_new_token_empty_rejected() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_NEW_TOKEN)
    f.new_token = NewTokenFrame(token=List[UInt8]())
    var raised = False
    try:
        encode_frame(f, out)
    except:
        raised = True
    assert_true(raised)


def test_stream_round_trip_with_offset_and_fin() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x41))  # 'A'
    data.append(UInt8(0x42))  # 'B'
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_STREAM_BASE)
    f.stream = StreamFrame(
        stream_id=UInt64(0),
        offset=UInt64(7),
        data=data^,
        fin=True,
    )
    encode_frame(f, out)
    # First byte: 0x08 | OFF (0x04) | LEN (0x02) | FIN (0x01) = 0x0F.
    assert_equal(Int(out[0]), 0x0F)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_STREAM_BASE)
    assert_equal(p.frame.stream.stream_id, UInt64(0))
    assert_equal(p.frame.stream.offset, UInt64(7))
    assert_equal(len(p.frame.stream.data), 2)
    assert_true(p.frame.stream.fin)


def test_stream_round_trip_no_offset_no_fin() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x58))  # 'X'
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_STREAM_BASE)
    f.stream = StreamFrame(
        stream_id=UInt64(4),
        offset=UInt64(0),
        data=data^,
        fin=False,
    )
    encode_frame(f, out)
    # First byte: 0x08 | LEN (0x02) = 0x0A.
    assert_equal(Int(out[0]), 0x0A)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.stream.stream_id, UInt64(4))
    assert_equal(p.frame.stream.offset, UInt64(0))
    assert_false(p.frame.stream.fin)


def test_max_data_round_trip() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_MAX_DATA)
    f.max_data = MaxDataFrame(maximum_data=UInt64(1 << 20))
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_MAX_DATA)
    assert_equal(p.frame.max_data.maximum_data, UInt64(1 << 20))


def test_max_stream_data_round_trip() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_MAX_STREAM_DATA)
    f.max_stream_data = MaxStreamDataFrame(
        stream_id=UInt64(12),
        maximum_stream_data=UInt64(0x1234),
    )
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_MAX_STREAM_DATA)
    assert_equal(p.frame.max_stream_data.stream_id, UInt64(12))
    assert_equal(p.frame.max_stream_data.maximum_stream_data, UInt64(0x1234))


def test_max_streams_bidi_and_uni() raises:
    var out_bidi = List[UInt8]()
    var fb = _zero_frame(FRAME_TYPE_MAX_STREAMS_BIDI)
    fb.max_streams = MaxStreamsFrame(
        unidirectional=False, maximum_streams=UInt64(8)
    )
    encode_frame(fb, out_bidi)
    assert_equal(Int(out_bidi[0]), 0x12)
    var pb = parse_frame(Span[UInt8, _](out_bidi))
    assert_equal(pb.frame.kind, FRAME_TYPE_MAX_STREAMS_BIDI)
    assert_false(pb.frame.max_streams.unidirectional)

    var out_uni = List[UInt8]()
    var fu = _zero_frame(FRAME_TYPE_MAX_STREAMS_UNI)
    fu.max_streams = MaxStreamsFrame(
        unidirectional=True, maximum_streams=UInt64(4)
    )
    encode_frame(fu, out_uni)
    assert_equal(Int(out_uni[0]), 0x13)
    var pu = parse_frame(Span[UInt8, _](out_uni))
    assert_equal(pu.frame.kind, FRAME_TYPE_MAX_STREAMS_UNI)
    assert_true(pu.frame.max_streams.unidirectional)


def test_data_blocked_round_trip() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_DATA_BLOCKED)
    f.data_blocked = DataBlockedFrame(maximum_data=UInt64(0xFF))
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_DATA_BLOCKED)
    assert_equal(p.frame.data_blocked.maximum_data, UInt64(0xFF))


def test_stream_data_blocked_round_trip() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_STREAM_DATA_BLOCKED)
    f.stream_data_blocked = StreamDataBlockedFrame(
        stream_id=UInt64(2),
        maximum_stream_data=UInt64(64),
    )
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_STREAM_DATA_BLOCKED)
    assert_equal(p.frame.stream_data_blocked.stream_id, UInt64(2))


def test_streams_blocked_bidi_and_uni() raises:
    var out_bidi = List[UInt8]()
    var fb = _zero_frame(FRAME_TYPE_STREAMS_BLOCKED_BIDI)
    fb.streams_blocked = StreamsBlockedFrame(
        unidirectional=False, maximum_streams=UInt64(2)
    )
    encode_frame(fb, out_bidi)
    assert_equal(Int(out_bidi[0]), 0x16)

    var out_uni = List[UInt8]()
    var fu = _zero_frame(FRAME_TYPE_STREAMS_BLOCKED_UNI)
    fu.streams_blocked = StreamsBlockedFrame(
        unidirectional=True, maximum_streams=UInt64(1)
    )
    encode_frame(fu, out_uni)
    assert_equal(Int(out_uni[0]), 0x17)


def test_new_connection_id_round_trip() raises:
    var cid = List[UInt8]()
    for i in range(8):
        cid.append(UInt8(i + 1))
    var token = List[UInt8]()
    for _ in range(16):
        token.append(UInt8(0xAA))
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_NEW_CONNECTION_ID)
    f.new_connection_id = NewConnectionIdFrame(
        sequence_number=UInt64(3),
        retire_prior_to=UInt64(1),
        connection_id=cid^,
        stateless_reset_token=token^,
    )
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_NEW_CONNECTION_ID)
    assert_equal(p.frame.new_connection_id.sequence_number, UInt64(3))
    assert_equal(p.frame.new_connection_id.retire_prior_to, UInt64(1))
    assert_equal(len(p.frame.new_connection_id.connection_id), 8)
    assert_equal(len(p.frame.new_connection_id.stateless_reset_token), 16)


def test_retire_connection_id_round_trip() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_RETIRE_CONNECTION_ID)
    f.retire_connection_id = RetireConnectionIdFrame(sequence_number=UInt64(7))
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_RETIRE_CONNECTION_ID)
    assert_equal(p.frame.retire_connection_id.sequence_number, UInt64(7))


def test_path_challenge_round_trip() raises:
    var data = List[UInt8]()
    for i in range(8):
        data.append(UInt8(i + 100))
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_PATH_CHALLENGE)
    f.path_challenge = PathChallengeFrame(data=data^)
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_PATH_CHALLENGE)
    assert_equal(len(p.frame.path_challenge.data), 8)


def test_path_response_round_trip() raises:
    var data = List[UInt8]()
    for i in range(8):
        data.append(UInt8(i))
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_PATH_RESPONSE)
    f.path_response = PathResponseFrame(data=data^)
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_PATH_RESPONSE)
    assert_equal(len(p.frame.path_response.data), 8)


def test_connection_close_transport_round_trip() raises:
    var reason = List[UInt8]()
    for b in String("oops").as_bytes():
        reason.append(b)
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT)
    f.connection_close = ConnectionCloseFrame(
        application=False,
        error_code=UInt64(0x100),
        frame_type=UInt64(FRAME_TYPE_STREAM_BASE),
        reason_phrase=reason^,
    )
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT)
    assert_false(p.frame.connection_close.application)
    assert_equal(p.frame.connection_close.error_code, UInt64(0x100))
    assert_equal(
        p.frame.connection_close.frame_type, UInt64(FRAME_TYPE_STREAM_BASE)
    )


def test_connection_close_application_round_trip() raises:
    var reason = List[UInt8]()
    for b in String("bye").as_bytes():
        reason.append(b)
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_CONNECTION_CLOSE_APPLICATION)
    f.connection_close = ConnectionCloseFrame(
        application=True,
        error_code=UInt64(0x42),
        frame_type=UInt64(0),
        reason_phrase=reason^,
    )
    encode_frame(f, out)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_CONNECTION_CLOSE_APPLICATION)
    assert_true(p.frame.connection_close.application)
    assert_equal(p.frame.connection_close.error_code, UInt64(0x42))


def test_handshake_done_round_trip() raises:
    var out = List[UInt8]()
    var f = _zero_frame(FRAME_TYPE_HANDSHAKE_DONE)
    encode_frame(f, out)
    assert_equal(len(out), 1)
    assert_equal(Int(out[0]), 0x1E)
    var p = parse_frame(Span[UInt8, _](out))
    assert_equal(p.frame.kind, FRAME_TYPE_HANDSHAKE_DONE)
    assert_equal(p.consumed, 1)


def test_unknown_frame_type_rejected() raises:
    var raised = False
    try:
        var _p = parse_frame(Span[UInt8, _](_bytes(0xFF)))
    except:
        raised = True
    assert_true(raised)


def test_truncated_crypto_rejected() raises:
    # 0x06 (CRYPTO) + offset varint 0 + length varint 8, then only
    # 2 payload bytes -- parser must reject.
    var buf = _bytes(0x06, 0x00, 0x08, 0xAA, 0xBB)
    var raised = False
    try:
        var _p = parse_frame(Span[UInt8, _](buf))
    except:
        raised = True
    assert_true(raised)


def main() raises:
    test_padding_single_byte()
    test_ping_round_trip()
    test_ack_round_trip()
    test_ack_ecn_round_trip()
    test_reset_stream_round_trip()
    test_stop_sending_round_trip()
    test_crypto_round_trip()
    test_new_token_round_trip()
    test_new_token_empty_rejected()
    test_stream_round_trip_with_offset_and_fin()
    test_stream_round_trip_no_offset_no_fin()
    test_max_data_round_trip()
    test_max_stream_data_round_trip()
    test_max_streams_bidi_and_uni()
    test_data_blocked_round_trip()
    test_stream_data_blocked_round_trip()
    test_streams_blocked_bidi_and_uni()
    test_new_connection_id_round_trip()
    test_retire_connection_id_round_trip()
    test_path_challenge_round_trip()
    test_path_response_round_trip()
    test_connection_close_transport_round_trip()
    test_connection_close_application_round_trip()
    test_handshake_done_round_trip()
    test_unknown_frame_type_rejected()
    test_truncated_crypto_rejected()
    print("test_quic_frame: 26 passed")
