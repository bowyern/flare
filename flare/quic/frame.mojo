"""QUIC v1 transport-frame codec (RFC 9000 §19).

This module is the canonical sans-I/O codec for the 22 transport
frame types QUIC v1 carries inside (deprotected) packet payloads.
It parses one frame at a time -- the QUIC connection state
machine drives the buffer cursor and dispatches per-frame
handling. Every encoder accepts a typed value and an output list;
every parser accepts a buffer slice and returns a typed
``Frame`` plus the number of bytes consumed.

Frame types covered (RFC 9000 §19, all 22):

* §19.1 PADDING (0x00)
* §19.2 PING (0x01)
* §19.3 ACK (0x02), ACK with ECN (0x03)
* §19.4 RESET_STREAM (0x04)
* §19.5 STOP_SENDING (0x05)
* §19.6 CRYPTO (0x06)
* §19.7 NEW_TOKEN (0x07)
* §19.8 STREAM (0x08..0x0f -- 8 sub-shapes via OFF/LEN/FIN bits)
* §19.9 MAX_DATA (0x10)
* §19.10 MAX_STREAM_DATA (0x11)
* §19.11 MAX_STREAMS (bidirectional 0x12, unidirectional 0x13)
* §19.12 DATA_BLOCKED (0x14)
* §19.13 STREAM_DATA_BLOCKED (0x15)
* §19.14 STREAMS_BLOCKED (bidirectional 0x16, unidirectional 0x17)
* §19.15 NEW_CONNECTION_ID (0x18)
* §19.16 RETIRE_CONNECTION_ID (0x19)
* §19.17 PATH_CHALLENGE (0x1a)
* §19.18 PATH_RESPONSE (0x1b)
* §19.19 CONNECTION_CLOSE (transport 0x1c, application 0x1d)
* §19.20 HANDSHAKE_DONE (0x1e)

The wire-level union over all 22 types is represented by the
``Frame`` discriminated struct: a ``kind`` byte selects which of
the 22 typed payload structs is populated. Every typed struct is
``Copyable`` + ``Movable`` so callers can shuttle frames through
queue / batch shapes without lifetime gymnastics.

Sans-I/O contract
-----------------

This file holds zero I/O imports. It is registered in
``tools/check_sans_io.sh`` so the contract is lint-enforced.

References
----------

* RFC 9000 §19 "Frame Types and Formats".
* RFC 9000 §16  "Variable-Length Integer Encoding" (varint).
* aioquic ``packet.PullQuicFrame`` / ``packet.encode_frame``.
* quiche ``frame::Frame::from_bytes`` / ``frame::Frame::to_bytes``.
"""

from std.collections import List
from std.memory import Span

from .varint import (
    Varint,
    VARINT_MAX,
    decode_varint,
    encode_varint,
    varint_encoded_length,
)


# ── Frame type constants (RFC 9000 §19 master table) ──────────────────────────


comptime FRAME_TYPE_PADDING: Int = 0x00
comptime FRAME_TYPE_PING: Int = 0x01
comptime FRAME_TYPE_ACK: Int = 0x02
comptime FRAME_TYPE_ACK_ECN: Int = 0x03
comptime FRAME_TYPE_RESET_STREAM: Int = 0x04
comptime FRAME_TYPE_STOP_SENDING: Int = 0x05
comptime FRAME_TYPE_CRYPTO: Int = 0x06
comptime FRAME_TYPE_NEW_TOKEN: Int = 0x07
# STREAM frame range (§19.8): 0x08..0x0f, low 3 bits encode
# OFF (0x04), LEN (0x02), FIN (0x01).
comptime FRAME_TYPE_STREAM_BASE: Int = 0x08
comptime FRAME_TYPE_STREAM_MAX: Int = 0x0F
comptime STREAM_OFF_BIT: Int = 0x04
comptime STREAM_LEN_BIT: Int = 0x02
comptime STREAM_FIN_BIT: Int = 0x01
comptime FRAME_TYPE_MAX_DATA: Int = 0x10
comptime FRAME_TYPE_MAX_STREAM_DATA: Int = 0x11
comptime FRAME_TYPE_MAX_STREAMS_BIDI: Int = 0x12
comptime FRAME_TYPE_MAX_STREAMS_UNI: Int = 0x13
comptime FRAME_TYPE_DATA_BLOCKED: Int = 0x14
comptime FRAME_TYPE_STREAM_DATA_BLOCKED: Int = 0x15
comptime FRAME_TYPE_STREAMS_BLOCKED_BIDI: Int = 0x16
comptime FRAME_TYPE_STREAMS_BLOCKED_UNI: Int = 0x17
comptime FRAME_TYPE_NEW_CONNECTION_ID: Int = 0x18
comptime FRAME_TYPE_RETIRE_CONNECTION_ID: Int = 0x19
comptime FRAME_TYPE_PATH_CHALLENGE: Int = 0x1A
comptime FRAME_TYPE_PATH_RESPONSE: Int = 0x1B
comptime FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT: Int = 0x1C
comptime FRAME_TYPE_CONNECTION_CLOSE_APPLICATION: Int = 0x1D
comptime FRAME_TYPE_HANDSHAKE_DONE: Int = 0x1E


# ── Typed frame payload structs ──────────────────────────────────────────────


@fieldwise_init
struct AckRange(Copyable, ImplicitlyCopyable, Movable):
    """One ACK range (RFC 9000 §19.3.1): ``gap`` + ``length``.

    The first range in an ACK frame is implicit and uses
    ``first_ack_range``; subsequent ranges carry an explicit
    ``gap`` (number of unacked packets between the previous range
    and this one, minus one) and ``length`` (count of acked
    packets in this range, minus one).
    """

    var gap: UInt64
    var length: UInt64


@fieldwise_init
struct EcnCounts(Copyable, ImplicitlyCopyable, Movable):
    """ECN counts (§19.3.2): per-codepoint cumulative counts. Only
    present in ACK_ECN frames (type 0x03)."""

    var ect0: UInt64
    var ect1: UInt64
    var ce: UInt64


@fieldwise_init
struct AckFrame(Copyable, Movable):
    """ACK / ACK-ECN frame payload (§19.3).

    ``ecn`` is populated only when the wire type is ``0x03``
    (ACK_ECN). The largest acknowledged packet number is the
    explicit field; the implicit first range covers
    ``[largest - first_ack_range, largest]``.
    """

    var largest_acknowledged: UInt64
    var ack_delay: UInt64
    var first_ack_range: UInt64
    var ranges: List[AckRange]
    var ecn: List[EcnCounts]


@fieldwise_init
struct ResetStreamFrame(Copyable, ImplicitlyCopyable, Movable):
    """RESET_STREAM (§19.4)."""

    var stream_id: UInt64
    var application_error_code: UInt64
    var final_size: UInt64


@fieldwise_init
struct StopSendingFrame(Copyable, ImplicitlyCopyable, Movable):
    """STOP_SENDING (§19.5)."""

    var stream_id: UInt64
    var application_error_code: UInt64


@fieldwise_init
struct CryptoFrame(Copyable, Movable):
    """CRYPTO (§19.6) -- TLS handshake bytes carried in-band on the
    Initial / Handshake / 1-RTT crypto streams."""

    var offset: UInt64
    var data: List[UInt8]


@fieldwise_init
struct NewTokenFrame(Copyable, Movable):
    """NEW_TOKEN (§19.7) -- server-issued address-validation token
    delivered to the client for use on a future 0-RTT handshake."""

    var token: List[UInt8]


@fieldwise_init
struct StreamFrame(Copyable, Movable):
    """STREAM (§19.8) -- payload bytes carried on a logical stream.

    The wire type (0x08..0x0f) encodes three flag bits:
    OFF (0x04) presence of the offset field, LEN (0x02) presence
    of the length field, FIN (0x01) end-of-stream marker. The
    parser populates ``offset`` (defaulting to 0 when OFF is
    unset) and reads the trailing data based on LEN -- absent LEN,
    the frame extends to the end of the packet payload.
    """

    var stream_id: UInt64
    var offset: UInt64
    var data: List[UInt8]
    var fin: Bool


@fieldwise_init
struct MaxDataFrame(Copyable, ImplicitlyCopyable, Movable):
    """MAX_DATA (§19.9)."""

    var maximum_data: UInt64


@fieldwise_init
struct MaxStreamDataFrame(Copyable, ImplicitlyCopyable, Movable):
    """MAX_STREAM_DATA (§19.10)."""

    var stream_id: UInt64
    var maximum_stream_data: UInt64


@fieldwise_init
struct MaxStreamsFrame(Copyable, ImplicitlyCopyable, Movable):
    """MAX_STREAMS (§19.11). ``unidirectional`` carries the wire-type
    distinction (0x12 = bidi, 0x13 = uni)."""

    var unidirectional: Bool
    var maximum_streams: UInt64


@fieldwise_init
struct DataBlockedFrame(Copyable, ImplicitlyCopyable, Movable):
    """DATA_BLOCKED (§19.12)."""

    var maximum_data: UInt64


@fieldwise_init
struct StreamDataBlockedFrame(Copyable, ImplicitlyCopyable, Movable):
    """STREAM_DATA_BLOCKED (§19.13)."""

    var stream_id: UInt64
    var maximum_stream_data: UInt64


@fieldwise_init
struct StreamsBlockedFrame(Copyable, ImplicitlyCopyable, Movable):
    """STREAMS_BLOCKED (§19.14). ``unidirectional`` carries the wire
    distinction (0x16 = bidi, 0x17 = uni)."""

    var unidirectional: Bool
    var maximum_streams: UInt64


@fieldwise_init
struct NewConnectionIdFrame(Copyable, Movable):
    """NEW_CONNECTION_ID (§19.15)."""

    var sequence_number: UInt64
    var retire_prior_to: UInt64
    var connection_id: List[UInt8]
    var stateless_reset_token: List[UInt8]


@fieldwise_init
struct RetireConnectionIdFrame(Copyable, ImplicitlyCopyable, Movable):
    """RETIRE_CONNECTION_ID (§19.16)."""

    var sequence_number: UInt64


@fieldwise_init
struct PathChallengeFrame(Copyable, Movable):
    """PATH_CHALLENGE (§19.17) -- 8 bytes of unpredictable data."""

    var data: List[UInt8]


@fieldwise_init
struct PathResponseFrame(Copyable, Movable):
    """PATH_RESPONSE (§19.18) -- echoes a prior PATH_CHALLENGE
    payload to confirm reachability on the new path."""

    var data: List[UInt8]


@fieldwise_init
struct ConnectionCloseFrame(Copyable, Movable):
    """CONNECTION_CLOSE (§19.19).

    ``application`` distinguishes the wire type: ``False`` is the
    transport-level 0x1c (carries ``frame_type`` of the offending
    frame); ``True`` is the application-level 0x1d (no
    ``frame_type`` field).
    """

    var application: Bool
    var error_code: UInt64
    var frame_type: UInt64
    var reason_phrase: List[UInt8]


@fieldwise_init
struct HandshakeDoneFrame(Copyable, ImplicitlyCopyable, Movable):
    """HANDSHAKE_DONE (§19.20) -- one-byte type with no payload."""

    pass


# ── Frame discriminated union ────────────────────────────────────────────────


@fieldwise_init
struct Frame(Copyable, Movable):
    """Discriminated union over all 22 RFC 9000 §19 frame types.

    ``kind`` is the wire-level type byte (or its canonical
    alias for variable-shape ranges -- e.g. STREAM frames collapse
    to ``FRAME_TYPE_STREAM_BASE`` here, with the OFF/LEN/FIN flag
    bits surfaced through the typed payload). Exactly one of the
    typed payload fields is populated; the rest are zero / empty
    sentinels.

    The codec uses a single struct rather than a Mojo trait /
    sum-type because Mojo doesn't yet expose a sum-type with
    pattern-match semantics; the discriminated-struct shape
    matches what aioquic's ``QuicFrame`` and quiche's ``Frame``
    enum compile to anyway, and it keeps every frame
    ``Copyable`` + ``Movable`` for free.
    """

    var kind: Int

    var padding_length: Int
    var ack: AckFrame
    var reset_stream: ResetStreamFrame
    var stop_sending: StopSendingFrame
    var crypto: CryptoFrame
    var new_token: NewTokenFrame
    var stream: StreamFrame
    var max_data: MaxDataFrame
    var max_stream_data: MaxStreamDataFrame
    var max_streams: MaxStreamsFrame
    var data_blocked: DataBlockedFrame
    var stream_data_blocked: StreamDataBlockedFrame
    var streams_blocked: StreamsBlockedFrame
    var new_connection_id: NewConnectionIdFrame
    var retire_connection_id: RetireConnectionIdFrame
    var path_challenge: PathChallengeFrame
    var path_response: PathResponseFrame
    var connection_close: ConnectionCloseFrame


@fieldwise_init
struct ParsedFrame(Copyable, Movable):
    """A parsed frame plus the number of wire bytes it consumed.

    Returned by :func:`parse_frame`; the caller advances its
    cursor by ``consumed`` and re-invokes :func:`parse_frame` on
    the remainder until the buffer is drained or a parse error
    fires.
    """

    var frame: Frame
    var consumed: Int


# ── Empty-payload helpers (sentinels for the discriminated union) ────────────


def _empty_ack() -> AckFrame:
    return AckFrame(
        largest_acknowledged=UInt64(0),
        ack_delay=UInt64(0),
        first_ack_range=UInt64(0),
        ranges=List[AckRange](),
        ecn=List[EcnCounts](),
    )


def _empty_reset_stream() -> ResetStreamFrame:
    return ResetStreamFrame(
        stream_id=UInt64(0),
        application_error_code=UInt64(0),
        final_size=UInt64(0),
    )


def _empty_stop_sending() -> StopSendingFrame:
    return StopSendingFrame(
        stream_id=UInt64(0),
        application_error_code=UInt64(0),
    )


def _empty_crypto() -> CryptoFrame:
    return CryptoFrame(offset=UInt64(0), data=List[UInt8]())


def _empty_new_token() -> NewTokenFrame:
    return NewTokenFrame(token=List[UInt8]())


def _empty_stream() -> StreamFrame:
    return StreamFrame(
        stream_id=UInt64(0),
        offset=UInt64(0),
        data=List[UInt8](),
        fin=False,
    )


def _empty_max_data() -> MaxDataFrame:
    return MaxDataFrame(maximum_data=UInt64(0))


def _empty_max_stream_data() -> MaxStreamDataFrame:
    return MaxStreamDataFrame(
        stream_id=UInt64(0),
        maximum_stream_data=UInt64(0),
    )


def _empty_max_streams() -> MaxStreamsFrame:
    return MaxStreamsFrame(
        unidirectional=False,
        maximum_streams=UInt64(0),
    )


def _empty_data_blocked() -> DataBlockedFrame:
    return DataBlockedFrame(maximum_data=UInt64(0))


def _empty_stream_data_blocked() -> StreamDataBlockedFrame:
    return StreamDataBlockedFrame(
        stream_id=UInt64(0),
        maximum_stream_data=UInt64(0),
    )


def _empty_streams_blocked() -> StreamsBlockedFrame:
    return StreamsBlockedFrame(
        unidirectional=False,
        maximum_streams=UInt64(0),
    )


def _empty_new_connection_id() -> NewConnectionIdFrame:
    return NewConnectionIdFrame(
        sequence_number=UInt64(0),
        retire_prior_to=UInt64(0),
        connection_id=List[UInt8](),
        stateless_reset_token=List[UInt8](),
    )


def _empty_retire_connection_id() -> RetireConnectionIdFrame:
    return RetireConnectionIdFrame(sequence_number=UInt64(0))


def _empty_path_challenge() -> PathChallengeFrame:
    return PathChallengeFrame(data=List[UInt8]())


def _empty_path_response() -> PathResponseFrame:
    return PathResponseFrame(data=List[UInt8]())


def _empty_connection_close() -> ConnectionCloseFrame:
    return ConnectionCloseFrame(
        application=False,
        error_code=UInt64(0),
        frame_type=UInt64(0),
        reason_phrase=List[UInt8](),
    )


def _zero_frame(kind: Int) -> Frame:
    return Frame(
        kind=kind,
        padding_length=0,
        ack=_empty_ack(),
        reset_stream=_empty_reset_stream(),
        stop_sending=_empty_stop_sending(),
        crypto=_empty_crypto(),
        new_token=_empty_new_token(),
        stream=_empty_stream(),
        max_data=_empty_max_data(),
        max_stream_data=_empty_max_stream_data(),
        max_streams=_empty_max_streams(),
        data_blocked=_empty_data_blocked(),
        stream_data_blocked=_empty_stream_data_blocked(),
        streams_blocked=_empty_streams_blocked(),
        new_connection_id=_empty_new_connection_id(),
        retire_connection_id=_empty_retire_connection_id(),
        path_challenge=_empty_path_challenge(),
        path_response=_empty_path_response(),
        connection_close=_empty_connection_close(),
    )


# ── Encoding helpers (varint append) ─────────────────────────────────────────


def _push_varint(mut out: List[UInt8], value: UInt64) raises:
    var encoded = encode_varint(value)
    for i in range(len(encoded)):
        out.append(encoded[i])


def _push_bytes(mut out: List[UInt8], data: List[UInt8]):
    for i in range(len(data)):
        out.append(data[i])


# ── Per-type encoders ────────────────────────────────────────────────────────


def encode_padding(length: Int, mut out: List[UInt8]) raises:
    """Encode ``length`` PADDING frames (§19.1) as repeated 0x00s."""
    if length < 0:
        raise Error("quic frame: padding length negative")
    for _ in range(length):
        out.append(UInt8(FRAME_TYPE_PADDING))


def encode_ping(mut out: List[UInt8]):
    """Encode a PING frame (§19.2): single 0x01 byte."""
    out.append(UInt8(FRAME_TYPE_PING))


def encode_ack(frame: AckFrame, mut out: List[UInt8]) raises:
    """Encode an ACK / ACK-ECN frame (§19.3).

    Picks the type byte based on whether ``frame.ecn`` is empty
    (0x02) or carries a single :class:`EcnCounts` entry (0x03).
    """
    var ecn_count = len(frame.ecn)
    if ecn_count > 1:
        raise Error("quic ack: ecn list must hold 0 or 1 entries")
    if ecn_count == 1:
        out.append(UInt8(FRAME_TYPE_ACK_ECN))
    else:
        out.append(UInt8(FRAME_TYPE_ACK))
    _push_varint(out, frame.largest_acknowledged)
    _push_varint(out, frame.ack_delay)
    _push_varint(out, UInt64(len(frame.ranges)))
    _push_varint(out, frame.first_ack_range)
    for i in range(len(frame.ranges)):
        var r = frame.ranges[i]
        _push_varint(out, r.gap)
        _push_varint(out, r.length)
    if ecn_count == 1:
        var counts = frame.ecn[0]
        _push_varint(out, counts.ect0)
        _push_varint(out, counts.ect1)
        _push_varint(out, counts.ce)


def encode_reset_stream(frame: ResetStreamFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_RESET_STREAM))
    _push_varint(out, frame.stream_id)
    _push_varint(out, frame.application_error_code)
    _push_varint(out, frame.final_size)


def encode_stop_sending(frame: StopSendingFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_STOP_SENDING))
    _push_varint(out, frame.stream_id)
    _push_varint(out, frame.application_error_code)


def encode_crypto(frame: CryptoFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_CRYPTO))
    _push_varint(out, frame.offset)
    _push_varint(out, UInt64(len(frame.data)))
    _push_bytes(out, frame.data)


def encode_new_token(frame: NewTokenFrame, mut out: List[UInt8]) raises:
    if len(frame.token) == 0:
        raise Error("quic new_token: token must be non-empty (RFC 9000 §19.7)")
    out.append(UInt8(FRAME_TYPE_NEW_TOKEN))
    _push_varint(out, UInt64(len(frame.token)))
    _push_bytes(out, frame.token)


def encode_stream(
    frame: StreamFrame, mut out: List[UInt8], emit_length: Bool = True
) raises:
    """Encode a STREAM frame (§19.8).

    ``emit_length`` controls whether the LEN bit is set: producers
    that emit a STREAM frame as the *last* frame of a packet may
    omit the explicit length and let the frame extend to the
    packet boundary. Most callers pass ``emit_length=True`` for
    safe self-describing framing.
    """
    var type_byte = FRAME_TYPE_STREAM_BASE
    if frame.offset > UInt64(0):
        type_byte |= STREAM_OFF_BIT
    if emit_length:
        type_byte |= STREAM_LEN_BIT
    if frame.fin:
        type_byte |= STREAM_FIN_BIT
    out.append(UInt8(type_byte))
    _push_varint(out, frame.stream_id)
    if frame.offset > UInt64(0):
        _push_varint(out, frame.offset)
    if emit_length:
        _push_varint(out, UInt64(len(frame.data)))
    _push_bytes(out, frame.data)


def encode_max_data(frame: MaxDataFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_MAX_DATA))
    _push_varint(out, frame.maximum_data)


def encode_max_stream_data(
    frame: MaxStreamDataFrame, mut out: List[UInt8]
) raises:
    out.append(UInt8(FRAME_TYPE_MAX_STREAM_DATA))
    _push_varint(out, frame.stream_id)
    _push_varint(out, frame.maximum_stream_data)


def encode_max_streams(frame: MaxStreamsFrame, mut out: List[UInt8]) raises:
    var t = (
        FRAME_TYPE_MAX_STREAMS_UNI if frame.unidirectional else FRAME_TYPE_MAX_STREAMS_BIDI
    )
    out.append(UInt8(t))
    _push_varint(out, frame.maximum_streams)


def encode_data_blocked(frame: DataBlockedFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_DATA_BLOCKED))
    _push_varint(out, frame.maximum_data)


def encode_stream_data_blocked(
    frame: StreamDataBlockedFrame, mut out: List[UInt8]
) raises:
    out.append(UInt8(FRAME_TYPE_STREAM_DATA_BLOCKED))
    _push_varint(out, frame.stream_id)
    _push_varint(out, frame.maximum_stream_data)


def encode_streams_blocked(
    frame: StreamsBlockedFrame, mut out: List[UInt8]
) raises:
    var t = (
        FRAME_TYPE_STREAMS_BLOCKED_UNI if frame.unidirectional else FRAME_TYPE_STREAMS_BLOCKED_BIDI
    )
    out.append(UInt8(t))
    _push_varint(out, frame.maximum_streams)


def encode_new_connection_id(
    frame: NewConnectionIdFrame, mut out: List[UInt8]
) raises:
    var cid_len = len(frame.connection_id)
    if cid_len < 1 or cid_len > 20:
        raise Error("quic new_connection_id: cid length must be in [1, 20]")
    if len(frame.stateless_reset_token) != 16:
        raise Error(
            "quic new_connection_id: stateless reset token must be 16 bytes"
        )
    if frame.retire_prior_to > frame.sequence_number:
        raise Error("quic new_connection_id: retire_prior_to > sequence_number")
    out.append(UInt8(FRAME_TYPE_NEW_CONNECTION_ID))
    _push_varint(out, frame.sequence_number)
    _push_varint(out, frame.retire_prior_to)
    out.append(UInt8(cid_len))
    _push_bytes(out, frame.connection_id)
    _push_bytes(out, frame.stateless_reset_token)


def encode_retire_connection_id(
    frame: RetireConnectionIdFrame, mut out: List[UInt8]
) raises:
    out.append(UInt8(FRAME_TYPE_RETIRE_CONNECTION_ID))
    _push_varint(out, frame.sequence_number)


def encode_path_challenge(
    frame: PathChallengeFrame, mut out: List[UInt8]
) raises:
    if len(frame.data) != 8:
        raise Error("quic path_challenge: data must be exactly 8 bytes")
    out.append(UInt8(FRAME_TYPE_PATH_CHALLENGE))
    _push_bytes(out, frame.data)


def encode_path_response(frame: PathResponseFrame, mut out: List[UInt8]) raises:
    if len(frame.data) != 8:
        raise Error("quic path_response: data must be exactly 8 bytes")
    out.append(UInt8(FRAME_TYPE_PATH_RESPONSE))
    _push_bytes(out, frame.data)


def encode_connection_close(
    frame: ConnectionCloseFrame, mut out: List[UInt8]
) raises:
    var t = (
        FRAME_TYPE_CONNECTION_CLOSE_APPLICATION if frame.application else FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT
    )
    out.append(UInt8(t))
    _push_varint(out, frame.error_code)
    if not frame.application:
        _push_varint(out, frame.frame_type)
    _push_varint(out, UInt64(len(frame.reason_phrase)))
    _push_bytes(out, frame.reason_phrase)


def encode_handshake_done(mut out: List[UInt8]):
    out.append(UInt8(FRAME_TYPE_HANDSHAKE_DONE))


# ── Top-level encode dispatcher ──────────────────────────────────────────────


def encode_frame(frame: Frame, mut out: List[UInt8]) raises:
    """Dispatch to the per-type encoder based on ``frame.kind``."""
    var k = frame.kind
    if k == FRAME_TYPE_PADDING:
        encode_padding(frame.padding_length, out)
    elif k == FRAME_TYPE_PING:
        encode_ping(out)
    elif k == FRAME_TYPE_ACK or k == FRAME_TYPE_ACK_ECN:
        encode_ack(frame.ack, out)
    elif k == FRAME_TYPE_RESET_STREAM:
        encode_reset_stream(frame.reset_stream, out)
    elif k == FRAME_TYPE_STOP_SENDING:
        encode_stop_sending(frame.stop_sending, out)
    elif k == FRAME_TYPE_CRYPTO:
        encode_crypto(frame.crypto, out)
    elif k == FRAME_TYPE_NEW_TOKEN:
        encode_new_token(frame.new_token, out)
    elif k == FRAME_TYPE_STREAM_BASE:
        encode_stream(frame.stream, out)
    elif k == FRAME_TYPE_MAX_DATA:
        encode_max_data(frame.max_data, out)
    elif k == FRAME_TYPE_MAX_STREAM_DATA:
        encode_max_stream_data(frame.max_stream_data, out)
    elif k == FRAME_TYPE_MAX_STREAMS_BIDI or k == FRAME_TYPE_MAX_STREAMS_UNI:
        encode_max_streams(frame.max_streams, out)
    elif k == FRAME_TYPE_DATA_BLOCKED:
        encode_data_blocked(frame.data_blocked, out)
    elif k == FRAME_TYPE_STREAM_DATA_BLOCKED:
        encode_stream_data_blocked(frame.stream_data_blocked, out)
    elif (
        k == FRAME_TYPE_STREAMS_BLOCKED_BIDI
        or k == FRAME_TYPE_STREAMS_BLOCKED_UNI
    ):
        encode_streams_blocked(frame.streams_blocked, out)
    elif k == FRAME_TYPE_NEW_CONNECTION_ID:
        encode_new_connection_id(frame.new_connection_id, out)
    elif k == FRAME_TYPE_RETIRE_CONNECTION_ID:
        encode_retire_connection_id(frame.retire_connection_id, out)
    elif k == FRAME_TYPE_PATH_CHALLENGE:
        encode_path_challenge(frame.path_challenge, out)
    elif k == FRAME_TYPE_PATH_RESPONSE:
        encode_path_response(frame.path_response, out)
    elif (
        k == FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT
        or k == FRAME_TYPE_CONNECTION_CLOSE_APPLICATION
    ):
        encode_connection_close(frame.connection_close, out)
    elif k == FRAME_TYPE_HANDSHAKE_DONE:
        encode_handshake_done(out)
    else:
        raise Error("quic frame: unsupported encode kind " + String(k))


# ── Per-type parsers ─────────────────────────────────────────────────────────


def _read_varint(buf: Span[UInt8, _], mut pos: Int) raises -> UInt64:
    """Decode a varint starting at ``pos`` and advance the cursor."""
    var v = decode_varint(buf[pos:])
    pos += v.consumed
    return v.value


def _read_bytes(
    buf: Span[UInt8, _], mut pos: Int, n: Int
) raises -> List[UInt8]:
    """Copy ``n`` bytes starting at ``pos`` into a fresh list."""
    if n < 0:
        raise Error("quic frame: negative byte count")
    if pos + n > len(buf):
        raise Error("quic frame: truncated payload")
    var out = List[UInt8]()
    for i in range(pos, pos + n):
        out.append(buf[i])
    pos += n
    return out^


def parse_frame(buf: Span[UInt8, _]) raises -> ParsedFrame:
    """Parse a single transport frame at the start of ``buf``.

    The QUIC frame type is itself varint-encoded (§19); for the
    22 codepoints defined in v1 the encoding is single-byte, but
    the codec reads it as a varint to stay forward-compatible
    with extension types that may register higher-numbered
    codepoints.

    Returns a :class:`ParsedFrame` carrying the typed
    :class:`Frame` plus the number of wire bytes consumed.
    """
    if len(buf) == 0:
        raise Error("quic frame: empty buffer")
    var pos = 0
    var type_var = decode_varint(buf[pos:])
    pos += type_var.consumed
    var t = Int(type_var.value)
    if t == FRAME_TYPE_PADDING:
        # Per §19.1, PADDING is one byte. The caller can collapse
        # runs by repeatedly invoking parse_frame; we surface a
        # single-frame view here so the caller can attribute byte
        # counts cleanly. A small-batch optimisation could fuse
        # consecutive 0x00s but that lives in the connection
        # state-machine layer above.
        var f = _zero_frame(FRAME_TYPE_PADDING)
        f.padding_length = 1
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_PING:
        return ParsedFrame(frame=_zero_frame(FRAME_TYPE_PING), consumed=pos)
    if t == FRAME_TYPE_ACK or t == FRAME_TYPE_ACK_ECN:
        var largest = _read_varint(buf, pos)
        var delay = _read_varint(buf, pos)
        var range_count = _read_varint(buf, pos)
        if range_count > UInt64(0x4000):
            raise Error("quic ack: range count exceeds RFC 9000 §19.3 cap")
        var first = _read_varint(buf, pos)
        var ranges = List[AckRange]()
        for _ in range(Int(range_count)):
            var gap = _read_varint(buf, pos)
            var length = _read_varint(buf, pos)
            ranges.append(AckRange(gap=gap, length=length))
        var ecn = List[EcnCounts]()
        if t == FRAME_TYPE_ACK_ECN:
            var ect0 = _read_varint(buf, pos)
            var ect1 = _read_varint(buf, pos)
            var ce = _read_varint(buf, pos)
            ecn.append(EcnCounts(ect0=ect0, ect1=ect1, ce=ce))
        var f = _zero_frame(t)
        f.ack = AckFrame(
            largest_acknowledged=largest,
            ack_delay=delay,
            first_ack_range=first,
            ranges=ranges^,
            ecn=ecn^,
        )
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_RESET_STREAM:
        var sid = _read_varint(buf, pos)
        var ec = _read_varint(buf, pos)
        var fs = _read_varint(buf, pos)
        var f = _zero_frame(FRAME_TYPE_RESET_STREAM)
        f.reset_stream = ResetStreamFrame(
            stream_id=sid, application_error_code=ec, final_size=fs
        )
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_STOP_SENDING:
        var sid = _read_varint(buf, pos)
        var ec = _read_varint(buf, pos)
        var f = _zero_frame(FRAME_TYPE_STOP_SENDING)
        f.stop_sending = StopSendingFrame(
            stream_id=sid, application_error_code=ec
        )
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_CRYPTO:
        var off = _read_varint(buf, pos)
        var n = _read_varint(buf, pos)
        var data = _read_bytes(buf, pos, Int(n))
        var f = _zero_frame(FRAME_TYPE_CRYPTO)
        f.crypto = CryptoFrame(offset=off, data=data^)
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_NEW_TOKEN:
        var n = _read_varint(buf, pos)
        if n == UInt64(0):
            raise Error("quic new_token: empty token (RFC 9000 §19.7)")
        var token = _read_bytes(buf, pos, Int(n))
        var f = _zero_frame(FRAME_TYPE_NEW_TOKEN)
        f.new_token = NewTokenFrame(token=token^)
        return ParsedFrame(frame=f^, consumed=pos)
    if t >= FRAME_TYPE_STREAM_BASE and t <= FRAME_TYPE_STREAM_MAX:
        var has_off = (t & STREAM_OFF_BIT) != 0
        var has_len = (t & STREAM_LEN_BIT) != 0
        var fin = (t & STREAM_FIN_BIT) != 0
        var sid = _read_varint(buf, pos)
        var off = UInt64(0)
        if has_off:
            off = _read_varint(buf, pos)
        var data: List[UInt8]
        if has_len:
            var n = _read_varint(buf, pos)
            data = _read_bytes(buf, pos, Int(n))
        else:
            # No explicit length -- payload extends to end of buffer.
            data = _read_bytes(buf, pos, len(buf) - pos)
        var f = _zero_frame(FRAME_TYPE_STREAM_BASE)
        f.stream = StreamFrame(stream_id=sid, offset=off, data=data^, fin=fin)
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_MAX_DATA:
        var v = _read_varint(buf, pos)
        var f = _zero_frame(FRAME_TYPE_MAX_DATA)
        f.max_data = MaxDataFrame(maximum_data=v)
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_MAX_STREAM_DATA:
        var sid = _read_varint(buf, pos)
        var v = _read_varint(buf, pos)
        var f = _zero_frame(FRAME_TYPE_MAX_STREAM_DATA)
        f.max_stream_data = MaxStreamDataFrame(
            stream_id=sid, maximum_stream_data=v
        )
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_MAX_STREAMS_BIDI or t == FRAME_TYPE_MAX_STREAMS_UNI:
        var v = _read_varint(buf, pos)
        var f = _zero_frame(t)
        f.max_streams = MaxStreamsFrame(
            unidirectional=t == FRAME_TYPE_MAX_STREAMS_UNI,
            maximum_streams=v,
        )
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_DATA_BLOCKED:
        var v = _read_varint(buf, pos)
        var f = _zero_frame(FRAME_TYPE_DATA_BLOCKED)
        f.data_blocked = DataBlockedFrame(maximum_data=v)
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_STREAM_DATA_BLOCKED:
        var sid = _read_varint(buf, pos)
        var v = _read_varint(buf, pos)
        var f = _zero_frame(FRAME_TYPE_STREAM_DATA_BLOCKED)
        f.stream_data_blocked = StreamDataBlockedFrame(
            stream_id=sid, maximum_stream_data=v
        )
        return ParsedFrame(frame=f^, consumed=pos)
    if (
        t == FRAME_TYPE_STREAMS_BLOCKED_BIDI
        or t == FRAME_TYPE_STREAMS_BLOCKED_UNI
    ):
        var v = _read_varint(buf, pos)
        var f = _zero_frame(t)
        f.streams_blocked = StreamsBlockedFrame(
            unidirectional=t == FRAME_TYPE_STREAMS_BLOCKED_UNI,
            maximum_streams=v,
        )
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_NEW_CONNECTION_ID:
        var seq = _read_varint(buf, pos)
        var retire = _read_varint(buf, pos)
        if pos >= len(buf):
            raise Error("quic new_connection_id: truncated cid length")
        var cid_len = Int(buf[pos])
        pos += 1
        if cid_len < 1 or cid_len > 20:
            raise Error("quic new_connection_id: cid length out of [1, 20]")
        var cid = _read_bytes(buf, pos, cid_len)
        var token = _read_bytes(buf, pos, 16)
        if retire > seq:
            raise Error(
                "quic new_connection_id: retire_prior_to > sequence_number"
            )
        var f = _zero_frame(FRAME_TYPE_NEW_CONNECTION_ID)
        f.new_connection_id = NewConnectionIdFrame(
            sequence_number=seq,
            retire_prior_to=retire,
            connection_id=cid^,
            stateless_reset_token=token^,
        )
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_RETIRE_CONNECTION_ID:
        var seq = _read_varint(buf, pos)
        var f = _zero_frame(FRAME_TYPE_RETIRE_CONNECTION_ID)
        f.retire_connection_id = RetireConnectionIdFrame(sequence_number=seq)
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_PATH_CHALLENGE:
        var data = _read_bytes(buf, pos, 8)
        var f = _zero_frame(FRAME_TYPE_PATH_CHALLENGE)
        f.path_challenge = PathChallengeFrame(data=data^)
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_PATH_RESPONSE:
        var data = _read_bytes(buf, pos, 8)
        var f = _zero_frame(FRAME_TYPE_PATH_RESPONSE)
        f.path_response = PathResponseFrame(data=data^)
        return ParsedFrame(frame=f^, consumed=pos)
    if (
        t == FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT
        or t == FRAME_TYPE_CONNECTION_CLOSE_APPLICATION
    ):
        var ec = _read_varint(buf, pos)
        var ft = UInt64(0)
        if t == FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT:
            ft = _read_varint(buf, pos)
        var rn = _read_varint(buf, pos)
        var reason = _read_bytes(buf, pos, Int(rn))
        var f = _zero_frame(t)
        f.connection_close = ConnectionCloseFrame(
            application=t == FRAME_TYPE_CONNECTION_CLOSE_APPLICATION,
            error_code=ec,
            frame_type=ft,
            reason_phrase=reason^,
        )
        return ParsedFrame(frame=f^, consumed=pos)
    if t == FRAME_TYPE_HANDSHAKE_DONE:
        return ParsedFrame(
            frame=_zero_frame(FRAME_TYPE_HANDSHAKE_DONE),
            consumed=pos,
        )
    raise Error("quic frame: unknown type " + String(t))
