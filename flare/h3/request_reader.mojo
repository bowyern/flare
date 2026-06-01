"""HTTP/3 request-stream reader -- sans-I/O state machine.

An HTTP/3 request lives on a single bidirectional QUIC stream:
the client emits a HEADERS frame (QPACK-encoded request pseudo-
headers + application headers), zero or more DATA frames carrying
the request body, and optionally a trailing HEADERS frame for
trailers. The stream's FIN bit closes the request side of the
exchange.

This module ships the codec-side reader that turns a stream of
bytes into a typed event sequence:

* ``H3RequestEvent.HEADERS`` -- a complete HEADERS frame has been
  parsed. The decoded :class:`QpackHeader` list is attached.
* ``H3RequestEvent.DATA``    -- a DATA frame's payload is ready.
* ``H3RequestEvent.NEEDS_MORE`` -- the buffer does not yet hold a
  complete next frame; the caller should accumulate more bytes
  and call again.
* ``H3RequestEvent.UNKNOWN_FRAME`` -- an unknown / grease frame
  type was parsed; receivers MUST ignore (RFC 9114 §7.2.8). The
  reader skips the payload bytes and surfaces the event so the
  caller can log it.
* ``H3RequestEvent.PROTOCOL_ERROR`` -- the byte stream is
  malformed (truncated varint, oversize length, QPACK decode
  failure, repeated HEADERS); the caller surfaces this as an
  H3_FRAME_UNEXPECTED / QPACK_DECOMPRESSION_FAILED stream-level
  error to the QUIC peer.

Sans-I/O contract: the reader holds zero socket / QUIC
references; it operates on byte spans that the QUIC stream
reassembly layer hands it. The H3 server reactor wraps this
in a per-stream loop that calls ``feed`` after every QUIC
DATA chunk arrival.

References:
- RFC 9114 §4 (HTTP Message Exchanges) + §7 (Frames).
- RFC 9204 (QPACK) -- field-section decoder used for HEADERS.
"""

from std.collections import List
from std.memory import Span

from flare.qpack import QpackHeader, decode_field_section
from flare.quic.varint import decode_varint

from .frame import (
    H3_FRAME_TYPE_CANCEL_PUSH,
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_GOAWAY,
    H3_FRAME_TYPE_HEADERS,
    H3_FRAME_TYPE_MAX_PUSH_ID,
    H3_FRAME_TYPE_PUSH_PROMISE,
    H3_FRAME_TYPE_SETTINGS,
    H3FrameType,
)


# ── Event tags ─────────────────────────────────────────────────────────────


comptime H3_REQUEST_EVENT_HEADERS: Int = 0
comptime H3_REQUEST_EVENT_DATA: Int = 1
comptime H3_REQUEST_EVENT_NEEDS_MORE: Int = 2
comptime H3_REQUEST_EVENT_UNKNOWN_FRAME: Int = 3
comptime H3_REQUEST_EVENT_PROTOCOL_ERROR: Int = 4
comptime H3_REQUEST_EVENT_TRAILERS: Int = 5


# ── State tags ─────────────────────────────────────────────────────────────


comptime H3_REQUEST_STATE_INIT: Int = 0
"""Awaiting the first HEADERS frame on this request stream."""
comptime H3_REQUEST_STATE_BODY: Int = 1
"""HEADERS received; reading DATA + optional trailers."""
comptime H3_REQUEST_STATE_TRAILERS: Int = 2
"""Trailers received; the next event must be NEEDS_MORE or
end-of-stream signalled by the caller. Receiving any further
frame is a PROTOCOL_ERROR."""
comptime H3_REQUEST_STATE_DONE: Int = 3
"""Stream is closed; further calls are no-ops."""


@fieldwise_init
struct H3RequestEvent(Copyable, Movable):
    """Output of one ``feed`` step.

    The ``kind`` field is one of the ``H3_REQUEST_EVENT_*``
    constants. The other fields are populated only on relevant
    events (``headers`` for HEADERS / TRAILERS, ``data`` for
    DATA, ``unknown_type`` for UNKNOWN_FRAME, ``error_message``
    for PROTOCOL_ERROR). The ``consumed`` field reports how many
    bytes were consumed from the input span -- the caller uses
    it to advance its own buffer cursor.
    """

    var kind: Int
    var headers: List[QpackHeader]
    var data: List[UInt8]
    var unknown_type: UInt64
    var error_message: String
    var consumed: Int


def _empty_event(kind: Int, consumed: Int) -> H3RequestEvent:
    return H3RequestEvent(
        kind=kind,
        headers=List[QpackHeader](),
        data=List[UInt8](),
        unknown_type=UInt64(0),
        error_message=String(""),
        consumed=consumed,
    )


# ── Reader ─────────────────────────────────────────────────────────────────


@fieldwise_init
struct H3RequestReader(Copyable, Movable):
    """Per-stream H3 request-side reader.

    The reader is stateful: it tracks whether the initial HEADERS
    frame has been seen so a second HEADERS frame can be classified
    as either trailers (legal, after at least one DATA frame in
    practice but the spec allows zero) or a protocol error
    (e.g. when the state has already advanced to TRAILERS).
    """

    var state: Int
    var max_field_section_bytes: UInt64

    @staticmethod
    def new(max_field_section_bytes: UInt64 = UInt64(8192)) -> Self:
        return Self(
            state=H3_REQUEST_STATE_INIT,
            max_field_section_bytes=max_field_section_bytes,
        )


def _parse_frame_header(
    buf: Span[UInt8, _],
) raises -> Tuple[UInt64, UInt64, Int]:
    """Decode the (type-varint, length-varint) header that
    prefixes every H3 frame and return ``(type, length,
    header_size)``.
    """
    if len(buf) == 0:
        raise Error("h3 reader: empty buffer at frame header")
    var type_var = decode_varint(buf)
    var rest = buf[type_var.consumed :]
    if len(rest) == 0:
        raise Error("h3 reader: type without length")
    var len_var = decode_varint(rest)
    return Tuple[UInt64, UInt64, Int](
        type_var.value,
        len_var.value,
        type_var.consumed + len_var.consumed,
    )


def feed(
    mut reader: H3RequestReader,
    buf: Span[UInt8, _],
) raises -> H3RequestEvent:
    """Try to parse the next H3 frame at the start of ``buf``.

    Returns:
    * ``NEEDS_MORE`` if the buffer is truncated -- the caller
      accumulates more bytes and re-calls.
    * ``HEADERS``   on a complete first HEADERS frame; updates
      the reader's state to ``BODY``.
    * ``TRAILERS``  on a HEADERS frame received while in
      ``BODY`` state; updates the reader's state to
      ``TRAILERS``.
    * ``DATA``      on a complete DATA frame.
    * ``UNKNOWN_FRAME`` on any frame whose type is unknown / grease;
      consumes the frame entirely (RFC 9114 §7.2.8).
    * ``PROTOCOL_ERROR`` on a malformed or out-of-sequence frame
      (e.g. DATA before HEADERS, repeated HEADERS in TRAILERS
      state, oversize HEADERS field section, QPACK decode
      failure). The reader's state advances to ``DONE`` so
      further calls are no-ops.
    """
    if reader.state == H3_REQUEST_STATE_DONE:
        return _empty_event(H3_REQUEST_EVENT_NEEDS_MORE, 0)
    if len(buf) == 0:
        return _empty_event(H3_REQUEST_EVENT_NEEDS_MORE, 0)

    # Try to read the frame header without committing to advancing
    # the reader state -- a truncated input must be NEEDS_MORE,
    # not PROTOCOL_ERROR.
    var ftype: UInt64
    var flen: UInt64
    var header_size: Int
    try:
        var t = _parse_frame_header(buf)
        ftype = t[0]
        flen = t[1]
        header_size = t[2]
    except:
        return _empty_event(H3_REQUEST_EVENT_NEEDS_MORE, 0)
    var total = header_size + Int(flen)
    if total > len(buf):
        return _empty_event(H3_REQUEST_EVENT_NEEDS_MORE, 0)

    # Frame is fully present. Dispatch on type + state.
    if ftype == H3_FRAME_TYPE_HEADERS:
        if reader.state == H3_REQUEST_STATE_TRAILERS:
            reader.state = H3_REQUEST_STATE_DONE
            var ev = _empty_event(H3_REQUEST_EVENT_PROTOCOL_ERROR, total)
            ev.error_message = String("h3 reader: HEADERS after trailers")
            return ev^
        if flen > reader.max_field_section_bytes:
            reader.state = H3_REQUEST_STATE_DONE
            var ev = _empty_event(H3_REQUEST_EVENT_PROTOCOL_ERROR, total)
            ev.error_message = String(
                "h3 reader: HEADERS field section above limit"
            )
            return ev^
        var payload = buf[header_size:total]
        var headers: List[QpackHeader]
        try:
            headers = decode_field_section(payload)
        except:
            reader.state = H3_REQUEST_STATE_DONE
            var ev = _empty_event(H3_REQUEST_EVENT_PROTOCOL_ERROR, total)
            ev.error_message = String("h3 reader: QPACK decode failed")
            return ev^
        if reader.state == H3_REQUEST_STATE_INIT:
            reader.state = H3_REQUEST_STATE_BODY
            return H3RequestEvent(
                kind=H3_REQUEST_EVENT_HEADERS,
                headers=headers^,
                data=List[UInt8](),
                unknown_type=UInt64(0),
                error_message=String(""),
                consumed=total,
            )
        # In BODY -- this is the trailers frame.
        reader.state = H3_REQUEST_STATE_TRAILERS
        return H3RequestEvent(
            kind=H3_REQUEST_EVENT_TRAILERS,
            headers=headers^,
            data=List[UInt8](),
            unknown_type=UInt64(0),
            error_message=String(""),
            consumed=total,
        )

    if ftype == H3_FRAME_TYPE_DATA:
        if reader.state != H3_REQUEST_STATE_BODY:
            reader.state = H3_REQUEST_STATE_DONE
            var ev = _empty_event(H3_REQUEST_EVENT_PROTOCOL_ERROR, total)
            ev.error_message = String("h3 reader: DATA outside body window")
            return ev^
        var data = List[UInt8](capacity=Int(flen))
        for i in range(header_size, total):
            data.append(buf[i])
        return H3RequestEvent(
            kind=H3_REQUEST_EVENT_DATA,
            headers=List[QpackHeader](),
            data=data^,
            unknown_type=UInt64(0),
            error_message=String(""),
            consumed=total,
        )

    # CANCEL_PUSH / SETTINGS / PUSH_PROMISE / GOAWAY / MAX_PUSH_ID
    # are all illegal on a request stream (RFC 9114 §6.2). The
    # control-frame types belong on the unidirectional control
    # streams; emitting them here is a hard protocol error.
    if (
        ftype == H3_FRAME_TYPE_SETTINGS
        or ftype == H3_FRAME_TYPE_GOAWAY
        or ftype == H3_FRAME_TYPE_MAX_PUSH_ID
        or ftype == H3_FRAME_TYPE_CANCEL_PUSH
        or ftype == H3_FRAME_TYPE_PUSH_PROMISE
    ):
        reader.state = H3_REQUEST_STATE_DONE
        var ev = _empty_event(H3_REQUEST_EVENT_PROTOCOL_ERROR, total)
        ev.error_message = String(
            "h3 reader: control-stream frame type on request stream"
        )
        return ev^

    # Unknown / grease -- ignore per RFC 9114 §7.2.8.
    return H3RequestEvent(
        kind=H3_REQUEST_EVENT_UNKNOWN_FRAME,
        headers=List[QpackHeader](),
        data=List[UInt8](),
        unknown_type=ftype,
        error_message=String(""),
        consumed=total,
    )
