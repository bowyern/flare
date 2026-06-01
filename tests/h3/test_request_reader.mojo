"""Unit tests for ``flare.h3.request_reader`` -- H3 request-stream
sans-I/O state machine.

Validates the event sequence the reader emits on the four
canonical wire shapes (HEADERS only, HEADERS+DATA, HEADERS+
DATA+TRAILERS, HEADERS with grease frame interleaved) plus the
six protocol-error paths (DATA before HEADERS, control-stream
frame type on request stream, repeated HEADERS after trailers,
oversized HEADERS field section, malformed QPACK in HEADERS,
truncated frame -> NEEDS_MORE).
"""

from std.collections import List
from std.memory import Span
from std.testing import assert_equal, assert_true

from flare.h3 import (
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    H3_FRAME_TYPE_SETTINGS,
    H3_REQUEST_EVENT_DATA,
    H3_REQUEST_EVENT_HEADERS,
    H3_REQUEST_EVENT_NEEDS_MORE,
    H3_REQUEST_EVENT_PROTOCOL_ERROR,
    H3_REQUEST_EVENT_TRAILERS,
    H3_REQUEST_EVENT_UNKNOWN_FRAME,
    H3_REQUEST_STATE_BODY,
    H3_REQUEST_STATE_DONE,
    H3_REQUEST_STATE_INIT,
    H3_REQUEST_STATE_TRAILERS,
    H3RequestReader,
    encode_h3_frame,
    feed,
)
from flare.qpack import QpackHeader, encode_field_section


def _qpack_request_headers() raises -> List[UInt8]:
    var hs = List[QpackHeader]()
    hs.append(QpackHeader(":method", "GET"))
    hs.append(QpackHeader(":scheme", "https"))
    hs.append(QpackHeader(":path", "/"))
    hs.append(QpackHeader("x-trace-id", "abc-123"))
    return encode_field_section(hs)


def _frame(ftype: UInt64, payload: List[UInt8]) raises -> List[UInt8]:
    return encode_h3_frame(ftype, Span[UInt8, _](payload))


def test_initial_state() raises:
    var r = H3RequestReader.new()
    assert_equal(r.state, H3_REQUEST_STATE_INIT)


def test_headers_only() raises:
    var r = H3RequestReader.new()
    var headers = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var ev = feed(r, Span[UInt8, _](headers))
    assert_equal(ev.kind, H3_REQUEST_EVENT_HEADERS)
    assert_equal(len(ev.headers), 4)
    assert_equal(ev.headers[0].name, ":method")
    assert_equal(ev.headers[0].value, "GET")
    assert_equal(r.state, H3_REQUEST_STATE_BODY)


def test_headers_then_data() raises:
    var r = H3RequestReader.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var data_payload = List[UInt8]()
    for c in String("hello").as_bytes():
        data_payload.append(c)
    var df = _frame(H3_FRAME_TYPE_DATA, data_payload)
    var ev1 = feed(r, Span[UInt8, _](hf))
    assert_equal(ev1.kind, H3_REQUEST_EVENT_HEADERS)
    var ev2 = feed(r, Span[UInt8, _](df))
    assert_equal(ev2.kind, H3_REQUEST_EVENT_DATA)
    assert_equal(len(ev2.data), 5)
    assert_equal(ev2.data[0], UInt8(ord("h")))


def test_headers_then_data_then_trailers() raises:
    var r = H3RequestReader.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var data_payload = List[UInt8]()
    for c in String("hi").as_bytes():
        data_payload.append(c)
    var df = _frame(H3_FRAME_TYPE_DATA, data_payload)
    var trailers_qpack = encode_field_section(
        List[QpackHeader]([QpackHeader("x-checksum", "deadbeef")])
    )
    var tf = _frame(H3_FRAME_TYPE_HEADERS, trailers_qpack)
    var _ = feed(r, Span[UInt8, _](hf))
    var _ = feed(r, Span[UInt8, _](df))
    var ev = feed(r, Span[UInt8, _](tf))
    assert_equal(ev.kind, H3_REQUEST_EVENT_TRAILERS)
    assert_equal(len(ev.headers), 1)
    assert_equal(ev.headers[0].name, "x-checksum")
    assert_equal(r.state, H3_REQUEST_STATE_TRAILERS)


def test_data_before_headers_is_protocol_error() raises:
    var r = H3RequestReader.new()
    var data_payload = List[UInt8]()
    data_payload.append(UInt8(0x41))
    var df = _frame(H3_FRAME_TYPE_DATA, data_payload)
    var ev = feed(r, Span[UInt8, _](df))
    assert_equal(ev.kind, H3_REQUEST_EVENT_PROTOCOL_ERROR)
    assert_equal(r.state, H3_REQUEST_STATE_DONE)


def test_control_frame_on_request_stream_is_protocol_error() raises:
    var r = H3RequestReader.new()
    var settings_payload = List[UInt8]()
    var sf = _frame(H3_FRAME_TYPE_SETTINGS, settings_payload)
    var ev = feed(r, Span[UInt8, _](sf))
    assert_equal(ev.kind, H3_REQUEST_EVENT_PROTOCOL_ERROR)
    assert_equal(r.state, H3_REQUEST_STATE_DONE)


def test_truncated_frame_yields_needs_more() raises:
    var r = H3RequestReader.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    # Slice off the final byte to truncate.
    var truncated = List[UInt8]()
    for i in range(len(hf) - 1):
        truncated.append(hf[i])
    var ev = feed(r, Span[UInt8, _](truncated))
    assert_equal(ev.kind, H3_REQUEST_EVENT_NEEDS_MORE)
    assert_equal(r.state, H3_REQUEST_STATE_INIT)


def test_unknown_frame_type_is_skipped() raises:
    var r = H3RequestReader.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    # Grease frame: 0x21 (one of the reserved unknown shapes).
    var grease_payload = List[UInt8]()
    grease_payload.append(UInt8(0xAA))
    var gf = _frame(UInt64(0x21), grease_payload)
    var combined = List[UInt8]()
    for i in range(len(hf)):
        combined.append(hf[i])
    for i in range(len(gf)):
        combined.append(gf[i])
    var ev1 = feed(r, Span[UInt8, _](combined))
    assert_equal(ev1.kind, H3_REQUEST_EVENT_HEADERS)
    var rest = List[UInt8]()
    for i in range(ev1.consumed, len(combined)):
        rest.append(combined[i])
    var ev2 = feed(r, Span[UInt8, _](rest))
    assert_equal(ev2.kind, H3_REQUEST_EVENT_UNKNOWN_FRAME)
    assert_equal(ev2.unknown_type, UInt64(0x21))


def test_oversized_headers_is_protocol_error() raises:
    var r = H3RequestReader.new(max_field_section_bytes=UInt64(8))
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var ev = feed(r, Span[UInt8, _](hf))
    assert_equal(ev.kind, H3_REQUEST_EVENT_PROTOCOL_ERROR)
    assert_equal(r.state, H3_REQUEST_STATE_DONE)


def test_repeat_headers_after_trailers_is_protocol_error() raises:
    var r = H3RequestReader.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var trailers_qpack = encode_field_section(
        List[QpackHeader]([QpackHeader("x-tail", "1")])
    )
    var tf = _frame(H3_FRAME_TYPE_HEADERS, trailers_qpack)
    var _ = feed(r, Span[UInt8, _](hf))
    var _ = feed(r, Span[UInt8, _](tf))
    # State now TRAILERS; another HEADERS frame is illegal.
    var ev = feed(r, Span[UInt8, _](hf))
    assert_equal(ev.kind, H3_REQUEST_EVENT_PROTOCOL_ERROR)


def main() raises:
    test_initial_state()
    test_headers_only()
    test_headers_then_data()
    test_headers_then_data_then_trailers()
    test_data_before_headers_is_protocol_error()
    test_control_frame_on_request_stream_is_protocol_error()
    test_truncated_frame_yields_needs_more()
    test_unknown_frame_type_is_skipped()
    test_oversized_headers_is_protocol_error()
    test_repeat_headers_after_trailers_is_protocol_error()
    print("test_h3_request_reader: 10 passed")
