"""``flare.h3`` — sans-I/O HTTP/3 codec primitives (RFC 9114).

HTTP/3 maps onto QUIC streams: each request lives on its own
bidirectional stream, and the application data is a sequence of
type-length-payload framed messages defined in RFC 9114 §7.

This package ships the *codec* layer of HTTP/3: pure byte-in /
byte-out parsers and emitters for frames. The QUIC stream layer
(reactor + flow control) and the header-block decoder (QPACK)
are deliberately separate modules; this package depends only on
the varint codec in :mod:`flare.quic.varint`.

Public re-exports:

- :class:`H3Frame`, :class:`H3FrameType` — the parsed-frame
  carrier + named frame-type constants.
- :func:`encode_h3_frame`, :func:`decode_h3_frame` — byte-level
  codec helpers.
- :func:`decode_h3_settings`, :func:`encode_h3_settings` — the
  HTTP/3 SETTINGS frame payload codec (a list of ``identifier:
  value`` varint pairs, RFC 9114 §7.2.4).
"""

from .frame import (
    H3FrameType,
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    H3_FRAME_TYPE_CANCEL_PUSH,
    H3_FRAME_TYPE_SETTINGS,
    H3_FRAME_TYPE_PUSH_PROMISE,
    H3_FRAME_TYPE_GOAWAY,
    H3_FRAME_TYPE_MAX_PUSH_ID,
    H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
    H3_SETTINGS_QPACK_BLOCKED_STREAMS,
    H3_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    H3Frame,
    H3Setting,
    decode_h3_frame,
    encode_h3_frame,
    decode_h3_settings,
    encode_h3_settings,
)
from .request_reader import (
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
    H3RequestEvent,
    H3RequestReader,
    feed,
)
