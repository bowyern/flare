"""``flare.h3.server`` -- HTTP/3 server connection driver (Track Q4 scaffold).

Wraps the sans-I/O HTTP/3 codec primitives
(:class:`flare.h3.H3RequestReader`,
:func:`flare.h3.encode_response_headers`) and the QUIC connection
driver (:class:`flare.quic.server.QuicConnection`) into a per-
connection HTTP/3 server. The full driver -- per-stream
``Handler`` dispatch, control stream lifecycle, settings
exchange, push, GOAWAY, and the QPACK encoder + decoder streams
-- lands in a focused follow-up commit. This module ships the
typed boundary the QUIC reactor + ALPN dispatcher build against.

## Stream layout (RFC 9114 §6)

HTTP/3 over QUIC uses four families of streams:

* **Bidirectional request streams** -- one per request/response
  exchange. The client opens, sends HEADERS + DATA frames; the
  server replies on the same stream with HEADERS + DATA + (FIN).
* **Unidirectional control stream** (type 0x00) -- exactly one
  per direction; carries SETTINGS first, then GOAWAY /
  MAX_PUSH_ID over the connection lifetime.
* **Unidirectional push stream** (type 0x01) -- server-initiated.
  Not implemented in the v0.8 Phase D scaffold (RFC 9114
  deprecates push as of revision 9).
* **Unidirectional QPACK encoder stream** (type 0x02) +
  **decoder stream** (type 0x03) -- carry dynamic-table
  instructions. The v0.8 Phase D scaffold runs QPACK in
  static-table-only mode (Track Q4 follow-up: stream-acked
  dynamic-table inserts).

## What ships here

- :class:`H3ConnectionConfig` -- per-connection HTTP/3 config:
  max field section size, max blocked streams, the GOAWAY
  threshold above which the server stops accepting new
  request streams.
- :class:`H3Connection` -- the per-connection driver carrier.
  Owns the per-stream :class:`H3RequestReader` instances (keyed
  by QUIC stream ID), the control-stream encoder + decoder, and
  the QPACK state.
- :class:`H3StreamType` -- the unidirectional-stream type
  codepoints from RFC 9114 §6.2.

## What's deferred

- `feed_stream_chunk` / `take_response_frames` -- the actual
  per-stream dispatch loop. Requires the QUIC reactor (Track Q3)
  to feed reassembled stream chunks in.
- Control-stream + SETTINGS exchange wiring. Requires the
  driver-level state machine to be alive end-to-end.
- QPACK dynamic-table inserts. Today static-table only.

References:
- RFC 9114 "HTTP/3".
- RFC 9204 "QPACK: Field Compression for HTTP/3".
"""

from std.collections import Dict, List, Optional

from flare.h3.request_reader import H3RequestReader


# ── Unidirectional stream type codepoints (RFC 9114 §6.2) ───────────────


struct H3StreamType:
    """RFC 9114 §6.2 unidirectional stream types.

    Each uni stream's first varint is the stream type; the reader
    dispatches on this varint to the matching internal state
    machine (control / push / qpack-enc / qpack-dec).
    """

    comptime CONTROL: Int = 0x00
    """RFC 9114 §6.2.1 -- control stream. Carries SETTINGS,
    GOAWAY, MAX_PUSH_ID. Exactly one per direction."""

    comptime PUSH: Int = 0x01
    """RFC 9114 §6.2.2 -- push stream. Server-initiated.
    Deprecated as of RFC 9114 revision 9; this codepoint is
    carried so the reader can reject incoming push streams with
    H3_STREAM_CREATION_ERROR."""

    comptime QPACK_ENCODER: Int = 0x02
    """RFC 9204 §4.2 -- QPACK encoder stream. Carries dynamic-
    table insert instructions."""

    comptime QPACK_DECODER: Int = 0x03
    """RFC 9204 §4.2 -- QPACK decoder stream. Carries
    section-acknowledgement + stream-cancellation instructions."""


# ── Configuration carrier ──────────────────────────────────────────────


struct H3ConnectionConfig(Copyable, Defaultable, Movable):
    """Per-connection HTTP/3 settings.

    The server advertises these via the control stream's SETTINGS
    frame (RFC 9114 §7.2.4). Production defaults match the values
    the OpenAPI gen + the cookbook examples expect.
    """

    var max_field_section_size: UInt64
    """RFC 9114 §7.2.4.2 -- maximum total size (in bytes) the
    server will accept for a single field section. Default:
    65536. The reader rejects oversize header blocks with
    H3_EXCESSIVE_LOAD."""

    var qpack_max_table_capacity: UInt64
    """RFC 9204 §3.2.2 -- maximum bytes the server is willing to
    spend on the QPACK dynamic table. Default 0 means static-
    table-only mode (the Track Q4 scaffold default)."""

    var qpack_blocked_streams: UInt64
    """RFC 9204 §3.2.3 -- maximum streams the server is willing
    to leave blocked on QPACK dynamic-table insertions. Default
    0 (paired with qpack_max_table_capacity=0)."""

    var enable_connect_protocol: Bool
    """RFC 9220 §3 -- whether to advertise CONNECT-Protocol
    support for WebSocket / WebTransport bootstrapping. Default
    True since the rest of flare supports CONNECT semantics."""

    var goaway_threshold_streams: UInt64
    """Local soft cap on the stream count above which the server
    emits GOAWAY and refuses new request streams. Default
    UINT64_MAX (effectively no cap; mirrors the H2 server's
    behaviour)."""

    def __init__(out self):
        self.max_field_section_size = UInt64(65536)
        self.qpack_max_table_capacity = UInt64(0)
        self.qpack_blocked_streams = UInt64(0)
        self.enable_connect_protocol = True
        self.goaway_threshold_streams = UInt64((1 << 63) - 1)


# ── Per-connection driver ──────────────────────────────────────────────


struct H3Connection(Defaultable, Movable):
    """Per-connection HTTP/3 server driver.

    Owned by the QUIC reactor. One instance per QUIC connection
    that negotiated the ``h3`` ALPN identifier. The driver:

    * Tracks per-bidirectional-stream :class:`H3RequestReader`
      instances keyed by QUIC stream ID.
    * Carries the SETTINGS the server announced + the client
      announced.
    * Tracks the control-stream lifecycle (whether the peer's
      SETTINGS arrived yet, whether GOAWAY was emitted).
    * Carries the QPACK state. Static-table-only in the v0.8
      Phase D scaffold; dynamic table follow-up.

    The driver is sans-I/O: the QUIC reactor feeds reassembled
    stream chunks in via :meth:`feed_stream_chunk` and drains
    pending outbound frames via :meth:`take_response_frames`.
    """

    var config: H3ConnectionConfig
    """Local configuration -- the values the server advertises
    via SETTINGS."""

    var peer_settings_received: Bool
    """Whether the peer's SETTINGS frame has arrived on the
    control stream yet. Until True, the driver buffers any
    application traffic that would depend on the negotiated
    field-section-size + QPACK parameters."""

    var goaway_emitted: Bool
    """Whether the server has emitted GOAWAY. Once True, new
    request streams are rejected with H3_REQUEST_CANCELLED."""

    var request_readers: Dict[Int, H3RequestReader]
    """Per-stream :class:`H3RequestReader` carriers. Keys are
    QUIC stream IDs. Streams are removed once the reader emits
    on_end_of_request + the server has emitted a response."""

    var control_stream_id: Int
    """QUIC stream ID of the locally-opened control stream. -1
    until the driver opens the control stream during connection
    setup."""

    var qpack_encoder_stream_id: Int
    """QUIC stream ID of the locally-opened QPACK encoder
    stream. -1 in static-only mode."""

    var qpack_decoder_stream_id: Int
    """QUIC stream ID of the locally-opened QPACK decoder
    stream. -1 in static-only mode."""

    def __init__(out self):
        self.config = H3ConnectionConfig()
        self.peer_settings_received = False
        self.goaway_emitted = False
        self.request_readers = Dict[Int, H3RequestReader]()
        self.control_stream_id = -1
        self.qpack_encoder_stream_id = -1
        self.qpack_decoder_stream_id = -1

    @staticmethod
    def with_config(config: H3ConnectionConfig) -> Self:
        """Construct with a non-default config carrier."""
        var out = Self()
        out.config = config.copy()
        return out^

    def open_request_stream(mut self, stream_id: Int) raises:
        """Allocate a per-stream reader for an inbound
        bidirectional QUIC stream. Idempotent: re-opening the
        same stream ID is a no-op (the QUIC reactor occasionally
        fires the open event redundantly when a stream sees
        both HEADERS and DATA before the dispatcher polls).
        """
        if stream_id in self.request_readers:
            return
        if self.goaway_emitted:
            raise Error(
                "H3Connection.open_request_stream: GOAWAY emitted;"
                " new request streams are rejected"
            )
        self.request_readers[stream_id] = H3RequestReader.new(
            self.config.max_field_section_size
        )

    def close_request_stream(mut self, stream_id: Int) raises:
        """Drop the per-stream reader. Called after the response
        FIN has been emitted (so the server doesn't keep parser
        state around for a stream that's done)."""
        if stream_id in self.request_readers:
            _ = self.request_readers.pop(stream_id)

    def has_stream(self, stream_id: Int) -> Bool:
        """Whether the driver currently tracks a reader for this
        stream ID. Useful for testing the open / close lifecycle
        without needing the full reactor."""
        return stream_id in self.request_readers

    def active_request_count(self) -> Int:
        """Number of active per-stream readers. The reactor uses
        this to decide when to emit GOAWAY (above
        ``goaway_threshold_streams``)."""
        return len(self.request_readers)

    def feed_stream_chunk(mut self, stream_id: Int, chunk: List[UInt8]) raises:
        """Feed a reassembled stream-data chunk into the per-
        stream reader. The reader fires its event callbacks
        synchronously into the driver, which buffers any
        pending response frames for the matching stream.

        Today raises because the per-stream callback wiring
        plus the response-writer integration ship in the
        Track Q4 follow-up commit.
        """
        raise Error(
            "H3Connection.feed_stream_chunk: per-stream dispatch"
            " not yet implemented. Track Q4 follow-up commit"
            " lands the H3RequestReader -> Handler -> response"
            " writer wiring. stream_id="
            + String(stream_id)
            + ", chunk_len="
            + String(len(chunk))
        )

    def take_response_frames(mut self, stream_id: Int) raises -> List[UInt8]:
        """Drain pending outbound bytes the response writer
        produced for ``stream_id`` and return them to the
        reactor for emission as QUIC stream-data.

        Today raises pending the per-stream wiring.
        """
        raise Error(
            "H3Connection.take_response_frames: response-frame"
            " queue not yet implemented (Track Q4 follow-up)."
            " stream_id="
            + String(stream_id)
        )
