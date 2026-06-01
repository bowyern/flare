"""``flare.quic`` — sans-I/O QUIC v1 codec primitives (RFC 9000).

This package ships the *codec* layer of QUIC: pure byte-in /
byte-out parsers and emitters for the wire format, plus pure
state machines and congestion-controller helpers that operate
on owned value-typed state. It contains no socket I/O and no
TLS handshake. Every public type's contract is "give me bytes,
get back a typed value (and optionally error context); give me
a typed value, get back bytes".

The codec layer is the load-bearing foundation that downstream
modules (the QUIC reactor + datagram pump, the TLS handshake
adapter that drives the CRYPTO frames) will build on top of.
Shipping the codec layer first lets us cross-validate against
reference fixtures before committing to a particular reactor /
TLS design.

Public re-exports:

- :mod:`.varint` — variable-length integer codec
  (RFC 9000 §16): :class:`Varint`, :func:`encode_varint`,
  :func:`decode_varint`, :func:`varint_encoded_length`,
  :data:`VARINT_MAX`.
- :mod:`.packet` — long / short header codec
  (RFC 9000 §17): :class:`ConnectionId`, :class:`LongHeader`,
  :class:`ShortHeader`, :class:`InitialExtras`, the
  ``PACKET_TYPE_*`` constants, and their byte-level helpers.
- :mod:`.frame` — all 22 RFC 9000 §19 transport frames behind
  a single discriminated :class:`Frame` union, plus
  :func:`encode_frame` / :func:`parse_frame`.
- :mod:`.transport_params` — RFC 9000 §18 transport-parameter
  codec: :class:`TransportParameters`,
  :func:`encode_transport_parameters`,
  :func:`decode_transport_parameters`, and the ``TP_ID_*``
  constants for every parameter the codec carries.
- :mod:`.state` — RFC 9000 §3 / §13 sans-I/O connection +
  stream state machines: :class:`Connection`, :class:`Stream`,
  :func:`handle_frame`, :func:`mark_handshake_complete`,
  :func:`is_idle_timeout_expired`, :func:`connection_close`,
  and the ``CONN_STATE_*`` / ``STREAM_STATE_*`` constants.
- :mod:`.cc` — CUBIC + HyStart++ congestion controller and
  pacing budget (RFC 9438 + RFC 9406 + RFC 9002 §7.7) as
  pure functions over a :class:`CcState` value:
  :func:`cc_init`, :func:`on_packet_sent`,
  :func:`on_ack_received`, :func:`on_packets_lost`,
  :func:`on_round_start`, :func:`pacing_budget`,
  :func:`pacing_rate_bytes_per_second`, :func:`can_send`.
"""

from .varint import (
    VARINT_MAX,
    Varint,
    decode_varint,
    encode_varint,
    varint_encoded_length,
)
from .packet import (
    QUIC_VERSION_1,
    QUIC_VERSION_NEGOTIATION,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ZERO_RTT,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_RETRY,
    MAX_CID_LENGTH,
    ConnectionId,
    LongHeader,
    InitialExtras,
    ShortHeader,
    encode_long_header,
    encode_short_header,
    parse_long_header,
    parse_initial_extras,
    parse_short_header,
)
from .frame import (
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
from .transport_params import (
    DEFAULT_ACK_DELAY_EXPONENT,
    DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    DEFAULT_MAX_ACK_DELAY,
    DEFAULT_MAX_UDP_PAYLOAD_SIZE,
    TP_ID_ACK_DELAY_EXPONENT,
    TP_ID_ACTIVE_CONNECTION_ID_LIMIT,
    TP_ID_DISABLE_ACTIVE_MIGRATION,
    TP_ID_INITIAL_MAX_DATA,
    TP_ID_INITIAL_MAX_STREAMS_BIDI,
    TP_ID_INITIAL_MAX_STREAMS_UNI,
    TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
    TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    TP_ID_INITIAL_MAX_STREAM_DATA_UNI,
    TP_ID_INITIAL_SCID,
    TP_ID_MAX_ACK_DELAY,
    TP_ID_MAX_IDLE_TIMEOUT,
    TP_ID_MAX_UDP_PAYLOAD_SIZE,
    TP_ID_ORIGINAL_DCID,
    TP_ID_PREFERRED_ADDRESS,
    TP_ID_RETRY_SCID,
    TP_ID_STATELESS_RESET_TOKEN,
    TransportParameters,
    decode_transport_parameters,
    empty_transport_parameters,
    encode_transport_parameters,
)
from .cc import (
    CUBIC_BETA_DEN,
    CUBIC_BETA_NUM,
    CUBIC_C_DEN,
    CUBIC_C_NUM,
    CcState,
    DEFAULT_MSS_BYTES,
    HYSTART_HIGH_RTT_THRESHOLD_MS,
    HYSTART_LOW_RTT_THRESHOLD_MS,
    HYSTART_RTT_SAMPLE_COUNT,
    INITIAL_WINDOW_PACKETS,
    MIN_WINDOW_PACKETS,
    PACING_GAIN_DEN,
    PACING_GAIN_NUM,
    can_send,
    cc_init,
    on_ack_received,
    on_packet_sent,
    on_packets_lost,
    on_round_start,
    pacing_budget,
    pacing_rate_bytes_per_second,
)
from .state import (
    CONN_STATE_CLOSED,
    CONN_STATE_CLOSING,
    CONN_STATE_DRAINING,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_HANDSHAKE,
    Connection,
    ConnectionEvents,
    STREAM_STATE_CLOSED,
    STREAM_STATE_HALF_CLOSED_LOCAL,
    STREAM_STATE_HALF_CLOSED_REMOTE,
    STREAM_STATE_IDLE,
    STREAM_STATE_OPEN,
    STREAM_STATE_RESET_RECVD,
    STREAM_STATE_RESET_SENT,
    Stream,
    connection_close,
    empty_events,
    handle_frame,
    is_idle_timeout_expired,
    mark_handshake_complete,
    new_connection,
    new_stream,
)
