"""`flare.tls.rustls_quic` -- rustls QUIC binding surface.

QUIC's TLS shape is fundamentally different from TLS-over-TCP:
the handshake runs *inside* QUIC frames, keys are derived per
encryption level (Initial / Handshake / 1-RTT / 0-RTT), and the
API the TLS library exposes is record-shaped rather than
byte-stream-shaped. See [`docs/tls-strategy.md`](../../docs/tls-strategy.md)
for the full rationale on why flare's QUIC path uses rustls
instead of extending the OpenSSL FFI for QUIC: the BoringSSL-
shape QUIC API is what the broader ecosystem (quiche, ngtcp2,
lsquic, msquic) standardized on, and `rustls` carries that API
natively (`rustls::quic::ServerConnection`).

## Scope of this commit (Track Q2 scaffold)

The runtime + integration tests need a typed boundary they can
target while the Rust crate ships in its own focused commit.
This module declares:

- :class:`RustlsQuicConfig` -- server-side acceptor config
  (certificate chain, private key, ALPN list, transport
  parameters callback). Owns the configuration the Rust crate
  reads through the C ABI.
- :class:`RustlsQuicAcceptor` -- factory for per-connection
  TLS sessions. Conceptually parallel to
  :class:`flare.tls.acceptor.TlsAcceptor`, but produces QUIC
  sessions rather than TCP TLS streams.
- :class:`RustlsQuicSession` -- per-connection rustls handle.
  The QUIC reactor (Track Q3) feeds it CRYPTO-frame bytes per
  encryption level and pulls handshake output bytes plus
  derived keys back out.
- :class:`RustlsQuicError` -- typed error carrier for the
  cases the reactor must distinguish (handshake-incomplete,
  protocol violation, certificate rejected, internal error).

Every method that would touch the Rust crate raises a clear
``Error`` with a "rustls Rust crate not built yet" message.
The Rust crate (`flare/tls/ffi/rustls_wrapper.rs`) +
`build_rustls.sh` activation script land in their own commit;
this module locks the Mojo-side API shape so the reactor +
H3 server work can build against it without blocking.

References:
- RFC 9001 "Using TLS to Secure QUIC".
- RFC 8446 "The Transport Layer Security (TLS) Protocol Version 1.3".
- BoringSSL QUIC API conventions (the shape rustls implements).
"""

from std.collections import List, Optional


# ── Encryption levels (RFC 9001 §4) ─────────────────────────────────────


struct QuicEncryptionLevel:
    """RFC 9001 §4.1 packet protection levels.

    Each level has its own set of secret-keyed AEAD keys derived
    by the TLS handshake. The rustls QUIC binding emits CRYPTO
    frames at one level at a time and returns the derived keys
    when each level transitions into "ready".
    """

    comptime INITIAL: Int = 0
    """RFC 9001 §4.1 -- keyed by the QUIC v1 initial salt mixed
    with the client's Destination Connection ID. Used for the
    first client-hello flight."""

    comptime EARLY_DATA: Int = 1
    """RFC 9001 §4.1 -- 0-RTT keys. Not implemented in the v0.8
    Phase D scaffold (see :data:`NotImplementedReason`)."""

    comptime HANDSHAKE: Int = 2
    """RFC 9001 §4.1 -- handshake keys derived after the server
    accepts the client's Initial. Used for ServerHello and
    EncryptedExtensions."""

    comptime APPLICATION: Int = 3
    """RFC 9001 §4.1 -- 1-RTT keys. Used for all post-handshake
    application traffic; this is the keyed level the H3 server
    will see for every request."""


# ── Configuration carrier ──────────────────────────────────────────────


struct RustlsQuicConfig(Copyable, Defaultable, Movable):
    """Server-side rustls QUIC configuration carrier.

    Mirrors the shape of :class:`flare.tls.config.TlsConfig` but
    targets the rustls QUIC backend. Fields are owned by Mojo;
    the Rust crate reads them through the C ABI at acceptor
    construction time and never mutates them.

    The actual configuration that rustls would consume is built
    inside :class:`RustlsQuicAcceptor.__init__` -- this struct
    is the inputs.
    """

    var cert_chain_pem: String
    """PEM-encoded server certificate chain (leaf cert plus any
    intermediates). Empty string is invalid; the Rust crate
    will reject construction."""

    var private_key_pem: String
    """PEM-encoded server private key (PKCS#8). RFC 9001 §4.6
    says only TLS 1.3 is supported for QUIC; the Rust crate
    will reject non-TLS-1.3-compatible keys."""

    var alpn_protocols: List[String]
    """ALPN protocol identifiers the server is willing to
    negotiate (RFC 7301). For HTTP/3 this should include
    ``"h3"`` (RFC 9114 §3.1). Order matters -- earlier entries
    are preferred."""

    var max_early_data_size: UInt32
    """Maximum 0-RTT data the server will accept. Set to 0 to
    disable 0-RTT (the default). 0-RTT replay protection is
    out of scope for this scaffold; see RFC 9001 §9.2."""

    var session_resumption_enabled: Bool
    """Whether to issue NewSessionTicket frames for session
    resumption. Default is True for production parity with
    OpenSSL acceptor."""

    def __init__(out self):
        self.cert_chain_pem = String("")
        self.private_key_pem = String("")
        self.alpn_protocols = List[String]()
        self.max_early_data_size = UInt32(0)
        self.session_resumption_enabled = True


# ── Error carrier ──────────────────────────────────────────────────────


struct RustlsQuicError(Copyable, Movable):
    """Typed error carrier for the rustls QUIC binding.

    The reactor distinguishes these cases for connection-close
    reason mapping (RFC 9000 §10.2 -- CONNECTION_CLOSE frame
    types and reasons). String reason is for logs only.
    """

    var kind: Int
    """One of the :class:`RustlsQuicErrorKind` codepoints."""

    var reason: String
    """Human-readable reason string for logs and the
    CONNECTION_CLOSE reason phrase."""

    @staticmethod
    def not_built() -> Self:
        """The Rust crate is not built; the reactor should
        treat this as a configuration error (not a per-packet
        failure)."""
        return Self(
            kind=RustlsQuicErrorKind.NOT_BUILT,
            reason=String(
                "rustls QUIC binding scaffold: the rustls Rust"
                " crate (flare/tls/ffi/rustls_wrapper.rs) is not"
                " built in this commit. Track Q2 follow-up will"
                " ship the crate plus the build_rustls.sh"
                " activation script."
            ),
        )

    def __init__(out self, kind: Int, reason: String):
        self.kind = kind
        self.reason = reason


struct RustlsQuicErrorKind:
    """RFC 9000 §20.2 + RFC 9001 §4.8 cryptographic-error
    enumeration plus the local "not built" sentinel."""

    comptime NOT_BUILT: Int = 0
    """The Rust crate is not built. Returned by every method
    in the scaffold; replaced once the crate ships."""

    comptime HANDSHAKE_INCOMPLETE: Int = 1
    """The session needs more CRYPTO frame bytes before it can
    advance. Reactor should keep feeding bytes; not a real
    error from the connection's perspective."""

    comptime PROTOCOL_VIOLATION: Int = 2
    """The peer violated the TLS 1.3 wire grammar or the QUIC
    transport-parameter encoding. Maps to PROTOCOL_VIOLATION
    (0x0a) in CONNECTION_CLOSE."""

    comptime CERTIFICATE_INVALID: Int = 3
    """The server's certificate chain failed validation (only
    meaningful for client-side mTLS, which is the v0.10 line
    item -- this exists to keep the enum complete)."""

    comptime INTERNAL_ERROR: Int = 4
    """An internal Rust panic crossed the FFI boundary, or the
    C ABI returned an unexpected return code. Maps to
    INTERNAL_ERROR (0x01) in CONNECTION_CLOSE."""


# ── Acceptor ────────────────────────────────────────────────────────────


struct RustlsQuicAcceptor(Copyable, Movable):
    """Factory for per-connection rustls QUIC sessions.

    Long-lived. One instance per QUIC listener, shared across
    every connection it accepts. The actual rustls
    ``rustls::quic::ServerConfig`` lives inside the Rust crate;
    this carrier holds an opaque handle (deferred to Track Q2
    follow-up) plus enough configuration metadata that tests +
    the reactor can introspect the carrier without entering
    Rust code.
    """

    var config: RustlsQuicConfig

    var _opaque_handle: Int
    """Opaque pointer (as ``Int``) into the Rust-side
    `Arc<ServerConfig>`. Zero in this scaffold (the Rust crate
    is not built); the follow-up commit replaces with the real
    handle returned from `flare_rustls_acceptor_new`."""

    def __init__(out self, config: RustlsQuicConfig):
        self.config = config.copy()
        self._opaque_handle = 0

    def accept(self, dst_cid: List[UInt8]) raises -> RustlsQuicSession:
        """Create a new per-connection session bound to the
        client's Destination Connection ID.

        The reactor calls this once per connection after parsing
        the first Initial packet. The DCID is required because
        the rustls binding uses it to derive the initial-secret
        per RFC 9001 §5.2.
        """
        raise Error(
            "RustlsQuicAcceptor.accept: rustls Rust crate"
            " (flare/tls/ffi/rustls_wrapper.rs) is not built"
            " yet (Track Q2 follow-up commit). The Mojo surface"
            " is in place so the QUIC server reactor can target"
            " this acceptor today; the rustls handshake lands"
            " in its own focused commit."
        )


# ── Session ─────────────────────────────────────────────────────────────


struct RustlsQuicSession(Copyable, Movable):
    """Per-connection rustls handle.

    The reactor's per-connection state machine drives this:

    1. Feed inbound CRYPTO frame bytes via :meth:`feed_crypto`.
    2. Pull outbound CRYPTO frame bytes via :meth:`take_crypto`.
    3. When the handshake transitions a level into "ready",
       :meth:`take_keys` returns the per-level packet-protection
       keys (one set per :class:`QuicEncryptionLevel`).
    4. :meth:`is_handshake_complete` returns True once the
       1-RTT keys are derived; from there the application can
       send data on streams.

    Every method in the scaffold raises ``NotImplemented`` with
    a clear message; replaced once the Rust crate ships.
    """

    var dst_cid: List[UInt8]
    """The DCID this session was created for. Carried so the
    reactor can sanity-check key derivation later."""

    var _opaque_session_handle: Int
    """Opaque pointer (as ``Int``) into the Rust-side
    `Box<ServerConnection>`. Zero in this scaffold."""

    var _level: Int
    """Current outbound encryption level. Starts at
    :data:`QuicEncryptionLevel.INITIAL`; advances as the
    handshake progresses. Useful for tests confirming the
    level-state-machine wiring."""

    def __init__(out self, dst_cid: List[UInt8]):
        self.dst_cid = dst_cid.copy()
        self._opaque_session_handle = 0
        self._level = QuicEncryptionLevel.INITIAL

    def feed_crypto(mut self, level: Int, data: List[UInt8]) raises:
        """Feed inbound CRYPTO frame bytes at ``level``.

        The reactor calls this after dispatching a CRYPTO frame
        out of a packet at the matching encryption level. The
        ``data`` buffer is a contiguous chunk; the rustls side
        reassembles fragments internally.
        """
        raise Error(
            "RustlsQuicSession.feed_crypto: rustls Rust crate"
            " not built (Track Q2 follow-up). level="
            + String(level)
            + ", data_len="
            + String(len(data))
        )

    def take_crypto(self, level: Int) raises -> List[UInt8]:
        """Drain pending outbound CRYPTO frame bytes at ``level``.

        Returns an empty list when no bytes are pending. The
        reactor packages the result into CRYPTO frames inside
        packets at the matching encryption level.
        """
        raise Error(
            "RustlsQuicSession.take_crypto: rustls Rust crate"
            " not built (Track Q2 follow-up). level="
            + String(level)
        )

    def is_handshake_complete(self) -> Bool:
        """Whether the 1-RTT keys are derived. The scaffold
        always returns False (the handshake never completes
        because the Rust crate is absent)."""
        return False

    def selected_alpn(self) raises -> String:
        """ALPN identifier the rustls side picked.

        Returns the negotiated identifier from the ALPN list
        passed at config time (e.g. ``"h3"``). The reactor uses
        this to dispatch to the H3 server vs an alternative
        application protocol over QUIC.
        """
        raise Error(
            "RustlsQuicSession.selected_alpn: rustls Rust crate"
            " not built (Track Q2 follow-up)."
        )

    def current_level(self) -> Int:
        """Current outbound encryption level. Useful for tests
        confirming the level machine compiles even before the
        Rust crate lands."""
        return self._level
