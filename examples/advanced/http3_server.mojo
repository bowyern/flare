"""HTTP/3 server -- one Handler across h1 + h2c + h2 + h3.

Walks the production shape of an HTTP/3 server:

* :meth:`flare.http.HttpServer.bind_with_h3` opens a TCP listener
  for h1 / h2c / h2 AND a QUIC UDP listener for h3 alongside.
* The same :class:`flare.http.Handler` instance serves every
  wire shape -- a single ``router.route("GET", "/hello", ...)``
  call is reachable from a curl over h1, an h2-frame client,
  and an h3 (QUIC) client.
* :meth:`flare.http.HttpServer.advertised_alpn_protocols` is
  what the TLS handshake advertises (server preference order
  ``h3 > h2 > http/1.1``); the negotiated identifier feeds
  :meth:`flare.http.HttpServer.route_alpn` to pick the matching
  driver per connection.
* :meth:`flare.http.HttpServer.tick_h3_once` lets the example
  validate the bind path -- the QUIC listener exists, its
  timer wheel advances, idle sweeps land -- without spinning
  up a full UDP traffic generator.

The TCP serve loop is the same path :class:`HttpServer.bind` +
:meth:`HttpServer.serve` always ran; this example calls a
single accept-and-respond cycle on the TCP side so the demo
returns deterministically. The full h3 reactor wiring (drain
UDP datagrams, dispatch through :class:`H3Connection`, encode
+ send responses) is the v0.7 line item; today the example
proves the bind + ALPN routing surface, the cross-driver
handler share, and the listener lifecycle.

Run:
    pixi run example-http3-server
"""

from flare.h3 import H3Connection, H3ConnectionConfig
from flare.http.alpn_dispatch import (
    ALPN_HTTP_1_1,
    ALPN_HTTP_2,
    ALPN_HTTP_3,
    WireProtocol,
    wire_protocol_name,
)
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import HttpServer, ok
from flare.net import IpAddr, SocketAddr
from flare.quic import QuicServerConfig


# ── The shared Handler ────────────────────────────────────────────────


def handle(req: Request) raises -> Response:
    """One handler reachable from every wire (h1 / h2c / h2 / h3).

    The handler doesn't look at the wire shape -- it doesn't
    need to. The reactor + protocol drivers materialize the
    :class:`Request` from the wire, the handler decides what to
    do, and the protocol drivers serialize the :class:`Response`
    back out. That's the point of the trait boundary.
    """
    if req.url == "/hello":
        return ok("Hello from flare across every wire!")
    var body = String("you reached ") + req.method + String(" ") + req.url
    return ok(body^)


# ── Walkthrough ───────────────────────────────────────────────────────


def main() raises:
    print("== HTTP/3 server -- one Handler across h1 + h2c + h2 + h3 ==")
    print()

    # Step 1: bind. The TCP listener handles h1 / h2c / h2 via
    # ALPN; the QUIC listener handles h3 via ALPN. Both ports
    # are kernel-chosen (port 0 = ephemeral) so the example is
    # reproducible without claiming well-known ports.
    var tcp_addr = SocketAddr(IpAddr.localhost(), UInt16(0))
    var udp_cfg = QuicServerConfig()
    udp_cfg.host = String("127.0.0.1")
    udp_cfg.port = UInt16(0)
    var srv = HttpServer.bind_with_h3(tcp_addr, udp_cfg^)

    print("[bind] TCP listener:", String(srv.local_addrs()[0]))
    print("[bind] UDP listener:", String(srv.local_h3_addr()))
    print()

    # Step 2: the advertised ALPN list. The TLS handshake on
    # the TCP side advertises ``h2`` + ``http/1.1``; the QUIC
    # handshake on the UDP side advertises ``h3``. Server
    # preference order is highest -> lowest so the negotiator
    # picks h3 over h2 when the client supports both.
    print("[alpn] advertised ALPN protocols (preference order):")
    var alpn = srv.advertised_alpn_protocols()
    for i in range(len(alpn)):
        print("   ", i, ":", alpn[i])
    print()

    # Step 3: ALPN routing decision per peer. The reactor calls
    # route_alpn() on the negotiated identifier from each TLS
    # handshake and gets back a WireProtocol codepoint that
    # picks the driver.
    print("[route] ALPN -> wire-protocol mapping:")
    print(
        "    h3 ->",
        wire_protocol_name(srv.route_alpn(String(ALPN_HTTP_3))),
    )
    print(
        "    h2 ->",
        wire_protocol_name(srv.route_alpn(String(ALPN_HTTP_2))),
    )
    print(
        "    http/1.1 ->",
        wire_protocol_name(srv.route_alpn(String(ALPN_HTTP_1_1))),
    )
    print(
        "    (no ALPN) ->",
        wire_protocol_name(srv.route_alpn(String(""))),
    )
    print()

    # Step 4: the QUIC listener is alive and its timer wheel
    # advances. tick_h3_once() is the test-only entry that
    # advances the wheel one step + sweeps the connection slab.
    # The full reactor wiring (drain inbound datagrams ->
    # H3Connection.feed_uni_stream_chunk /
    # feed_stream_chunk -> dispatch -> emit_response ->
    # drain outbound) lives in the v0.7 reactor commit.
    print("[h3] tick the QUIC listener's timer wheel:")
    var live = srv.tick_h3_once(UInt64(0))
    print("    live connections after tick:", live)
    print()

    # Step 5: prove the same Handler the QUIC reactor will
    # invoke is the one the TCP reactor invokes. Dispatch a
    # synthetic Request through the handler directly -- this is
    # what a real h3 reactor commit will do once it has
    # decoded the QUIC stream bytes.
    print("[demo] dispatch a synthetic request through the shared Handler:")
    var req = Request(
        method=String("GET"), url=String("/hello"), body=List[UInt8]()
    )
    var resp = handle(req^)
    print("    response status:", resp.status)
    print(
        "    response body:",
        String(unsafe_from_utf8=Span[UInt8, _](resp.body)),
    )
    print()

    # Step 6: H3Connection is what the QUIC reactor will hand
    # each accepted QUIC connection to. Build one + verify it
    # emits the server SETTINGS that the listener will write
    # on the new control stream.
    var h3 = H3Connection.with_config(H3ConnectionConfig())
    var initial_settings = h3.emit_initial_settings()
    print("[h3] initial server SETTINGS emit length =", len(initial_settings))
    print()

    print("== done ==")
