"""HTTP/2 cleartext via the RFC 7540 §3.2 Upgrade dance, client side.

Two h2c flavours coexist on the cleartext wire:

1. **Prior knowledge** (``HttpClient(prefer_h2c=True)``): the client
   sends the h2 connection preface immediately and hopes the server
   speaks h2. Cheaper, but only works when the server is known
   ahead-of-time to support h2c.
2. **Upgrade** (``HttpClient(h2c_upgrade=True)``): the client sends
   the request as HTTP/1.1 with ``Upgrade: h2c`` +
   ``HTTP2-Settings: <base64url>``; if the server accepts (``101
   Switching Protocols``), the response flows back over h2 on
   stream id 1. If the server doesn't speak h2c, it just answers
   the original request as h1 and the client returns that
   response unchanged. This file demos the second variant.

Run:
    pixi run example-h2c-client
"""

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import SocketAddr
from flare.testing import fork_server, kill_forked_server


def _route(req: Request) raises -> Response:
    if req.url == "/":
        return ok("hello via h2c-upgrade")
    if req.url == "/echo":
        return ok(req.method + ":" + String(len(req.body)))
    return Response(status=404, reason="Not Found")


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    print("[h2c-upgrade demo] listening on 127.0.0.1:" + String(Int(port)))

    var pid = fork_server(srv^, _route)
    var base = String("http://127.0.0.1:") + String(Int(port))

    with HttpClient(h2c_upgrade=True, base_url=base) as c:
        var r1 = c.get("/")
        print("[h2c-upgrade] GET / ->", r1.status, r1.text())
        var r2 = c.post("/echo", "abc")
        print("[h2c-upgrade] POST /echo ->", r2.status, r2.text())

    kill_forked_server(pid)
