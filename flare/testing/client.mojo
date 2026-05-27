"""In-process test client for ``Handler`` implementations.

``TestClient[H]`` is a thin synthesise-request-call-handler-
return-response helper. It exists for the same reason
FastAPI's ``TestClient`` does: handler-level tests want to
exercise the request/response shape without the friction of a
real socket, a real reactor, or a real port assignment.

Usage::

    var client = TestClient(MyHandler())
    var resp = client.get("/users/42")
    assert_equal(resp.status, 200)

The client supports the seven standard HTTP methods (GET, POST,
PUT, PATCH, DELETE, HEAD, OPTIONS); each accepts an optional
body and optional headers, and returns the captured
``Response``.

The client does not run any middleware *for* the caller -- the
``handler`` passed in must already be the fully-composed stack
the test wants to exercise. Compose your middleware once at
construction time, then run as many requests through it as the
test needs.
"""

from std.collections import List

from flare.http.handler import Handler
from flare.http.headers import HeaderMap
from flare.http.request import Request
from flare.http.response import Response
from flare.net import IpAddr, SocketAddr


struct TestClient[H: Handler](ImplicitlyDestructible, Movable):
    """Wraps a ``Handler`` and exposes per-method synth helpers.

    The handler is moved in at construction; subsequent calls
    take a borrow. Two helper shapes are available per method:
    a bare ``get(path)`` shape for cases where no body / no
    custom headers are needed, and a ``request(method, path,
    body, headers)`` shape for the full surface.
    """

    var handler: Self.H

    def __init__(out self, var handler: Self.H):
        self.handler = handler^

    def request(
        self,
        method: String,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        """Synth a ``Request`` from the arguments and run it
        through ``self.handler``. The peer address is fixed to
        ``127.0.0.1:0`` and ``expose_errors`` is True so
        handler-level errors surface in the body (a test-mode
        affordance; production runs default to False)."""
        var req = Request(
            method=method,
            url=path,
            body=body^,
            version=String("HTTP/1.1"),
            peer=SocketAddr(IpAddr("127.0.0.1", False), UInt16(0)),
            expose_errors=True,
        )
        req.headers = headers^
        return self.handler.serve(req)

    def get(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("GET"), path, headers=headers^)

    def head(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("HEAD"), path, headers=headers^)

    def options(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("OPTIONS"), path, headers=headers^)

    def post(
        self,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        return self.request(String("POST"), path, body=body^, headers=headers^)

    def put(
        self,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        return self.request(String("PUT"), path, body=body^, headers=headers^)

    def patch(
        self,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        return self.request(String("PATCH"), path, body=body^, headers=headers^)

    def delete(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("DELETE"), path, headers=headers^)
