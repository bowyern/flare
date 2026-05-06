"""Example 42: typed JSON request -> typed JSON response (v0.7).

The :class:`flare.http.Json[T]` input extractor parses a request
body into a typed :class:`json.Value`; the symmetric output side is
:func:`flare.http.ok_json_value`, which accepts a typed
:class:`json.Value` and emits a 200 OK response with
``Content-Type: application/json`` and the serialised body.

Closes the input/output asymmetry the v0.7 critique flagged: prior
to v0.7 the canonical JSON-out path was ``ok_json(string)`` with
the caller stitching JSON together by hand, while the input side
already had typed parsing.

Run:
    mojo -I . examples/42_ok_json_typed.mojo
"""

from json import loads, Value as JsonValue

from flare.http import (
    HttpServer,
    Request,
    Response,
    Router,
    ok,
    ok_json_value,
)
from flare.net import SocketAddr


def echo_json(req: Request) raises -> Response:
    """Echo a JSON request body as a JSON response.

    The request body is parsed via :func:`json.loads` into a typed
    :class:`json.Value`; the typed value is wrapped in a JSON object
    under ``"echo"`` and returned via :func:`ok_json_value`. No
    string concatenation, no ``Content-Type`` header munging in
    handler code.
    """
    var parsed = loads(req.text())
    return ok_json_value(parsed^)


def home(req: Request) raises -> Response:
    return ok("flare ok_json_value demo: POST /echo with a JSON body")


def main() raises:
    """Demo only -- shows the wiring without actually starting the server.

    A full run would be ``HttpServer.bind(SocketAddr.localhost(8080)).serve(r^)``;
    here we keep it offline so ``pixi run tests`` doesn't hang.
    """
    var r = Router()
    r.get("/", home)
    r.post("/echo", echo_json)

    # Build a fake request to demonstrate the typed pipeline without
    # needing a live network.
    var fake = Request(method="POST", url="/echo", version="HTTP/1.1")
    fake.headers.set("Content-Type", "application/json")
    var body_str = String('{"id":42,"name":"alice"}')
    var bb = body_str.as_bytes()
    for i in range(len(bb)):
        fake.body.append(bb[i])

    var resp = echo_json(fake^)
    print("status:", resp.status)
    print("Content-Type:", resp.headers.get("Content-Type"))
    print("body:", String(unsafe_from_utf8=resp.body))
