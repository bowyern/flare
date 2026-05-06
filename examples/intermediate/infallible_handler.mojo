"""Example 43: HandlerInfallible vs Handler -- when to pick which (v0.7).

Most flare handlers extend :trait:`flare.http.Handler`:

    def serve(self, req: Request) raises -> Response: ...

The ``raises`` annotation is the right shape for 99 % of handler
bodies: realistic code paths can fail (DB query, deserialise,
external HTTP, etc.) and the server's catch-converts-to-500
contract handles them uniformly.

But some handler bodies *literally cannot* fail:

* A static-response fast path that returns a pre-built
  :class:`flare.http.Response`.
* A health-check route that always returns 200.
* A sentinel "the handler ran" route in tests.

For those, :trait:`flare.http.HandlerInfallible` (v0.7) lets you
write ``def serve(self, req) -> Response`` (no ``raises``). The
:class:`flare.http.WithRaises` adapter wraps an infallible handler
so it slots into Router / App / middleware that expect the regular
:trait:`Handler`.

Run:
    mojo -I . examples/43_infallible_handler.mojo
"""

from flare.http import (
    Handler,
    HandlerInfallible,
    Request,
    Response,
    Router,
    WithRaises,
    ok,
)


@fieldwise_init
struct HealthCheck(Copyable, HandlerInfallible, Movable):
    """Always-OK health probe. Provably infallible: no parsing,
    no allocation that can fail in the reactor's hot path."""

    @always_inline
    def serve(self, req: Request) -> Response:
        return ok('{"status":"ok"}')


@fieldwise_init
struct EchoMethod(Copyable, HandlerInfallible, Movable):
    """Returns a fixed string for the request method. Still
    provably infallible -- no header parsing, no body read.
    Showcases that infallible handlers can still inspect the
    request, just not in ways that can raise."""

    @always_inline
    def serve(self, req: Request) -> Response:
        return ok("method=" + req.method)


def fallible_user_lookup(req: Request) raises -> Response:
    """A regular :trait:`Handler`-shaped handler: parsing the
    request URL into an int *can* fail (non-numeric path param),
    so this handler keeps the ``raises`` shape."""
    var id_str = req.param("id")
    if id_str.byte_length() == 0:
        return Response(status=400, reason="Missing :id")
    var as_int = atol(id_str)  # may raise ValueError
    return ok("user=" + String(as_int))


def main() raises:
    """Demo only -- no live server. Shows the wiring at a glance.

    A real app would mount the handlers on a Router::

        var r = Router()
        r.get("/health", WithRaises[HealthCheck](HealthCheck()))
        r.get("/method", WithRaises[EchoMethod](EchoMethod()))
        r.get("/user/:id", fallible_user_lookup)
        srv.serve(r^)
    """
    var req = Request(method="GET", url="/health", version="HTTP/1.1")

    # Direct call: HandlerInfallible.serve has no ``raises`` keyword,
    # so the call site is plain (no ``try`` / ``except`` needed).
    var health = HealthCheck()
    var hr = health.serve(req)
    print(
        "health: status=", hr.status, "body=", String(unsafe_from_utf8=hr.body)
    )

    var echo = EchoMethod()
    var er = echo.serve(req)
    print(
        "echo:   status=", er.status, "body=", String(unsafe_from_utf8=er.body)
    )

    # Adapter: WithRaises[Inner] satisfies the regular Handler
    # constraint, so it slots into Router / App.
    var adapted = WithRaises[HealthCheck](HealthCheck())
    var ar = adapted.serve(req)
    print("via adapter:", ar.status, String(unsafe_from_utf8=ar.body))
