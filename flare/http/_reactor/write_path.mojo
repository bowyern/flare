"""Response serialisation helpers for the H1 reactor write path.

This module owns the byte-emitting half of the per-connection
state machine: turning a parsed :class:`flare.http.response.Response`
or a pre-encoded :class:`flare.http.static_response.StaticResponse`
into the HTTP/1.1 wire bytes that
:meth:`flare.http._reactor.conn_handle.ConnHandle.on_writable`
flushes to the socket.

Splitting the serialise-path helpers out of
:mod:`flare.http._reactor.conn_handle` keeps that module focused
on the connection state machine; the helpers here are pure
functions over the connection's ``write_buf`` and ``DateCache``
and only mutate those caller-supplied references.

The hot-path optimisations (response-side ``DateCache`` reuse,
single-allocation header skip predicates, bulk-copy body append)
match the byte-fast-path / keep-alive helpers in
:mod:`flare.http._reactor.keepalive_scan`.
"""

from std.collections import List
from std.memory import memcpy

from flare.http.response import Response
from flare.http.server import (
    _status_reason,
    _append_str,
    _append_int,
)
from flare.http.static_response import StaticResponse
from flare.runtime import DateCache

from .keepalive_scan import _is_connection, _is_content_length, _is_date


def serialize_static_into(
    mut write_buf: List[UInt8],
    mut write_pos: Int,
    resp: StaticResponse,
    keep_alive: Bool,
) -> None:
    """Queue a pre-encoded static response into ``write_buf``.

    Reuses the buffer's existing capacity across requests (same
    pattern as :func:`serialize_response_into`) and pulls either
    the keep-alive or close variant of the pre-encoded bytes
    depending on ``keep_alive``.
    """
    write_buf.clear()
    write_pos = 0
    # Pick the keep-alive or close variant by branch rather than via
    # a conditional expression. ``List[UInt8]`` is not
    # ``ImplicitlyCopyable`` under current Mojo, so binding the
    # selected variant to a single ``var`` would force an implicit
    # copy that the compiler now rejects. Splitting the branch
    # keeps both arms in pure borrow + ``unsafe_ptr()`` form and
    # avoids any copy at all.
    var n: Int
    if keep_alive:
        n = len(resp.keepalive_bytes)
    else:
        n = len(resp.close_bytes)
    if write_buf.capacity < n:
        write_buf.reserve(n)
    write_buf.resize(n, UInt8(0))
    if keep_alive:
        memcpy(
            dest=write_buf.unsafe_ptr(),
            src=resp.keepalive_bytes.unsafe_ptr(),
            count=n,
        )
    else:
        memcpy(
            dest=write_buf.unsafe_ptr(),
            src=resp.close_bytes.unsafe_ptr(),
            count=n,
        )


def serialize_response_into(
    mut write_buf: List[UInt8],
    mut date_cache: DateCache,
    resp: Response,
    keep_alive: Bool,
) -> None:
    """Serialise ``resp`` into ``write_buf`` ready to be sent.

    Reuses ``write_buf``'s allocated capacity across requests --
    callers clear the buffer after the previous response has been
    flushed, so the backing storage is idle when serialise starts.
    The ``Date`` header is emitted from the caller-supplied
    :class:`flare.runtime.DateCache` (RFC 9110 §6.6.1); any
    caller-supplied ``Date`` field on ``resp`` is dropped.
    """
    var reason = resp.reason
    if reason.byte_length() == 0:
        reason = _status_reason(resp.status)
    var body_len = len(resp.body)

    var estimated = 64 + body_len
    for i in range(resp.headers.len()):
        estimated += (
            resp.headers._keys[i].byte_length()
            + resp.headers._values[i].byte_length()
            + 4
        )
    write_buf.clear()
    if write_buf.capacity < estimated:
        write_buf.reserve(estimated)
    var wire = write_buf^

    _append_str(wire, "HTTP/1.1 ")
    _append_int(wire, resp.status)
    _append_str(wire, " ")
    _append_str(wire, reason)
    _append_str(wire, "\r\n")

    for i in range(resp.headers.len()):
        var k = resp.headers._keys[i]
        # Case-insensitive skip of Content-Length, Connection,
        # and Date without allocating a lowercased copy each
        # header. Date is always emitted by us from the per-
        # connection DateCache (RFC 9110 §6.6.1 mandates a single
        # Date field-line).
        if _is_content_length(k) or _is_connection(k) or _is_date(k):
            continue
        _append_str(wire, k)
        _append_str(wire, ": ")
        _append_str(wire, resp.headers._values[i])
        _append_str(wire, "\r\n")

    _append_str(wire, "Content-Length: ")
    _append_int(wire, body_len)
    _append_str(wire, "\r\n")

    # Date: RFC 9110 §6.6.1, IMF-fixdate from the per-connection
    # DateCache. The cache calls clock_gettime + (re)formats only
    # when the wall-clock second has advanced; reads on the same
    # second return the cached 29-byte buffer directly.
    date_cache.refresh()
    var date_bytes = date_cache.current_bytes()
    _append_str(wire, "Date: ")
    var date_old_len = len(wire)
    wire.resize(date_old_len + len(date_bytes), UInt8(0))
    memcpy(
        dest=wire.unsafe_ptr() + date_old_len,
        src=date_bytes.unsafe_ptr(),
        count=len(date_bytes),
    )
    _append_str(wire, "\r\n")

    if keep_alive:
        _append_str(wire, "Connection: keep-alive\r\n")
    else:
        _append_str(wire, "Connection: close\r\n")

    _append_str(wire, "\r\n")

    # Bulk-copy the body. Appending byte-by-byte from ``resp.body``
    # dominates this function's cost on small-body responses.
    if body_len > 0:
        var old = len(wire)
        wire.resize(old + body_len, UInt8(0))
        memcpy(
            dest=wire.unsafe_ptr() + old,
            src=resp.body.unsafe_ptr(),
            count=body_len,
        )

    write_buf = wire^


def build_error_response(status: Int, reason: String) -> Response:
    """Build a minimal text/plain error response. The caller threads
    the result through :func:`serialize_response_into` to queue it
    onto the wire.
    """
    var body_str = String(status) + " " + reason
    var resp = Response(status=status, reason=reason)
    var body_bytes = body_str.as_bytes()
    for i in range(len(body_bytes)):
        resp.body.append(body_bytes[i])
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def queue_h2c_upgrade_101(mut write_buf: List[UInt8]) -> None:
    """Queue the ``101 Switching Protocols`` response for an h2c
    upgrade (RFC 7540 §3.2) into ``write_buf``. ``Connection: close``
    is intentionally omitted so the same TCP fd carries the
    subsequent HTTP/2 frames.
    """
    write_buf.clear()
    var wire = write_buf^
    _append_str(wire, "HTTP/1.1 101 Switching Protocols\r\n")
    _append_str(wire, "Connection: Upgrade\r\n")
    _append_str(wire, "Upgrade: h2c\r\n\r\n")
    write_buf = wire^
