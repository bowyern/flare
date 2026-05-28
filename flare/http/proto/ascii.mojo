"""``flare.http.proto.ascii`` -- zero-validation ASCII helpers.

Closes critique register §C4 by promoting ``_ascii_unchecked_string``
out of :mod:`flare.http.server` (which was the originating site for
the helper but is the wrong layer -- it's the reactor-coupled
dispatcher, not the sans-I/O parser surface).

Why it lives here

The pattern -- "construct a Mojo ``String`` from a byte span without
re-running the stdlib's full UTF-8 validator" -- belongs in the
proto layer because every consumer is parser-shaped: HTTP/1.1 wire
artefacts (method, URL, version, header name, header value),
HTTP/2 control frame fields, WebSocket control-frame text payloads,
gRPC ``trailers-only`` field names, and so on. The bytes have
already passed the protocol's own RFC 7230 / RFC 9110 / RFC 7540 /
RFC 6455 token / VCHAR / TCHAR check upstream, so the additional
stdlib UTF-8 validation is dead work.

The helper showed up as the single hottest user-space symbol in
``perf record`` against the H1 plaintext bench (~5% of CPU). Wider
adoption past the H1 path is the v0.7 finishing-pass goal; this
module is the namespace for that promotion.

Caller contract

Inputs MUST already be valid ASCII (every byte ``< 0x80``). The
helper does not check; calling it on non-ASCII bytes produces an
incorrectly-encoded ``String`` (each byte becomes a one-byte UTF-8
sequence, which is correct iff every byte is < 0x80). HTTP/1.1
wire artefacts satisfy this through the parser's RFC 7230 token /
VCHAR check; HTTP/2 token-shaped fields satisfy it through HPACK's
RFC 7541 §4 ASCII-only contract; WebSocket text frames do *not*
satisfy it (those carry UTF-8 by spec) -- the codec there must
keep using ``String(unsafe_from_utf8=...)``.

Public API

* :func:`ascii_unchecked_string(span: Span[UInt8, _]) -> String` --
  construct a ``String`` of the same byte length from ``span`` via
  ``String(unsafe_uninit_length=n)`` + ``memcpy``. Empty input
  returns ``String("")``.
"""

from std.memory import memcpy


@always_inline
def ascii_unchecked_string(span: Span[UInt8, _]) -> String:
    """Construct a ``String`` from ASCII bytes without UTF-8 validation.

    ``String(unsafe_from_utf8=span)`` in Mojo 1.0.0b1 unconditionally
    runs ``_is_valid_utf8_runtime`` even though the constructor name
    suggests it skips validation -- a ``perf record`` on the H1
    plaintext bench surfaced ``_is_valid_utf8_runtime`` as the
    single hottest user-space symbol (~5% of CPU). This helper
    allocates an uninitialised ``String`` of the exact length and
    memcpy's the bytes directly into its buffer, sidestepping the
    validator entirely.

    Caller contract: the bytes MUST already be valid ASCII (each
    byte ``< 0x80``). HTTP/1.1 wire artefacts -- method, URL,
    version, header name, header value -- all satisfy this via
    the RFC 7230 token / VCHAR checks the parser already runs
    upstream; we never get here with a non-ASCII byte.

    Args:
        span: Source bytes. Caller guarantees every byte is < 0x80.

    Returns:
        A freshly-allocated ``String`` of length ``len(span)`` with
        the bytes copied verbatim.
    """
    var n = len(span)
    if n == 0:
        return String("")
    var s = String(unsafe_uninit_length=n)
    memcpy(dest=s.unsafe_ptr_mut(), src=span.unsafe_ptr(), count=n)
    return s^
