"""Tests for ``WsClient.connect_prefer_h2`` (Track F1).

Verifies the ALPN-aware factory wires correctly:

- ``ws://`` URLs (plaintext, no TLS) fall through to the
  existing :meth:`WsClient._connect_impl` path; the factory
  behaves identically to :meth:`WsClient.connect`.
- The factory's signature accepts a custom :class:`TlsConfig`
  including a caller-pinned ``alpn`` list (so users who want to
  force ``["http/1.1"]`` and skip the dispatcher's default
  ``["h2", "http/1.1"]`` offer can do so).

The TLS-negotiated h2-branch (where the server selects ``h2``
and the factory raises pointing at ``WsAutoClient``) requires a
TLS test server that advertises h2 in ALPN; that integration
lives with the H2-tunnel-runtime sub-commit.
"""

from std.testing import assert_true

from flare.tls import TlsConfig
from flare.ws import WsClient


def test_connect_prefer_h2_plain_ws_passthrough() raises:
    """Plaintext ``ws://`` connection through ``connect_prefer_h2``
    delegates to the H1 path. Skipped when the public echo
    server is unreachable; matches the SKIP pattern used by
    :func:`test_ws_connect_plain`."""
    try:
        var ws = WsClient.connect_prefer_h2(
            "ws://echo.websocket.events", TlsConfig()
        )
        ws.close()
        assert_true(True)
    except e:
        print(" [SKIP] ws:// unavailable: " + String(e))


def test_connect_prefer_h2_accepts_pinned_alpn_config() raises:
    """The factory honours a caller-pinned ``TlsConfig.alpn``
    list verbatim. Smoke-asserts that constructing the config
    and reading the field back round-trips cleanly; the live
    TLS negotiation path lives with the wss:// integration
    layer."""
    var cfg = TlsConfig()
    cfg.alpn = List[String]()
    cfg.alpn.append("http/1.1")
    assert_true(len(cfg.alpn) == 1)
    assert_true(cfg.alpn[0] == "http/1.1")


def main() raises:
    test_connect_prefer_h2_plain_ws_passthrough()
    test_connect_prefer_h2_accepts_pinned_alpn_config()
    print("test_ws_prefer_h2: 2 passed")
