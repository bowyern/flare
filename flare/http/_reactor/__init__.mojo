"""``flare.http._reactor`` -- per-connection state-machine sub-package.

This sub-package owns the per-connection halves of the reactor-backed
HTTP server: ``ConnHandle`` (the per-conn state machine), ``StepResult``
(the typed return shape from every event handler), the state-constant
trio, the local h2c upgrade detector, and the byte-fast-path / keep-alive
helpers the reactor loops also consult.

The sister module ``flare.http._server_reactor_impl`` owns the
I/O-bearing pieces (reactor entry-point loops, ``Pool[ConnHandle]``
glue, io_uring buffer-ring scaffolding) and re-exports every public
symbol below for back-compat with existing imports across
``flare/http/``, ``flare/http2/``, ``flare/runtime/``, the test suite,
and the fuzz corpus.

Internal namespace: nothing here is part of the public ``flare`` API.
"""

from .conn_handle import (
    STATE_READING,
    STATE_WRITING,
    STATE_CLOSING,
    StepResult,
    ConnHandle,
    _detect_h2c_upgrade_inline,
    _monotonic_ms,
    _is_content_length,
    _is_date,
    _is_connection,
    _connection_is_keepalive,
    _connection_is_close,
    _compact_read_buf_drop_prefix,
    _compute_close_after,
    _wants_close,
)
