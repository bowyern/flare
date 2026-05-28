"""Reliability middleware: ``Retry`` + ``Timeout`` policies.

A reliability middleware wraps an inner ``Handler`` and adds a
policy that improves the chance the call succeeds in the face of
transient failures (transient upstream 5xx, slow handlers, etc).

This commit ships two policies; the matching ``RateLimit`` and
``CircuitBreaker`` policies follow in subsequent commits within
this cycle.

- :class:`Retry[Inner]` — re-invoke the inner handler when it
  raises or returns a 5xx response, up to ``max_attempts`` times.
  Caller-tunable retry set (any 5xx by default; bounded to GET /
  HEAD / OPTIONS / TRACE / PUT / DELETE -- the RFC 9110 §9.2.2
  idempotent set -- by passing ``retry_only_idempotent=True``).
  Optional exponential backoff with full jitter spaces attempts.
- :class:`Timeout[Inner]` — bound the wall-clock time the inner
  handler may consume. Returns ``Response.with_status(504)`` if
  the deadline elapses before serve() completes. (The timeout
  is observed via ``perf_counter_ns`` against the request's
  arrival time; integration with the reactor's ``Cancel`` cell
  flip is the v0.7-style enhancement in a later commit.)

Each middleware is generic over its inner ``Handler`` so the
chain stays monomorphised -- no virtual dispatch.
"""

from std.time import perf_counter_ns
from std.random import random_ui64

from ..runtime._libc_time import libc_nanosleep_ms
from .handler import Handler
from .request import Request
from .response import Response


@fieldwise_init
struct RetryPolicy(Copyable, Defaultable, Movable):
    """Tunable retry policy.

    - ``max_attempts``: total number of inner-handler invocations
      (so ``max_attempts=3`` means 1 initial + 2 retries).
    - ``retry_only_idempotent``: when True, retries are gated on
      the request method being one of GET / HEAD / OPTIONS / TRACE
      / PUT / DELETE (the RFC 9110 §9.2.2 idempotent set). When
      False, every 5xx triggers a retry regardless of method.
    - ``initial_backoff_ms``: when > 0, sleep this many milliseconds
      before retry attempt #2. Each subsequent attempt scales the
      backoff by ``backoff_multiplier`` (capped at
      ``max_backoff_ms``). The actual sleep is "full jitter" --
      a uniform random draw in ``[0, capped_backoff_ms]`` -- which
      is the AWS-recommended default for retry storms (see
      <https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/>).
      ``0`` (the default) disables sleeps and matches the previous
      "tight loop" behaviour.
    - ``backoff_multiplier``: per-attempt scaling factor. Defaults
      to ``2`` (binary exponential backoff: 100ms -> 200ms ->
      400ms -> ...).
    - ``max_backoff_ms``: cap on the un-jittered backoff before
      ``random_ui64`` draws the actual sleep. Defaults to
      ``2_000`` (2 s); set to a small value to keep tail latency
      bounded.

    Defaults: ``max_attempts=3``, ``retry_only_idempotent=True``,
    ``initial_backoff_ms=0`` (no sleep), ``backoff_multiplier=2``,
    ``max_backoff_ms=2_000``.
    """

    var max_attempts: Int
    var retry_only_idempotent: Bool
    var initial_backoff_ms: Int
    var backoff_multiplier: Int
    var max_backoff_ms: Int

    def __init__(out self):
        self.max_attempts = 3
        self.retry_only_idempotent = True
        self.initial_backoff_ms = 0
        self.backoff_multiplier = 2
        self.max_backoff_ms = 2_000


def _is_idempotent_method(method: String) -> Bool:
    """Return True if ``method`` is in the RFC 9110 §9.2.2 idempotent
    set: GET, HEAD, OPTIONS, TRACE, PUT, DELETE.

    PUT and DELETE are idempotent at the protocol level even
    though they have observable side effects: re-applying them
    yields the same final resource state. Including them here
    matches RFC 9110 verbatim; callers that consider their PUT /
    DELETE handlers unsafe to re-invoke can flip
    ``retry_only_idempotent=False`` and gate retries with their
    own logic.
    """
    return (
        method == String("GET")
        or method == String("HEAD")
        or method == String("OPTIONS")
        or method == String("TRACE")
        or method == String("PUT")
        or method == String("DELETE")
    )


def _backoff_sleep_ms(policy: RetryPolicy, attempt: Int) -> Int:
    """Compute the jittered sleep budget for retry ``attempt``.

    ``attempt`` is the upcoming attempt index (1-based) **after**
    the failure that triggered the retry; the sleep precedes the
    next ``inner.serve`` call. Returns ``0`` when backoff is
    disabled (``initial_backoff_ms <= 0``) or the policy is
    misconfigured.

    The schedule is binary exponential by default
    (``backoff_multiplier=2``): the un-jittered budget for
    attempt N (counting from N=2 = first retry) is
    ``initial_backoff_ms * multiplier ** (N - 2)`` capped at
    ``max_backoff_ms``. The returned value is then drawn
    uniformly from ``[0, capped]`` ("full jitter").
    """
    if policy.initial_backoff_ms <= 0 or attempt <= 1:
        return 0
    var capped = policy.initial_backoff_ms
    var i = 2
    while i < attempt:
        var next = capped * policy.backoff_multiplier
        if policy.max_backoff_ms > 0 and next > policy.max_backoff_ms:
            capped = policy.max_backoff_ms
            break
        capped = next
        i += 1
    if policy.max_backoff_ms > 0 and capped > policy.max_backoff_ms:
        capped = policy.max_backoff_ms
    if capped <= 0:
        return 0
    return Int(random_ui64(0, UInt64(capped)))


struct Retry[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Retry the inner handler on transient failure.

    A response with status >= 500 triggers a retry; a raised
    exception is also treated as a transient failure (the
    inner handler re-runs from scratch). The last attempt's
    outcome (response or exception) is propagated unchanged when
    all attempts are exhausted.

    By default the middleware does NOT sleep between attempts and
    retries fire as fast as the inner handler returns. Set
    ``RetryPolicy.initial_backoff_ms`` to enable binary
    exponential backoff with full jitter (the AWS-recommended
    default for retry storms): the sleep before retry N is drawn
    uniformly from ``[0, min(initial_backoff_ms * 2 ** (N - 2),
    max_backoff_ms)]``. ``RateLimit[Inner]`` composed inside
    ``Retry`` remains the canonical way to express richer
    pacing policies.
    """

    var inner: Self.Inner
    var policy: RetryPolicy

    def __init__(out self):
        self.inner = Self.Inner()
        self.policy = RetryPolicy()

    def __init__(
        out self, var inner: Self.Inner, var policy: RetryPolicy = RetryPolicy()
    ):
        self.inner = inner^
        self.policy = policy^

    def serve(self, req: Request) raises -> Response:
        # Pre-flight: if the request method is non-idempotent and
        # the policy gates retries on idempotency, fall through to
        # a single serve() (no retry attempt at all).
        var allow_retry = True
        if self.policy.retry_only_idempotent and not _is_idempotent_method(
            req.method
        ):
            allow_retry = False
        if not allow_retry or self.policy.max_attempts <= 1:
            return self.inner.serve(req)
        var attempt = 0
        var last_err: String = String("")
        var last_raised = False
        while attempt < self.policy.max_attempts:
            attempt += 1
            try:
                var resp = self.inner.serve(req)
                if resp.status < 500 or attempt == self.policy.max_attempts:
                    return resp^
                # 5xx and we still have attempts: jittered sleep
                # before the next attempt (no-op when backoff is
                # disabled).
                var nap = _backoff_sleep_ms(self.policy, attempt + 1)
                if nap > 0:
                    _ = libc_nanosleep_ms(nap)
            except e:
                last_err = String(e)
                last_raised = True
                if attempt == self.policy.max_attempts:
                    break
                var nap = _backoff_sleep_ms(self.policy, attempt + 1)
                if nap > 0:
                    _ = libc_nanosleep_ms(nap)
        if last_raised:
            raise Error(last_err)
        # Should be unreachable: the only way out without a
        # response is via the raise branch above.
        return self.inner.serve(req)


struct Timeout[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Bound the inner handler's wall-clock time.

    The middleware records the entry timestamp and ALSO invokes
    the inner handler; on return, if elapsed wall time exceeds
    the configured budget, the response is replaced with a 504
    Gateway Timeout. This is the simple integration point; tight
    cancel-cell wiring (preempt the inner handler mid-serve)
    requires reactor cooperation and lands in a later commit.

    For the codec-style sans-I/O test surface this commit
    establishes today, the simple post-hoc check is the right
    primitive: handlers that genuinely block longer than the
    budget surface as 504, and those that just barely overrun
    get truncated. The reactor cell-flip integration is the
    enhancement.
    """

    var inner: Self.Inner
    var budget_ms: Int

    def __init__(out self):
        self.inner = Self.Inner()
        self.budget_ms = 30_000

    def __init__(out self, var inner: Self.Inner, budget_ms: Int = 30_000):
        self.inner = inner^
        self.budget_ms = budget_ms

    def serve(self, req: Request) raises -> Response:
        # ``budget_ms <= 0`` means "no time allowed at all": the
        # request is rejected before invoking the inner handler.
        # This keeps the contract intuitive for callers that flip
        # the budget through configuration (a zero budget is the
        # explicit "disabled" sentinel) and avoids the rounding
        # artifact where a sub-millisecond handler would otherwise
        # pass the elapsed > 0 check on a very fast host.
        if self.budget_ms <= 0:
            return Response(status=504, reason=String("Gateway Timeout"))
        var start = perf_counter_ns()
        var resp = self.inner.serve(req)
        var elapsed_ms = (perf_counter_ns() - start) // 1_000_000
        if elapsed_ms > UInt(self.budget_ms):
            return Response(status=504, reason=String("Gateway Timeout"))
        return resp^
