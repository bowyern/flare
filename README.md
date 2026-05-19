<p align="center">
  <img src="./logo.png" alt="flare" width="280">
</p>

<h1 align="center">flare</h1>

<p align="center">
  <a href="https://github.com/ehsanmok/flare/actions/workflows/ci.yml"><img src="https://github.com/ehsanmok/flare/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/ehsanmok/flare/actions/workflows/fuzz.yml"><img src="https://github.com/ehsanmok/flare/actions/workflows/fuzz.yml/badge.svg?branch=main&event=workflow_dispatch" alt="Fuzz"></a>
  <a href="https://ehsanmok.github.io/flare/"><img src="https://github.com/ehsanmok/flare/actions/workflows/docs.yaml/badge.svg?branch=main" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

**Full networking stack for Mojo** 🔥 HTTP/1.1 and HTTP/2 server and client, WebSocket, TLS, TCP, UDP, Unix sockets, DNS, all in one library on top of one non-blocking reactor. Drop to raw sockets when HTTP isn't the right shape.

```mojo
from flare.prelude import *

def hello(req: Request) -> Response:
    return ok("hello")

def main() raises:
    var r = Router()
    r.get("/", hello)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^, num_workers=2)
```

## Why flare

- **Batteries included:** HTTP/1.1 + HTTP/2, WebSocket (RFC 6455), TLS 1.2/1.3 with ALPN, signed cookies, sessions, multipart, gzip + brotli, CORS, static files, SSE, mTLS, and the PROXY protocol all live in `flare/`. Full inventory in [`docs/features.md`](docs/features.md).
- **Composable by types, not callbacks:** `Handler` is a trait. `Router`, `App[S]`, middleware, and typed extractors (`PathInt`, `QueryInt`, `Form[T]`, `Json[T]`, `Cookies`) compose by nesting structs. The compiler monomorphises the handler chain into one direct call sequence per request type — no virtual dispatch through the chain.
- **Hard to misuse under load:** Per-request `Cancel` tokens, graceful drain, sanitized 4xx/5xx, TLS cert reload, structured logging, Prometheus metrics.
- **Fast, with a tight tail:** Thread-per-core reactor (`kqueue` / `epoll`, opt-in `io_uring`). On a 4-worker plaintext bench, flare's handler path posts the cleanest tail of the pack at p99.9 / p99.99 across 5 runs. [Numbers below.](#performance)
- **Fuzzed:** 34 fuzz harnesses, 8M+ runs, zero known crashes. ASan and assert-mode coverage on every FFI boundary.

## Install

```toml
[workspace]
channels = ["https://conda.modular.com/max-nightly", "conda-forge"]
preview = ["pixi-build"]

[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", tag = "<latest-release>" }
```

```bash
pixi install
```

Requires [pixi](https://pixi.sh) (pulls Mojo nightly automatically). Pin to a [released tag](https://github.com/ehsanmok/flare/releases) for reproducible builds.

To track unreleased work (breaking changes possible between tags):

```toml
[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", branch = "main" }
```

## Quick start

The tour below walks the snippet at the top of this README from beginner to advanced. Each level adds roughly one concept; everything compiles, and the runnable equivalents live under [`examples/`](examples/) (every one is part of `pixi run tests`). [`docs/cookbook.md`](docs/cookbook.md) maps "I want to..." to the right example, and the rendered package docstring is at <https://ehsanmok.github.io/flare/>.

### Beginner: your first router

Three routes (two infallible, one that may fail), a path parameter, and a JSON response. Plain `def` handlers, a `Router`, `HttpServer.bind`, `num_workers`. No traits, no generics, no extractors yet.

```mojo
from flare.prelude import *  # Request, Response, Router, HttpServer, ok, ok_json, SocketAddr, ...

def home(req: Request) -> Response:                     # no raises - body cannot fail
    return ok("flare is up")

def health(req: Request) -> Response:                   # no raises - static JSON
    return ok_json('{"status":"ok"}')

def greet(req: Request) raises -> Response:             # raises - req.param("name")
    return ok("hello, " + req.param("name"))            #   raises if :name is missing

def main() raises:
    var r = Router()
    r.get("/",           home)
    r.get("/hi/:name",   greet)
    r.get("/health",     health)

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^)
```

The single-worker `srv.serve(r^)` shape works with any `Handler`. For multi-worker mode (`num_workers=N`) the handler must be `Copyable` because each worker gets its own `H.copy()`. `Router` is `Copyable` because its routes are held behind an Arc-style refcount, so each worker copy shares the same boxed handlers without re-allocating. Bare-function handlers (`srv.serve(my_fn, num_workers=4)`) and `ComptimeRouter[ROUTES]` work the same way.

`flare.prelude` re-exports the everyday handler surface: `Request`, `Response`, `Router`, `HttpServer`, `ok` / `ok_json` / `ok_json_value` / `not_found` / `bad_request` / `internal_error` / `redirect`, `Method` / `Status`, the `Handler` family, and `SocketAddr`. Anything outside that set (typed extractors, middleware, sessions, cookies, forms, comptime routing, HTTP/2 internals, lower-level transports) stays as an explicit `from flare.http import ...` so the import block continues to document what each module reaches for. Everywhere in this Quick start uses the prelude; the Intermediate example below is the exception because it reaches for `Extracted` and `PathInt`, which sit outside the prelude. Spelling out the imports there keeps it obvious which names are in play.

`raises` is optional and tracks the body. If the handler cannot fail (`home`, `health` above) drop the annotation; if it parses input or talks to a DB (`greet`'s `req.param` raises when `:name` is missing) keep it and let the server's catch-converts-to-500 contract take over. Mojo's function-type subtyping accepts both shapes at the same `Router.get(...)` call site. For *stateful* infallible handlers (the body still cannot fail but needs to carry struct fields) see [`HandlerInfallible`](examples/intermediate/infallible_handler.mojo).

What you get for free: 404 on unknown paths, 405 with `Allow` on wrong method, sanitized 4xx / 5xx bodies, peer-FIN cancellation, RFC 7230 size limits, the per-worker reactor with `kqueue` / `epoll` (opt-in `io_uring`).

For request bodies, query strings, cookies, sessions, multipart forms, gzip / brotli, TLS, HTTP/2, and WebSocket, see [`examples/`](examples/) (one per topic, indexed in [`docs/cookbook.md`](docs/cookbook.md)).

### Intermediate: typed extractors

Once your handlers need to read structured input (path params as integers, query strings as bools, headers as strings), promote each `Handler` from a `def` into a struct whose fields *are* the inputs. `PathInt["id"]` / `PathStr` / `QueryInt` / `HeaderStr` / `Form[T]` / `Multipart` / `Cookies` / ... parse and validate at extraction time; `Extracted[H]` reflects on the struct's fields and pulls each one in before `serve` runs. Missing or malformed values become a 400 with a sanitized body, so your `serve` only sees well-typed values.

```mojo
from flare.http import (
    Router, ok, Request, Response, HttpServer,
    Extracted, PathInt, Handler,
)
from flare.net import SocketAddr

def home(req: Request) raises -> Response:
    return ok("home")

@fieldwise_init
struct GetUser(Copyable, Defaultable, Handler, Movable):
    var id: PathInt["id"]

    def __init__(out self):
        self.id = PathInt["id"]()

    def serve(self, req: Request) raises -> Response:
        return ok("user=" + String(self.id.value))

def main() raises:
    var r = Router()
    r.get("/", home)
    r.get[Extracted[GetUser]]("/users/:id", Extracted[GetUser]())
    HttpServer.bind(SocketAddr.localhost(8080)).serve(r^, num_workers=4)
```

Middleware is the same shape: a `Handler` that wraps another `Handler`. The stock middleware (`Logger`, `RequestId`, `Compress`, `CatchPanic`, `Cors`) and stock leaf handlers (`FileServer`) all compose by nesting structs, no callback chain. `examples/intermediate/middleware.mojo` walks through a typical production stack (`RequestID → Logger → Timing → Recover → RequireAuth → Router`).

### Advanced: compile-time dispatch, shared state, cancel awareness

Three independent patterns. Pick the ones your workload needs.

**Cancel-aware handlers:** `CancelHandler.serve(req, cancel)` gets a token the reactor flips on peer FIN, deadline elapse, or graceful drain. Long-running handlers poll between expensive steps and return early; plain `Handler`s ignore the token and run to completion. The reactor still tears down the connection if the peer goes away; the token just lets your handler do partial work cleanly.

```mojo
from flare.http import CancelHandler, Cancel, Request, Response, ok

@fieldwise_init
struct SlowHandler(CancelHandler, Copyable, Movable):
    def serve(self, req: Request, cancel: Cancel) raises -> Response:
        for i in range(100):
            if cancel.cancelled():
                return ok("partial: " + String(i))
            # ...one expensive step...
        return ok("done")
```

**Compile-time route tables:** When the route table is known at build time, `ComptimeRouter[ROUTES]` parses the path patterns at compile time and unrolls the dispatch loop per route. No runtime trie walk, no per-request handler-table indirection. Same path-param + wildcard syntax as the runtime `Router`, same 404 / 405-with-`Allow` semantics; the only difference is *when* the dispatch is decided.

```mojo
from flare.http import (
    ComptimeRoute, ComptimeRouter, HttpServer,
    Request, Response, Method, ok,
)
from flare.net import SocketAddr

def home(req: Request) raises -> Response:
    return ok("home")

def get_user(req: Request) raises -> Response:
    return ok("user=" + req.param("id"))

def files(req: Request) raises -> Response:
    return ok("files=" + req.param("*"))

comptime ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET,  "/",            home),
    ComptimeRoute(Method.GET,  "/users/:id",   get_user),
    ComptimeRoute(Method.GET,  "/files/*",     files),
]

def main() raises:
    var r = ComptimeRouter[ROUTES]()
    HttpServer.bind(SocketAddr.localhost(8080)).serve(r^, num_workers=4)
```

**App state + middleware composition:** `App[S]` carries shared state alongside an inner handler; `state_view()` hands out a borrow that middleware can read or mutate. The compiler monomorphises the whole nested chain into one direct call sequence per request type, with no virtual dispatch and no per-request allocation.

```mojo
from flare.http import App, Router, Request, Response, Handler, State, ok, HttpServer
from flare.net import SocketAddr

@fieldwise_init
struct Counters(Copyable, Movable):
    var hits: Int

def home(req: Request) raises -> Response:
    return ok("home")

@fieldwise_init
struct WithHits[Inner: Handler](Handler):
    var inner:    Self.Inner
    var snapshot: State[Counters]

    def serve(self, req: Request) raises -> Response:
        var resp = self.inner.serve(req)
        resp.headers.set("X-Hits", String(self.snapshot.get().hits))
        return resp^

def main() raises:
    var router = Router()
    router.get("/", home)
    var app  = App(state=Counters(hits=0), handler=router^)
    var view = app.state_view()

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(WithHits(inner=app^, snapshot=view^))
```

For the static-response fast path (`serve_static`), `serve_comptime[handler, config]` with build-time invariant checks, the multi-worker shared-listener mode (`HttpServer.serve(handler, num_workers=N)`), and the cross-worker `WorkerHandoffPool` (`FLARE_SOAK_WORKERS=on`), see [`docs/cookbook.md`](docs/cookbook.md) and the linked examples.

## Performance

TFB plaintext (`GET /plaintext` returning 13 bytes of `Hello, World!`), `wrk2 -t8 -c256 -d30s --latency` (coordinated-omission corrected), Linux x86_64 dev-box. Each row is the highest rate that survives the bench harness's sustainable-peak finder; latency cells are `median ± σ` over five 30 s measurement rounds at that rate. Both flare and the Rust baselines are AOT-built with no debug asserts (`mojo build -D ASSERT=none` / `cargo build --release --locked`). Full methodology in [`docs/benchmark.md`](docs/benchmark.md#methodology).

The σ on the tail percentiles is the **honesty meter**: a small σ means all 5 runs landed inside the working envelope; a σ in the tens or hundreds of ms means at least one run brushed the saturation cliff and the headline rate is sitting at the limit, not comfortably inside it.

**4-worker comparison** (the four frameworks that ship a multi-worker mode):

| Server | Workers | Req/s | σ%  | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| **flare_mc_static** (fixed-response fast path) [^reuse] | **4** | **274,514** | **0.59** | **1.12 ± 0.08** | **98.43 ± 406.17** | **133.63 ± 425.84** | **148.35 ± 430.22** |
| actix_web (tokio) | 4 | 223,847 | 0.35 | 1.28 ± 0.01 | 2.72 ± 0.08 | 3.18 ± 269.54 | 7.51 ± 305.02 |
| hyper (tokio multi-thread) | 4 | 215,508 | 0.21 | 1.25 ± 0.00 | 2.83 ± 0.07 | 3.30 ± 125.23 | 10.85 ± 147.50 |
| **flare_mc** (handler) [^reuse] | **4** | **212,246** | **0.21** | **1.23 ± 0.01** | **2.61 ± 0.02** | **2.93 ± 0.02** | **3.25 ± 0.10** |
| axum (tokio multi-thread) | 4 | 199,380 | 0.17 | 1.30 ± 0.00 | 2.80 ± 0.14 | 3.23 ± 5.50 | 3.58 ± 7.55 |

**Single-worker** (per-core request-processing cost):

| Server | Workers | Req/s | σ%  | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| nginx (`worker_processes 1`) | 1 | 80,239 | 1.57 | 1.09 ± 0.02 | 3.45 ± 0.07 | 4.13 ± 0.11 | 4.80 ± 0.11 |
| **flare** (reactor) | **1** | **71,619** | **1.27** | **1.20 ± 0.02** | **3.01 ± 0.18** | **3.30 ± 1.49** | **3.43 ± 5.67** |
| Go `net/http` (`GOMAXPROCS=1`) | 1 | 40,173 | 1.57 | 1.38 ± 0.00 | 3.21 ± 0.01 | 3.74 ± 0.09 | 4.62 ± 0.32 |

What jumps out:

- **flare_mc (the handler path)** has the cleanest tail of the 4-worker pack. Its medians are competitive (`2.61 ms` p99, `2.93 ms` p99.9, `3.25 ms` p99.99); the σ around those medians is what stands apart — sub-100 µs at p99 / p99.9 / p99.99, against σ of 125–305 ms for the Rust baselines at p99.9 / p99.99. At 212k req/s the harness still has headroom; the Rust libs (actix_web 224k, hyper 216k) post slightly higher headline rates with at least one of 5 runs brushing the cliff.
- **flare_mc_static** posts the highest throughput of the pack (274k req/s, ~23% over actix_web), and the σ on its tail says where the cost lands: the fixed-response fast path is sitting at saturation, where 1–2 of 5 measurement runs slip off and the p99.x distribution widens. Use this row when headline matters and the workload tolerates occasional tail expansion; use `flare_mc` when you want a uniformly tight tail under sustained load.
- **flare 1w** posts 89% of nginx 1w throughput with a tighter p99 (3.01 vs 3.45 ms) and competitive σ at every percentile. It does 1.78× Go `net/http` at the same worker count.

The matching nginx / hyper / actix_web / axum baselines built from source by the harness live under [`benchmark/baselines/`](benchmark/baselines/).

### Production build

flare ships safety asserts on every FFI / unsafe-pointer boundary (`debug_assert[assert_mode="safe"]`). The Mojo stdlib default `ASSERT=safe` keeps them in the binary, which is what you want in development: they catch use-after-free, EBADF, EFAULT in the FFI layer before they become silent kernel-mode UB. Each one costs roughly one cmp+je on the reactor hot path.

For production deployments and apples-to-apples benchmarks, build with asserts compiled out:

```bash
mojo build -D ASSERT=none -I . examples/basic/http_server.mojo -o myserver
./myserver
```

This matches what the bench harness uses for the `flare_mc_static` / `flare_mc` numbers above (directly comparable to Rust's `cargo build --release --locked` posture). `mojo build` defaults to `-O3`; no extra flag needed.

Full assert-mode hierarchy (`none` / `safe` / `all` / `warn`), the sanitizer harness, and contributor guidance for adding `debug_assert` to new FFI wrappers all live in [`docs/build.md`](docs/build.md).

## Low-level API

flare ships the primitives the HTTP server is built on, so you can drop down a layer when HTTP isn't the right shape: custom binary protocols, raw TLS, UDP, or running the reactor directly.

```mojo
from flare.tcp import TcpStream
from flare.tls import TlsStream, TlsConfig
from flare.udp import UdpSocket
from flare.ws  import WsClient
from flare.dns import resolve
from flare.runtime import Reactor, INTEREST_READ
```

Round-trip examples for each (`basic/tcp_echo`, `basic/websocket_echo`, `basic/udp`, `basic/tls`, `advanced/reactor`) live under [`examples/`](examples/), and the rendered package docstring at <https://ehsanmok.github.io/flare/> walks the layered API top-down. Use cases: a custom protocol over TLS, a UDP client / server, a WebSocket client driven from a CLI tool, or a hand-rolled non-HTTP server on top of the same reactor that powers `HttpServer`.

## Architecture

```
flare.io       BufReader (Readable trait, generic buffered reader)
flare.ws       WebSocket client + server (RFC 6455, permessage-deflate, WS-over-h2)
flare.http     HTTP/1.1 client + reactor server + Cancel + Handler / Router / App
flare.http2    HTTP/2 frame codec, HPACK, stream state, h2c upgrade
flare.crypto   HMAC-SHA256, base64url (signed cookies, sessions)
flare.tls      TLS 1.2/1.3 (OpenSSL, both client and server)
flare.tcp      TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      UdpSocket (IPv4 + IPv6)
flare.uds      UnixListener + UnixStream (AF_UNIX sidecar IPC)
flare.dns      getaddrinfo (dual-stack)
flare.net      IpAddr, SocketAddr, RawSocket
flare.runtime  Reactor (kqueue/epoll/io_uring), TimerWheel, Scheduler,
               HandoffQueue + WorkerHandoffPool, BufferPool, DateCache,
               vectored I/O
flare.testing  fork-and-serve helpers for cookbook examples + integration tests
flare.utils    POSIX FFI thunks (fork / waitpid / kill / usleep / exit / getpid)
```

Each layer imports only from layers below it. No circular dependencies. The full request lifecycle, including the `Cancel` injection point and the per-connection state machine, lives in [`docs/architecture.md`](docs/architecture.md).

## Security

Per-layer security posture and the sanitised-error-response policy live in [`docs/security.md`](docs/security.md). Highlights: RFC 7230 token validation, configurable size limits, sanitised 4xx/5xx bodies, TLS 1.2+ only, WebSocket frame masking + UTF-8 validation, 34 fuzz harnesses with 8M+ runs and zero known crashes.

For security issues, please open a private security advisory on GitHub or email the maintainer directly.

## Develop

```bash
git clone https://github.com/ehsanmok/flare.git && cd flare
pixi install                  # lean: tests, examples, microbench, format-check
pixi install -e dev           # adds mojodoc + pre-commit
```

flare uses four pixi environments, layered:

| Env | Adds | What it unlocks |
|---|---|---|
| `default` | nothing | `tests`, `examples`, microbenchmarks, `format-check` |
| `dev` | `mojodoc`, `pre-commit` | `docs`, `docs-build`, `format` (with hook install) |
| `fuzz` | `dev` + `mozz` | `fuzz-*` / `prop-*` |
| `bench` | `dev` + `go`, `nginx`, `wrk`, `wrk2`, `rust` | `bench-vs-baseline*`, `bench-tail-quick`, `bench-mixed-keepalive`, `bench-soak-*` |

Common tasks (run with `pixi run [--environment <env>] <task>`):

| Task | Env | What it does |
|---|---|---|
| `tests` | `default` | Full unit + integration suite plus every example under [`examples/`](examples/) |
| `format-check` / `format` | `default` / `dev` | `mojo format` over `flare`, `tests`, `benchmark`, `examples`, `fuzz` |
| `docs` / `docs-build` | `dev` | mojodoc-rendered package docstring (live or static) |
| `fuzz-all` | `fuzz` | Every harness in [`fuzz/`](fuzz/) (34 harnesses, 8M+ runs combined) |
| `fuzz-<name>` / `prop-<name>` | `fuzz` | Single harness — see [`pixi.toml`](pixi.toml) for the full list |
| `bench-vs-baseline-quick` | `bench` | flare vs Go `net/http`, throughput config (~7 min) |
| `bench-vs-baseline` | `bench` | flare vs all baselines (Go, nginx, hyper, axum, actix_web), all configs |
| `bench-tail-quick` | `bench` | Tail-percentile harness at the calibrated peak rate |
| `bench-mixed-keepalive` | `bench` | Mixed keepalive / non-keepalive workload |
| `bench-soak-{slow_clients,churn,mixed,smoke,extended}` | `bench` | 24 h soak harnesses for long-running operational gates |
| `bench-tls-setup` | `bench` | Generate self-signed cert + key for the TLS benches |

```bash
pixi run tests                                          # full suite + every example under examples/
pixi run --environment fuzz fuzz-all                    # 34 harnesses
pixi run --environment bench bench-vs-baseline-quick    # ~7 min
```

The full task list (per-component + the every-individual-fuzz-harness breakdown) lives in [`pixi.toml`](pixi.toml). The architecture / benchmark / security / cookbook tour is under [`docs/`](docs/).

## License

[MIT](./LICENSE)

[^reuse]: Multi-worker flare uses per-worker `SO_REUSEPORT` listeners by default for `num_workers >= 2` (matching actix_web). Set `FLARE_REUSEPORT_WORKERS=0` to opt into the single-listener `EPOLLEXCLUSIVE` shape, which trades 7-22 % req/s (handler vs static fast path respectively) for a uniformly tight p99.99 across both paths. See [`docs/benchmark.md`](docs/benchmark.md) for the listener-mode A/B and [Production build](#production-build) for the `mojo build -D ASSERT=none` shape these numbers use.
