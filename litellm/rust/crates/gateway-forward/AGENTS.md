# Forwarding gateway

`Forward` is a reverse proxy in front of the Python proxy on loopback. Python must see each request as if the client had connected to it directly, because it serves every route behind Rust without Rust knowing which one

## Rules

### What Python and the client receive

- Forward the method, target, headers and body byte for byte within the [URL contract](FORWARDING.md#url-fragments-and-literal-hashes). Only drop hop-by-hop headers (RFC 9110 section 7.6.1) and set `x-litellm-rust-peer`, which replaces any client copy
- Never invent a Host. Python builds absolute URLs from it, so a missing one must never become the private upstream address
- A request Python could not have received unchanged (HTTP/1.1 without Host, a transfer coding other than chunked, a target without a path) gets the status uvicorn would have given, from Rust
- Stream both bodies. Never buffer, cap or time out a body, since uploads and provider streams have no upper bound
- An upstream that dies mid-response fails the client body. A clean end would make SSE clients treat a truncated stream as complete
- A client disconnect closes the upstream connection at every stage, which is how Python learns to stop a provider stream

### Connections

- Serve HTTP/1.1 only, as uvicorn does. WebSocket is the one protocol switch, relayed as raw bytes after the 101 and drained on shutdown
- Retire pooled upstream connections well before Python's keep-alive timeout, so no request lands on one Python is closing
- Close idle client connections after Python's keep-alive timeout, as uvicorn did. Time only the wait for the next request, never an exchange in progress
- Drain on EOF of stdin exactly as on SIGTERM, since the supervisor holds the only write end. `input_closed` reads on a plain thread, because a read blocked on tokio's blocking pool would hold up the runtime's exit

### The native app

- Never branch on a route or path. A behavior one endpoint needs is a protocol behavior every endpoint gets
- Take the native app as any tower `Service`, never as an axum `Router`, and never match a route, attach a route layer or install a fallback. The caller's screen sees every request first and is the only thing that decides who answers, so no request Python answers passes through a native layer
- `behind` returns a `Gated` that only `run` and `serve` take, so callers put every layer on the native app before handing it over. `x-litellm-gateway` on the response names who answered and why

## Layout

Every decision has one home

| File | Owns |
|---|---|
| `lib.rs` | The only wiring. `serve` creates the `Connections` and hands a clone to `Forward` and to `server::serve`, and nothing else starts a server |
| `server.rs` | Accepting client connections and their timeouts, which `axum::serve` does not expose |
| `connections.rs` | Every connection and relay, and the shutdown sequence from draining to closing what outlives the drain |
| `client.rs` | `ClientSocket`, which the serving loop puts in each request's extensions, and the one function that reads it back |
| `forward.rs`, `websocket.rs` | Moving requests, bodies and upgraded connections, never touching a header. `Forward` is only the leaf service that relays to Python |
| `rewrite.rs` | What Python and the client receive, as pure functions over requests and responses |
| `error.rs` | `Rejection`, the only place that picks a status for a request Rust answers itself |
| `gate.rs` | `Forward::behind`, which puts the screen in front of the native app |
| `connector.rs` | Keeping hyper reading Python's answer after Python stops reading the request |
| `settings.rs` | Parsing the environment into typed values, so an `Upstream` is a loopback origin by construction |

## Environment

Only the Python supervisor in `litellm/proxy/rust_forward/` starts forwarding mode, from `litellm` and from `python -m gateway.launch`. `supervisor/children.py` is the only writer of these variables, so adding, renaming or removing one changes `settings.rs` and `children.rust_spec` in the same change. Every variable is required, and a missing or invalid one fails startup naming it. Without `LITELLM_FORWARD_UPSTREAM` the binary runs as the standalone Rust gateway and this crate does nothing

Never read Python's own settings (`HOST`, `PORT`, `KEEPALIVE_TIMEOUT`, `GRACEFUL_SHUTDOWN_TIMEOUT`) or keep a copy of its defaults, since Python can take those from CLI flags the environment never shows

| Variable | Meaning |
|---|---|
| `LITELLM_FORWARD_UPSTREAM` | Python's loopback origin, e.g. `http://127.0.0.1:53211` |
| `LITELLM_FORWARD_HOST` | public bind host |
| `LITELLM_FORWARD_PORT` | public bind port |
| `LITELLM_FORWARD_UPSTREAM_KEEPALIVE` | seconds uvicorn keeps an idle connection open. Pooled connections are retired at half of it, and idle client connections are closed after it |
| `LITELLM_FORWARD_SHUTDOWN_DRAIN` | seconds to drain on shutdown, already including Python's graceful timeout and teardown headroom |

## Tests

Test through real sockets with `tests/support`, never `oneshot`. `Gateway` runs the forwarder on a listener like production, `recording` is a well-behaved upstream that captures what Python would receive, and `raw_upstream` and `Raw` drive bytes by hand for framing, timing and disconnects a real server would not produce. Waits measured in minutes use paused tokio time

The forwarder sees HTTP/1.1 messages, so there is one test file per traffic shape uvicorn can emit and never one per route. Add a route's behavior to the shape it already has, and add a new shape file only for a wire behavior none of them covers

| File | Shape |
|---|---|
| `exchange` | plain request and response |
| `framing` | requests whose framing a parser could read two ways |
| `slow_head` | minutes before response headers |
| `stream`, `idle_stream` | incremental response bodies, and long-lived streams that go quiet |
| `upload`, `download`, `websocket`, `client_identity` | as named |
| `lifecycle` | disconnects, pooling, idle timeouts, shutdown |
| `roundtrip` | the forwarding invariant for generated messages |
