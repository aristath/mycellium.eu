# mycellium-http

> The native HTTP transport: a `ureq`-backed implementation of the client's `HttpTransport` port.

**Layer:** adapter · **Depends on:** mycellium-core, ureq

## What it does

The directory and queue clients speak HTTP, but *how* the bytes travel is left to
the host. This crate is the **native** answer: `UreqTransport`, a blocking-socket
implementation of `mycellium_core::http::HttpTransport`. The browser build supplies
its own `fetch`/`XMLHttpRequest` implementation instead — because both clients are
written against the trait rather than any concrete transport, the same client logic
runs verbatim on native and in WebAssembly. This one small crate is the only place
`ureq` appears in the tree.

## Public API

- `UreqTransport` — a unit struct (`Default`) implementing `HttpTransport`.
- `HttpTransport::request(method, url, headers, body)` — sends the request and
  returns an `HttpResponse { status, body }`.

## How it fits

`mycellium-directory-client` and `mycellium-queue-client` expose a `native`
constructor (`new()`) that wires in a `UreqTransport`; both also expose
`with_transport(...)` for callers that bring their own (the browser's XHR
transport lives in `mycellium-wasm`). The engine and CLI use the `native`
constructors, so this crate is their HTTP backend.

## Notes

A ureq `4xx`/`5xx` is surfaced by the library as an *error*; `UreqTransport` folds
it back into a normal `HttpResponse` so callers see the status code. Per the trait
contract, a returned `Err` therefore means a genuine **transport** failure
(connection refused, DNS, TLS) — never merely "the server said no."
