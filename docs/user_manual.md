# Zeroserve User Manual

## Overview

Zeroserve is a high-performance, scriptable HTTP server that uses `io_uring` and eBPF. It
serves a static website from a tarball, and optionally runs eBPF request scripts.
It supports HTTP, HTTPS, hot reload, a small templating pass for text responses, and
an opt-in reverse proxy from scripts.
The HTTP listener also accepts HTTP/2 cleartext (h2c) via prior knowledge.
HTTPS negotiates HTTP/2 (h2) via ALPN with HTTP/1.1 fallback.

## Quick start

Serve a prebuilt tarball:

```bash
zeroserve --addr 0.0.0.0:8080 site.tar
```

Package a directory into a tarball and serve it:

```bash
# Create a tarball from the current directory
zeroserve --pack . > site.tar

# Serve it
zeroserve --addr 0.0.0.0:8080 site.tar
```

## Packaging a site

Zeroserve expects a tarball whose root corresponds to the site root.
Use `--pack` to build one from a directory:

```bash
zeroserve --pack ./public > site.tar
```

Packaging notes:

- All regular files under the directory are added to the tarball.
- Request scripts live under `.zeroserve/scripts/`.
- Any `.c` file in `.zeroserve/scripts/` is compiled to an `.o` eBPF object.
  The resulting `.o` is included in the tarball and the `.c` is omitted.
- If a `.c` and `.o` share the same name, the `.o` is skipped in favor of recompiling.
- Script compilation requires `clang` and `llc` on your `PATH`.

If you want the SDK header without packing:

```bash
zeroserve --dump-sdk > zeroserve.h
```

## Running the server

Command synopsis:

```bash
zeroserve [OPTIONS] SITE_TAR
```

Key options:

- `--addr <IP:PORT>`: HTTP bind address (default `0.0.0.0:8080`).
- `--tls-addr <IP:PORT>`: HTTPS bind address (requires `--cert` and `--key`).
- `--cert <FILE>`: TLS certificate PEM.
- `--key <FILE>`: TLS private key PEM.
- `--index <NAME>`: Default document for directories (default `index.html`).
- `--try-html`: Try `<path>.html` when a request path is missing.
- `--chunk-size <BYTES>`: Streaming chunk size for tar reads (default 65536).
- `--reload-signal-file <FILE>`: Poll a file and reload when its contents change.
- `--disable-request-logging`: Turn off per-request logs.
- `--enable-proxy-protocol`: Expect PROXY protocol v1 on each new connection.
- `--disable-ns-isolation`: Disable Linux namespace isolation.
- `--enable-netns-isolation`: Enable Linux network namespace isolation.
- `--preempt-timer-interval-ms <MS>`: Script preemption timer interval.
- `--sqpoll-idle-ms <MS>`: Enable io_uring sqpoll with idle timeout.

Examples:

```bash
# HTTP only
zeroserve --addr 0.0.0.0:8080 site.tar

# HTTP + HTTPS
zeroserve --addr 0.0.0.0:8080 \
  --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem \
  site.tar

# HTML fallback and PROXY protocol
zeroserve --try-html --enable-proxy-protocol site.tar
```

## Routing and file lookup

Zeroserve normalizes request paths (handles `.`/`..` and percent decoding) before lookup.
Lookup order:

- Direct match for the requested path.
- If the path is a directory (or looks like one), try `<path>/<index>`.
- Also tries `<path>/<index>` even without a trailing slash.
- If `--try-html` is enabled, try `<path>.html` when the path has no extension.

The default index document is `index.html`, configurable via `--index`.

## Hot reload

Zeroserve reloads the site tarball, scripts, and TLS configuration on:

- `SIGHUP` (for example: `killall -SIGHUP zeroserve`).
- Changes to `--reload-signal-file` (polled periodically, content-based).

This is useful for replacing the tarball and certificate in place without downtime.

## TLS

To enable HTTPS, provide a TLS address plus certificate and key. HTTPS supports
HTTP/2 via ALPN (h2) with HTTP/1.1 fallback:

```bash
zeroserve --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem site.tar
```

Reloading TLS assets uses the same hot-reload mechanism as the tarball.

## Request scripting (eBPF)

Zeroserve can run eBPF programs on every request. Scripts are loaded from
`.zeroserve/scripts/*.o` inside the tarball and executed in sorted path order.

Flow and behavior:

- Each script must export a function in section `zeroserve.request`.
  Use the `ZS_ENTRY` macro to mark the entrypoint.
- Scripts run for every request.
- A per-request metadata map is shared across scripts.
- If a script calls `zs_respond`, its response is sent and later scripts are skipped.
- If a script calls `zs_reverse_proxy`, the request is proxied and later scripts are skipped.
- Script failures are logged but do not abort the chain.

### Entry point

```c
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  // ...
  return 0;
}
```

### Building scripts

Option A: let `--pack` compile `.c` sources automatically.

```bash
zeroserve --pack ./site > site.tar
```

Option B: compile manually.

```bash
clang -O2 -target bpf -emit-llvm -c input.c -o tmp.bc
llc -march=bpf -bpf-stack-size=4096 -mcpu=v3 -filetype=obj tmp.bc -o out.o
```

Put the `.o` files at `.zeroserve/scripts/` in the tarball.

### Helper API overview

Logging and time:

- `zs_log(msg, len)`
- `zs_now_ms()` returns milliseconds since the Unix epoch.

Crypto and encoding:

- `zs_getrandom(out, out_len)` fills `out` with random bytes.
- `zs_hmac_sha256(key, key_len, msg, msg_len, out)` writes a 32-byte digest.
- `zs_base64_encode(data, data_len, out, out_len, encoding)` encodes Base64.
- `zs_base64_decode_in_place(buf, buf_len, encoding)` decodes Base64 in place.

JSON parsing:

- `zs_json_parse(data, data_len)` parses JSON and returns a handle (-1 on failure).
- `zs_load_static_json(path, path_len)` reads the static file at `path` in the tarball,
  parses JSON, and returns a handle (-1 if missing or invalid JSON). The path is used
  verbatim (no normalization, index fallback, or `.html` try).
- `zs_load_file_metadata(path, path_len)` returns a JSON handle for a tarball entry
  with `{"size":...,"etag":...,"mtime":...}` (-1 if missing). The path is used verbatim.
- `zs_json_reset(json)` resets a handle back to the document root.
- `zs_json_get(json, key, key_len)` reads an object key and returns a handle (-1 if missing).
- `zs_json_array_get(handle, array_index)` takes an array index and returns a handle
  (-1 if missing, non-array).
- `zs_json_read_string(json, out, out_len)` writes a JSON string into `out`.
- `zs_json_read_i64(json, out, out_len)` writes an `i64` into `out`.
- `zs_json_read_bool(json, out, out_len)` writes `0` or `1` into `out`.
- `zs_object_free(handle)` releases a handle when you're done with it.

Request inspection:

- `zs_req_method`, `zs_req_path`, `zs_req_uri`, `zs_req_query`, `zs_req_scheme`, `zs_req_peer`
- `zs_req_header(name, name_len, out, out_len)`
- `zs_req_query_param(name, name_len, out, out_len)`

Request mutation:

- `zs_req_set_uri(uri, uri_len)`
- `zs_req_set_header(name, name_len, value, value_len)`
  (pass `value_len = 0` to remove the header)

Metadata:

- `zs_meta_get(key, key_len, out, out_len)`
- `zs_meta_set(key, key_len, value, value_len)`

Metadata keys prefixed with `zs.response.header.` are applied as HTTP response
headers for all responses (static files, `zs_respond`, and reverse proxy).
Example: `zs_meta_set("zs.response.header.cache-control", ..., "no-store", ...)`.

Response/proxy:

- `zs_respond(status, body, body_len)`
- `zs_reverse_proxy(backend_url, backend_url_len)`

Helper notes:

- String helpers write C strings into the provided buffer.
- If `out_len = 0`, helpers return the required length.
- Binary helpers return the number of bytes written and do not NUL-terminate.
- `zs_hmac_sha256` requires an output buffer of at least 32 bytes.
- `zs_base64_encode` needs an output buffer sized to the encoded length; use `out_len = 0` to query it.
- `zs_base64_decode_in_place` uses `buf_len` bytes of input (exclude any trailing NUL).
- `zs_json_read_i64` writes a native-endian `i64`; `zs_json_read_bool` writes a single byte.
- Base64 `encoding` values: `ZS_BASE64_STANDARD` (0), `ZS_BASE64_STANDARD_NO_PAD` (1),
  `ZS_BASE64_URL` (2), `ZS_BASE64_URL_NO_PAD` (3).
- Header names are matched case-insensitively.
- `ZS_STR("literal")` expands to `(ptr, len)` using `zs_strlen`, which is handy for
  helpers that take a string pointer plus length; only use it with NUL-terminated
  strings and pass explicit lengths for binary or embedded-NUL data.

Examples:

- `examples/log_request.c` logs method and path.
- `examples/reverse_proxy.c` proxies `/api` to a backend.
- `examples/template.c` sets metadata for templating.
- `examples/health_response.c` returns a JSON health check.

**For a complete list of APIs, run `zeroserve --dump-sdk` to dump the SDK header.**

## Template substitution

When scripts set metadata, Zeroserve performs a simple template replacement on
static text responses. Any `<zs-meta>key</zs-meta>` placeholder (with optional
whitespace around the key) is replaced with the corresponding metadata value.

Rules:

- Only applies to HTML and XML MIME types.
- Only runs for static file responses, not `zs_respond` bodies.
- Unknown keys are removed.

Example:

```html
<h1>Hello <zs-meta>name</zs-meta></h1>
```

If a script does `zs_meta_set("name", ..., "Ada", ...)`, the response becomes:

```html
<h1>Hello Ada</h1>
```

## Reverse proxy behavior

`zs_reverse_proxy` takes a backend URL such as `http://127.0.0.1:9000` or
`https://api.example.com/v1?token=abc`.

Zeroserve will:

- Append the request path to the backend base path.
- Merge the backend query string with the request query string.
- Use the backend host (and port if non-default) for the `Host` header.

Only `http` and `https` backends are supported.

## Operational notes

- Request logging is enabled by default; disable with `--disable-request-logging`.
- `--enable-proxy-protocol` is required when running behind a TCP load balancer
  that speaks PROXY protocol v1.
- `--disable-ns-isolation` and `--enable-netns-isolation` are Linux-specific
  isolation controls; leave them default unless you know you need them.
- Long-running scripts are throttled; keep scripts fast and avoid busy loops.
- Static file responses include an `ETag` based on a Blake3 hash prefix; matching
  `If-None-Match` requests receive `304 Not Modified`.

## Troubleshooting

- TLS startup errors: `--tls-addr` requires both `--cert` and `--key`.
- `--pack expects a directory`: pass a directory path, not a file.
- `tarball ... does not contain any regular files`: ensure your site has files.
- Script compilation fails: verify `clang` and `llc` are on `PATH`.
