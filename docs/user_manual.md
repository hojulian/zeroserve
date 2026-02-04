# Zeroserve User Manual

## Overview

Zeroserve is a high-performance, scriptable HTTP server that uses `io_uring` and eBPF. It
serves a static website from a tarball, and optionally runs eBPF request scripts.
It supports HTTP, HTTPS, hot reload, a small templating pass for text responses, and
an opt-in reverse proxy from scripts.

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

- `--addr <ADDR>`: HTTP listen address (default `0.0.0.0:8080`). Accepts either
  `ip:port` to bind a new socket, or `fd:N` to use an inherited file descriptor.
- `--tls-addr <ADDR>`: HTTPS listen address (requires `--cert` and `--key`).
  Accepts either `ip:port` or `fd:N`.
- `--cert <FILE>`: TLS certificate PEM.
- `--key <FILE>`: TLS private key PEM.
- `--index <NAME>`: Default document for directories (default `index.html`).
- `--try-html`: Try `<path>.html` when a request path is missing.
- `--chunk-size <BYTES>`: Streaming chunk size for tar reads (default 65536).
- `--max-buffered-body-size-kb <KB>`: Maximum request body size in KB for script
  body reads via `zs_req_body_json` (default 256).
- `--max-request-external-memory-footprint-kb <KB>`: Maximum external memory
  footprint in KB per request for scripts (default 256).
- `--reload-signal-file <FILE>`: Poll a file and reload when its contents change.
- `--disable-request-logging`: Turn off per-request logs.
- `--enable-proxy-protocol`: Expect PROXY protocol v1 on each new connection.
- `--disable-ns-isolation`: Disable Linux namespace isolation.
- `--enable-netns-isolation`: Enable Linux network namespace isolation.
- `--preempt-timer-interval-ms <MS>`: Script preemption timer interval.
- `--sqpoll-idle-ms <MS>`: Enable io_uring sqpoll with idle timeout.
- `--validate-hostnames <HOSTNAMES>`: Comma-separated list of allowed hostnames.
  Requests with a non-matching `Host` header (or HTTP/2 `:authority`) receive a
  `421 Misdirected Request` response. Supports IPv4, IPv6 (bracket notation), and
  hostnames with optional ports (e.g., `example.com,api.example.com,[::1]`).
  Matching is case-insensitive and port numbers are stripped before comparison.

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

# Socket activation (inherit pre-bound sockets)
zeroserve --addr fd:3 --tls-addr fd:4 --cert cert.pem --key key.pem site.tar

# Hostname validation (reject requests not matching allowed hostnames)
zeroserve --validate-hostnames example.com,www.example.com,[::1] site.tar
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
- `zs_env_get(name, name_len, out, out_len)` reads an environment variable.

Crypto and encoding:

- `zs_getrandom(out, out_len)` fills `out` with random bytes.
- `zs_sha256(data, data_len, out, out_len)` writes a 32-byte SHA-256 digest.
- `zs_hmac_sha256(key, key_len, msg, msg_len, out)` writes a 32-byte HMAC-SHA-256 digest.
- `zs_base64_encode(data, data_len, out, out_len, encoding)` encodes Base64.
- `zs_base64_decode_in_place(buf, buf_len, encoding)` decodes Base64 in place.
- `zs_hex_encode(data, data_len, out, out_len, case)` encodes binary data to hexadecimal.
- `zs_hex_decode_in_place(buf, buf_len)` decodes hexadecimal to binary in place.

AWS Signature Version 4:

- `zs_aws_v4_authorization_header(params, params_len)` generates an AWS SigV4
  Authorization header value. Takes a pointer to `zs_aws_v4_sign_params`
  and the struct size. Returns the number of characters written (excluding null
  terminator), or -1/-2 on error. If `params->out_len` is 0, returns the required
  buffer size without writing.

    The `zs_aws_v4_sign_params` struct fields:
    - `access_key`, `access_key_len`: AWS access key ID
    - `secret_key`, `secret_key_len`: AWS secret access key
    - `region`, `region_len`: AWS region (e.g., "us-east-1")
    - `service`, `service_len`: Service name (e.g., "s3", "execute-api")
    - `method`, `method_len`: HTTP method (e.g., "GET", "POST")
    - `uri`, `uri_len`: Request URI including path and optional query string
    - `headers_json`: JSON object handle with headers to sign
    - `body_hash`, `body_hash_len`: Hex-encoded SHA256, or "UNSIGNED-PAYLOAD"
    - `timestamp_ms`: Unix timestamp in milliseconds
    - `out`, `out_len`: Output buffer for the Authorization header value

- `zs_aws_v4_presigned_url(params, params_len, expires_secs)` generates an AWS SigV4
  pre-signed URL. Takes a pointer to `zs_aws_v4_sign_params`, the struct size, and the
  expiration time in seconds. Returns the number of characters written (excluding null
  terminator), or -1/-2 on error. If `params->out_len` is 0, returns the required
  buffer size without writing.

  The output is a URL path with query string containing the signature parameters
  (`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`,
  `X-Amz-SignedHeaders`, `X-Amz-Signature`). The body is always treated as
  `UNSIGNED-PAYLOAD`.

  The `zs_aws_v4_sign_params` struct is shared with `zs_aws_v4_authorization_header`,
  but `body_hash` is ignored (always treated as `UNSIGNED-PAYLOAD`).

Rate limiting:

- `zs_rate_limit(key, key_len, per_second, per_minute, per_hour)` checks whether a
  request should be allowed based on rate limits for the given key. Returns:
  - `ZS_RATE_LIMIT_ALLOWED` (0) if the request is allowed
  - `ZS_RATE_LIMIT_EXCEEDED_SECOND` (1) if per-second limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_MINUTE` (2) if per-minute limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_HOUR` (3) if per-hour limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_BUCKET_LIMIT` (4) if too many unique keys are being tracked
  - `-1` on error (invalid parameters or key too long, max 256 bytes)

  A limit of 0 means unlimited for that window. The key can be any arbitrary bytes,
  such as an IP address (`zs_req_peer`), API key, or user ID. Rate limit state is
  shared across all requests and persists across hot reloads.

  Example (rate limit by IP):
  ```c
  char peer[64];
  zs_req_peer(peer, sizeof(peer));
  int64_t result = zs_rate_limit(ZS_STR(peer), 10, 100, 1000);
  if (result == ZS_RATE_LIMIT_EXCEEDED_SECOND) {
      zs_respond(429, ZS_STR("{\"error\":\"rate limit exceeded\"}"));
      return 0;
  }
  ```

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

JSON creation and modification:

- `zs_json_new_object()` creates an empty JSON object `{}`; returns a handle.
- `zs_json_new_array()` creates an empty JSON array `[]`; returns a handle.
- `zs_json_clone(json)` deep-clones a JSON value into a new independent tree.
- `zs_json_len(json)` returns the length of an array, object, or string (-1 for other types).
- `zs_json_type(json)` returns the type code: `ZS_JSON_NULL` (0), `ZS_JSON_BOOL` (1),
  `ZS_JSON_NUMBER` (2), `ZS_JSON_STRING` (3), `ZS_JSON_ARRAY` (4), `ZS_JSON_OBJECT` (5).
- `zs_json_set(json, key, key_len, value_json)` sets a field on an object (value is cloned).
- `zs_json_remove(json, key, key_len)` removes a field from an object.
- `zs_json_array_push(json, value_json)` appends a cloned value to an array.
- `zs_json_array_set(json, index, value_json)` sets an element at an array index.
- `zs_json_set_string(json, value, value_len)` replaces the node with a string.
- `zs_json_set_i64(json, value)` replaces the node with an i64.
- `zs_json_set_bool(json, value)` replaces the node with a boolean.
- `zs_json_set_null(json)` replaces the node with null.

JSON response:

- `zs_json_respond(status, json)` serializes the JSON handle to a response body,
  sets `Content-Type: application/json`, and sends the response.

Request inspection:

- `zs_req_method`, `zs_req_path`, `zs_req_uri`, `zs_req_query`, `zs_req_scheme`, `zs_req_peer`
- `zs_req_header(name, name_len, out, out_len)`
- `zs_req_query_param(name, name_len, out, out_len)`
- `zs_req_body_json()` parses the request body as JSON and returns a handle (-1 on failure).

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
- `zs_json_respond(status, json)` (auto-sets Content-Type to application/json)
- `zs_reverse_proxy(backend_url, backend_url_len)`

Helper notes:

- String helpers write C strings into the provided buffer.
- If `out_len = 0`, helpers return the required length.
- Binary helpers return the number of bytes written and do not NUL-terminate.
- `zs_sha256` requires `out_len` to be exactly 32 bytes.
- `zs_hmac_sha256` requires an output buffer of at least 32 bytes.
- `zs_base64_encode` needs an output buffer sized to the encoded length; use `out_len = 0` to query it.
- `zs_base64_decode_in_place` uses `buf_len` bytes of input (exclude any trailing NUL).
- `zs_hex_encode` outputs 2 hex characters per input byte; use `out_len = 0` to query the required length.
- `zs_hex_decode_in_place` requires an even `buf_len`; returns the decoded length or -1 on error.
- `zs_json_read_i64` writes a native-endian `i64`; `zs_json_read_bool` writes a single byte.
- Base64 `encoding` values: `ZS_BASE64_STANDARD` (0), `ZS_BASE64_STANDARD_NO_PAD` (1),
  `ZS_BASE64_URL` (2), `ZS_BASE64_URL_NO_PAD` (3).
- Hex `case` values: `ZS_HEX_LOWERCASE` (0), `ZS_HEX_UPPERCASE` (1).
- Header names are matched case-insensitively.
- `ZS_STR("literal")` expands to `(ptr, len)` using `zs_strlen`, which is handy for
  helpers that take a string pointer plus length; only use it with NUL-terminated
  strings and pass explicit lengths for binary or embedded-NUL data.
- `zs_req_body_json` reads the request body lazily (only when called) and caches the
  result for subsequent calls. The body is limited to 256KB by default (configurable
  via `--max-buffered-body-size-kb`); larger bodies return -1. Returns -1 for empty
  bodies or invalid JSON.

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

## Socket activation

Zeroserve supports socket activation, where a process manager (such as systemd)
pre-binds the listening sockets and passes them as inherited file descriptors.
Use `fd:N` syntax instead of `ip:port`:

```bash
zeroserve --addr fd:3 site.tar
```

This is useful for:

- Zero-downtime restarts (the socket stays open during process replacement).
- Running without elevated privileges (the parent binds privileged ports).
- Integration with systemd socket units.

Example systemd socket unit (`zeroserve.socket`):

```ini
[Socket]
ListenStream=80
ListenStream=443

[Install]
WantedBy=sockets.target
```

Example systemd service unit (`zeroserve.service`):

```ini
[Service]
ExecStart=/usr/bin/zeroserve --addr fd:3 --tls-addr fd:4 --cert /etc/certs/cert.pem --key /etc/certs/key.pem /var/www/site.tar
```

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
