# Zeroserve SDK API (summary)

## Entry point and macros

- Include the SDK: `#include <zeroserve.h>`.
- Mark the entry function with `ZS_ENTRY` (section `zeroserve.request`).
- `ZS_STR("literal")` expands to `(ptr, len)` for NUL-terminated literals.

## Request inspection

- `zs_req_method(out, out_len)`
- `zs_req_path(out, out_len)`
- `zs_req_uri(out, out_len)`
- `zs_req_query(out, out_len)`
- `zs_req_scheme(out, out_len)`
- `zs_req_peer(out, out_len)`
- `zs_req_header(name, name_len, out, out_len)`
- `zs_req_query_param(name, name_len, out, out_len)`
- `zs_req_body_json()` parses the request body as JSON and returns a handle (-1 on failure,
  empty body, body > 256KB, or invalid JSON). The body is read lazily on first call and cached.

## Request mutation

- `zs_req_set_uri(uri, uri_len)`
- `zs_req_set_header(name, name_len, value, value_len)`
    - Pass `value_len = 0` to remove a header.

## Metadata (per-request string map)

- `zs_meta_get(key, key_len, out, out_len)`
- `zs_meta_set(key, key_len, value, value_len)`
    - Keys prefixed with `zs.response.header.` become response headers.

## Response / proxy

- `zs_respond(status, body, body_len)`
- `zs_reverse_proxy(backend_url, backend_url_len)`

## Key-value map

- `zs_kv_get(key, key_len, out, out_len)` looks up `key` in the server-managed
  key-value map loaded from `--kv-map-file`. The map is a flat JSON object
  (`{"key": "value"}`), hot-reloaded via inotify on file change. Returns:
  - number of bytes written into `out` (NOT null-terminated) on success
  - `0` if the key was not found
  - `-1` on error (bad memory, no map configured)

## Logging, time, and environment

- `zs_log(msg, len)`
- `zs_now_ms()`
- `zs_env_get(name, name_len, out, out_len)` reads an environment variable.

## Crypto and encoding

- `zs_getrandom(out, out_len)`
- `zs_sha256(data, data_len, out, out_len)` writes a 32-byte SHA-256 digest (requires `out_len == 32`).
- `zs_hmac_sha256(key, key_len, msg, msg_len, out)`
- `zs_base64_encode(data, data_len, out, out_len, encoding)`
- `zs_base64_decode_in_place(buf, buf_len, encoding)`
- `zs_hex_encode(data, data_len, out, out_len, case)` encodes binary data to hexadecimal.
- `zs_hex_decode_in_place(buf, buf_len)` decodes hexadecimal to binary in place.

## JSON parsing (handle table)

- `zs_json_parse(data, data_len)` parses JSON and returns a handle (-1 on failure).
- `zs_load_static_json(path, path_len)` reads the static file at `path` in the tarball and
  parses JSON, returning a handle (-1 if missing or invalid JSON). The path is used verbatim
  (no normalization, index fallback, or `.html` try).
- `zs_load_file_metadata(path, path_len)` returns a JSON handle for a tarball entry with
  `{"size":...,"etag":...,"mtime":...}` (-1 if missing). The path is used verbatim.
- `zs_json_reset(handle)` resets a handle back to the document root.
- `zs_json_get(handle, key, key_len)` reads an object key and returns a handle
  (-1 if missing, non-object, or invalid UTF-8 key).
- `zs_json_array_get(handle, array_index)` takes an array index and returns a handle
  (-1 if missing, non-array).
- `zs_json_read_string(handle, out, out_len)` writes a JSON string into `out`
  (use `out_len = 0` to query required length; -1 if not a string).
- `zs_json_read_i64(handle, out, out_len)` writes a native-endian `i64` into `out`
  (requires `out_len == sizeof(i64)`; -1 if not a number or out of range).
- `zs_json_read_bool(handle, out, out_len)` writes `0` or `1` into `out`
  (requires `out_len == 1`; -1 if not a boolean).
- `zs_object_free(handle)` releases a JSON handle when you're done with it.
- The handle table is limited (32 entries); free handles to avoid exhaustion.

## JSON creation and modification

- `zs_json_new_object()` creates an empty JSON object `{}`; returns a handle (-1 on failure).
- `zs_json_new_array()` creates an empty JSON array `[]`; returns a handle (-1 on failure).
- `zs_json_clone(handle)` deep-clones a JSON value into a new independent tree; returns a handle.
- `zs_json_len(handle)` returns the length of an array, object, or string (-1 for other types).
- `zs_json_type(handle)` returns the type code: `ZS_JSON_NULL` (0), `ZS_JSON_BOOL` (1),
  `ZS_JSON_NUMBER` (2), `ZS_JSON_STRING` (3), `ZS_JSON_ARRAY` (4), `ZS_JSON_OBJECT` (5).
- `zs_json_set(handle, key, key_len, value_handle)` sets a field on an object; the value is
  cloned from `value_handle`. Returns 0 on success, -1 if not an object.
- `zs_json_remove(handle, key, key_len)` removes a field from an object. Returns 0 on success,
  -1 if not an object or key not found.
- `zs_json_array_push(handle, value_handle)` appends a cloned value to an array; returns new
  length on success, -1 if not an array.
- `zs_json_array_set(handle, index, value_handle)` sets an element at an array index; returns
  0 on success, -1 if out of bounds or not an array.
- `zs_json_set_string(handle, value, value_len)` replaces the node with a string value.
- `zs_json_set_i64(handle, value)` replaces the node with an i64 value.
- `zs_json_set_bool(handle, value)` replaces the node with a boolean (0 = false, non-zero = true).
- `zs_json_set_null(handle)` replaces the node with null.

## JSON response

- `zs_json_respond(status, handle)` serializes the JSON handle to a response body, sets
  `Content-Type: application/json`, and sends the response. Returns 0 on success.

## Helper notes

- String helpers write C strings into the output buffer.
- Passing `out_len = 0` returns the required length.
- Binary helpers return the number of bytes written and do not NUL-terminate.
- `zs_sha256` requires `out_len` to be exactly 32 bytes.
- `zs_hmac_sha256` writes 32 bytes to the output buffer.
- `zs_base64_encode` requires the output buffer to fit the encoded length.
- Base64 `encoding` values: `ZS_BASE64_STANDARD`, `ZS_BASE64_STANDARD_NO_PAD`,
  `ZS_BASE64_URL`, `ZS_BASE64_URL_NO_PAD`.
- `zs_hex_encode` outputs 2 hex characters per input byte; use `out_len = 0` to query the required length.
- `zs_hex_decode_in_place` requires an even `buf_len`; returns the decoded length or -1 on error.
- Hex `case` values: `ZS_HEX_LOWERCASE`, `ZS_HEX_UPPERCASE`.
- Header names are matched case-insensitively.
- The SDK also provides small string/memory helpers like `zs_strlen`, `zs_strcmp`,
  `zs_memcpy`, `zs_memset`, and `zs_utoa10`.
- `zs_req_body_json` reads the body lazily (only when called) and caches the result.
  Subsequent calls return the cached handle. The body is limited to 256KB.

## AWS SigV4 signing

- `zs_aws_v4_authorization_header(params, params_len)` generates an AWS Signature Version 4
  Authorization header value. Takes a pointer to `zs_aws_v4_sign_params` and the struct size.
  Returns the number of characters written (excluding null terminator), or -1/-2 on error.
  If `params->out_len` is 0, returns the required buffer size without writing.

  The `zs_aws_v4_sign_params` struct fields:
  - `access_key`, `access_key_len`: AWS access key ID
  - `secret_key`, `secret_key_len`: AWS secret access key
  - `region`, `region_len`: AWS region (e.g., "us-east-1")
  - `service`, `service_len`: Service name (e.g., "s3", "execute-api")
  - `method`, `method_len`: HTTP method (e.g., "GET", "POST")
  - `uri`, `uri_len`: Request URI including path and optional query string
  - `headers_json`: JSON object handle with headers to sign (e.g., `{"host": "s3.amazonaws.com"}`)
  - `body_hash`, `body_hash_len`: Hex-encoded SHA256 of body, or "UNSIGNED-PAYLOAD"
  - `timestamp_ms`: Unix timestamp in milliseconds for the request
  - `out`, `out_len`: Output buffer for the Authorization header value

  Example usage:

  ```c
  char auth[512];
  zs_json headers = zs_json_new_object();
  zs_json_set_string(headers, "host", 4, "s3.amazonaws.com", 16);

  zs_aws_v4_sign_params p = {
      .access_key = "AKIA...", .access_key_len = 20,
      .secret_key = "wJalr...", .secret_key_len = 40,
      .region = "us-east-1", .region_len = 9,
      .service = "s3", .service_len = 2,
      .method = "GET", .method_len = 3,
      .uri = "/bucket/object", .uri_len = 14,
      .headers_json = headers,
      .body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      .body_hash_len = 64,
      .timestamp_ms = zs_now_ms(),
      .out = auth, .out_len = sizeof(auth)
  };

  zs_s64 n = zs_aws_v4_authorization_header(&p, sizeof(p));
  if (n > 0) {
      zs_req_set_header("Authorization", 13, auth, n);
  }
  zs_object_free(headers);
  ```

- `zs_aws_v4_presigned_url(params, params_len, expires_secs)` generates an AWS Signature
  Version 4 pre-signed URL. Takes a pointer to `zs_aws_v4_sign_params`, the struct size,
  and the expiration time in seconds. Returns the number of characters written (excluding
  null terminator), or -1/-2 on error. If `params->out_len` is 0, returns the required
  buffer size without writing.

  The output is a URL path with query string containing the signature parameters
  (`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`,
  `X-Amz-SignedHeaders`, `X-Amz-Signature`). The body is always treated as
  `UNSIGNED-PAYLOAD`.

  Example usage:

  ```c
  char url[1024];
  zs_json headers = zs_json_new_object();
  zs_s64 host_val = zs_json_parse(ZS_STR("\"s3.amazonaws.com\""));
  zs_json_set(headers, ZS_STR("host"), host_val);
  zs_object_free(host_val);

  zs_aws_v4_sign_params p = {
      .access_key = "AKIA...", .access_key_len = 20,
      .secret_key = "wJalr...", .secret_key_len = 40,
      .region = "us-east-1", .region_len = 9,
      .service = "s3", .service_len = 2,
      .method = "GET", .method_len = 3,
      .uri = "/bucket/object?prefix=docs/", .uri_len = 25,
      .headers_json = headers,
      .timestamp_ms = zs_now_ms(),
      .out = url, .out_len = sizeof(url)
  };

  zs_s64 n = zs_aws_v4_presigned_url(&p, sizeof(p), 3600);
  if (n > 0) {
      // url now contains "/bucket/object?prefix=docs/&X-Amz-Algorithm=..."
  }
  zs_object_free(headers);
  ```

## Rate limiting

- `zs_rate_limit(key, key_len, per_second, per_minute, per_hour)` checks whether a request
  should be allowed based on rate limits for the given key. Returns:
  - `ZS_RATE_LIMIT_ALLOWED` (0) if allowed
  - `ZS_RATE_LIMIT_EXCEEDED_SECOND` (1) if per-second limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_MINUTE` (2) if per-minute limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_HOUR` (3) if per-hour limit exceeded
  - `ZS_RATE_LIMIT_EXCEEDED_BUCKET_LIMIT` (4) if too many unique keys are being tracked
  - `-1` on error (invalid parameters or key too long, max 256 bytes)

  A limit of 0 means unlimited for that window. The key can be any arbitrary bytes,
  such as an IP address (`zs_req_peer`), API key, or user ID. Rate limit state is
  shared across all requests and persists across hot reloads.

  Example (rate limit by API key):

  ```c
  ZS_ENTRY
  zs_u64 entry(void) {
      char api_key[128];
      if (zs_req_header("X-API-Key", 9, api_key, sizeof(api_key)) <= 0) {
          zs_respond(401, ZS_STR("{\"error\":\"missing api key\"}"));
          return 0;
      }

      // Allow 5 req/s, 60 req/min per API key
      zs_s64 result = zs_rate_limit(ZS_STR(api_key), 5, 60, 0);
      if (result != ZS_RATE_LIMIT_ALLOWED) {
          zs_respond(429, ZS_STR("{\"error\":\"rate limit exceeded\"}"));
          return 0;
      }
      return 0;
  }
  ```

## OIDC login (Authorization Code + PKCE)

zeroserve is the OAuth2 client (Relying Party). Config is passed as a JSON object
handle (keys: `issuer` or `authorization_endpoint`+`token_endpoint`, `client_id`,
`client_secret`, `redirect_uri`, optional `scope`, `cookie_secret`,
`session_ttl_secs`). Login state and the session live in sealed cookies (no
server-side store). `cookie_secret` must be >= 16 bytes and stable across
restarts. The id_token claims are validated (`iss`/`aud`/`exp`/`nonce`) but its
signature is not separately checked (it is fetched over TLS from the token
endpoint; OIDC Core 3.1.3.7).

- `zs_oidc_begin_login(cfg, return_to, return_to_len)` — set state cookie, 302 to
  the IdP, return to `return_to` afterward. Terminal.
- `zs_oidc_handle_callback(cfg)` — on the `redirect_uri` path: validate state,
  exchange the code, set the session cookie, 302 to `return_to`. Terminal.
- `zs_oidc_session_verify(cfg)` — JSON claims handle if logged in, `0` if not,
  `<0` on error. Not terminal; free the handle with `zs_object_free`.
- `zs_oidc_logout(cfg, end_session_url, end_session_url_len)` — clear the session
  cookie and optionally 302 to the IdP end-session URL. Terminal.

  Example (gate the site, with /callback and /logout routes):
  ```c
  zs_s64 cfg = zs_json_parse(ZS_STR(
      "{\"issuer\":\"https://idp.example\","
       "\"client_id\":\"cid\",\"client_secret\":\"csecret\","
       "\"redirect_uri\":\"https://app.example/callback\","
       "\"cookie_secret\":\"stable-16+byte-secret\"}"));
  if (cfg < 0) { zs_respond(500, ZS_STR("config error")); return 0; }

  char path[256];
  zs_req_path(path, sizeof(path));
  if (zs_memcmp(path, "/callback", 9) == 0) { zs_oidc_handle_callback(cfg); return 0; }
  if (zs_memcmp(path, "/logout", 7) == 0)  { zs_oidc_logout(cfg, ZS_STR("")); return 0; }

  zs_s64 session = zs_oidc_session_verify(cfg);
  if (session <= 0) {
      char uri[512]; zs_req_uri(uri, sizeof(uri));
      zs_oidc_begin_login(cfg, ZS_STR(uri));
      return 0;
  }
  zs_object_free(session);
  return 0;  // authenticated
  ```
