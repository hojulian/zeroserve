# Example patterns

## Log request method and path
- Read with `zs_req_method` and `zs_req_path` into fixed buffers.
- Clamp lengths before logging with `zs_log`.

## Reverse proxy for a path prefix
- Read path and compare prefix, then call `zs_reverse_proxy("http://127.0.0.1:9000", ...)`.
- After calling, return 0; later scripts will be skipped automatically.

## Health endpoint response
- Match a path like `/health`.
- Build a small JSON body and respond with `zs_respond(200, body, len)`.
- Set content type via `zs_meta_set(ZS_STR("zs.response.header.content-type"),
  ZS_STR("application/json"))`.

## Parse JSON from a header
- Read a header or query param into a buffer, then parse with `zs_json_parse`.
- Traverse with `zs_json_get`, `zs_json_array_get` and `zs_json_read_*` and check for `-1` handles.
- Free every handle with `zs_object_free` to avoid hitting the handle limit.

## JWT verification and payload extraction
- Read the `authorization` header, require a `Bearer ` prefix, then split the token
  on `.` to get header, payload, and signature segments.
- Compute `zs_hmac_sha256` over the `header.payload` bytes and Base64URL encode it
  with `zs_base64_encode(..., ZS_BASE64_URL_NO_PAD)` to compare with the signature.
- Base64URL decode the payload in place with `zs_base64_decode_in_place`.

## Template metadata
- Use `zs_meta_set` to populate keys used by `<zs-meta>key</zs-meta>` placeholders
  in HTML/XML static responses.
- Metadata is shared across scripts in the request chain.
