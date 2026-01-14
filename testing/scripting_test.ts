import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
    hasBpfToolchain,
    packSite,
    repoRoot,
    withZeroserve,
} from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();
const encoder = new TextEncoder();

function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

function base64ToBase64Url(base64: string): string {
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function bytesToBase64Url(bytes: Uint8Array): string {
    return base64ToBase64Url(bytesToBase64(bytes));
}

async function startBackend(
    handler: (req: Request) => Response,
): Promise<{ url: string; close: () => Promise<void> }> {
    const controller = new AbortController();
    let port = 0;
    const server = Deno.serve(
        {
            hostname: "127.0.0.1",
            port: 0,
            signal: controller.signal,
            onListen: ({ port: listenPort }) => {
                port = listenPort;
            },
        },
        handler,
    );

    if (port === 0) {
        await new Promise((resolve) => setTimeout(resolve, 0));
    }

    if (port === 0) {
        controller.abort();
        await server.finished;
        throw new Error("failed to start backend server");
    }

    return {
        url: `http://127.0.0.1:${port}`,
        close: async () => {
            controller.abort();
            await server.finished;
        },
    };
}

Deno.test({
    name: "e2e: scripting APIs",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "Hello <zs-meta>name</zs-meta> via <zs-meta>method</zs-meta> at <zs-meta>now_ms</zs-meta>\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.copyFile(
                join(repoRoot, "examples", "template.c"),
                join(scriptsDir, "template.c"),
            );
            await Deno.copyFile(
                join(repoRoot, "examples", "health_response.c"),
                join(scriptsDir, "health_response.c"),
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const healthRes = await fetch(`${baseUrl}/health`);
                assertEquals(healthRes.status, 200);
                const healthJson = (await healthRes.json()) as {
                    status: string;
                    year: string;
                };
                assertEquals(healthJson.status, "ok");
                const year = Number.parseInt(healthJson.year, 10);
                assert(!Number.isNaN(year));
                assert(year >= 1970 && year <= 3000);

                const templatedRes = await fetch(
                    `${baseUrl}/index.html?name=user`,
                );
                assertEquals(templatedRes.status, 200);
                const templatedBody = await templatedRes.text();
                assert(templatedBody.includes("Hello user via GET"));
                assert(!templatedBody.includes("<zs-meta>name</zs-meta>"));
                assert(!templatedBody.includes("<zs-meta>method</zs-meta>"));
                assert(!templatedBody.includes("<zs-meta>now_ms</zs-meta>"));
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: request mutations (set_uri, set_header)",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startBackend((req) => {
            const url = new URL(req.url);
            const payload = {
                path: url.pathname,
                query: url.search.slice(1),
                headers: {
                    "x-original": req.headers.get("x-original"),
                    "x-remove": req.headers.get("x-remove"),
                    "x-script-set": req.headers.get("x-script-set"),
                },
            };
            return new Response(JSON.stringify(payload), {
                headers: { "content-type": "application/json" },
            });
        });

        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "proxy target\n",
            );
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const backendUrl = backend.url;
            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  zs_req_set_uri(ZS_STR("/proxy/rewritten?name=changed&flag=1"));
  zs_req_set_header(ZS_STR("x-script-set"), ZS_STR("from-script"));
  zs_req_set_header(ZS_STR("x-remove"), ZS_STR(""));
  zs_reverse_proxy(ZS_STR("${backendUrl}"));
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-rewrite_proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/original/path?name=orig`, {
                    headers: {
                        "x-original": "keep",
                        "x-remove": "drop",
                    },
                });
                assertEquals(res.status, 200);
                const payload = (await res.json()) as {
                    path: string;
                    query: string;
                    headers: Record<string, string | null>;
                };
                assertEquals(payload.path, "/proxy/rewritten");
                assertEquals(payload.query, "name=changed&flag=1");
                assertEquals(payload.headers["x-original"], "keep");
                assertEquals(payload.headers["x-script-set"], "from-script");
                assertEquals(payload.headers["x-remove"], null);
            });
        } finally {
            await backend.close().catch(() => {});
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: metadata response headers",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startBackend(() => {
            return new Response("proxied", {
                headers: { "content-type": "text/plain" },
            });
        });

        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "static.txt"),
                "static ok\n",
            );
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const backendUrl = backend.url;
            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  const char *header_key = "zs.response.header.x-test";
  const char *header_value = "meta";
  zs_meta_set(
    ZS_STR(header_key),
    ZS_STR(header_value)
  );

  char path[64];
  zs_req_path(path, sizeof(path));

  if (zs_strcmp(path, "/respond") == 0) {
    zs_respond(201, ZS_STR("script response"));
    return 0;
  }

  if (zs_strcmp(path, "/proxy") == 0) {
    zs_reverse_proxy(ZS_STR("${backendUrl}"));
    return 0;
  }

  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-response-headers.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const staticRes = await fetch(`${baseUrl}/static.txt`);
                assertEquals(staticRes.status, 200);
                assertEquals(staticRes.headers.get("x-test"), "meta");
                assertEquals(await staticRes.text(), "static ok\n");

                const scriptRes = await fetch(`${baseUrl}/respond`);
                assertEquals(scriptRes.status, 201);
                assertEquals(scriptRes.headers.get("x-test"), "meta");
                assertEquals(await scriptRes.text(), "script response");

                const proxyRes = await fetch(`${baseUrl}/proxy`);
                assertEquals(proxyRes.status, 200);
                assertEquals(proxyRes.headers.get("x-test"), "meta");
                assertEquals(await proxyRes.text(), "proxied");
            });
        } finally {
            await backend.close().catch(() => {});
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: crypto helpers",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "crypto helpers\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

static int base64_roundtrip(const char *input, zs_u64 input_len, zs_u64 encoding) {
  char buf[64];
  zs_s64 enc_len = zs_base64_encode(input, input_len, buf, sizeof(buf), encoding);
  if (enc_len <= 0) return 0;
  zs_s64 dec_len = zs_base64_decode_in_place(buf, enc_len, encoding);
  if (dec_len != (zs_s64)input_len) return 0;
  if (zs_memcmp(buf, input, input_len) != 0) return 0;
  return 1;
}

static int base64_expected(void) {
  zs_u8 bytes[3] = {0xff, 0xff, 0xff};
  char buf[8];
  zs_s64 len = zs_base64_encode(bytes, sizeof(bytes), buf, sizeof(buf), ZS_BASE64_STANDARD);
  if (len != 4 || zs_memcmp(buf, "////", 4) != 0) return 0;
  len = zs_base64_encode(bytes, sizeof(bytes), buf, sizeof(buf), ZS_BASE64_URL);
  if (len != 4 || zs_memcmp(buf, "____", 4) != 0) return 0;

  const char hi[] = "hi";
  len = zs_base64_encode(hi, sizeof(hi) - 1, buf, sizeof(buf), ZS_BASE64_STANDARD);
  if (len != 4 || zs_memcmp(buf, "aGk=", 4) != 0) return 0;
  len = zs_base64_encode(hi, sizeof(hi) - 1, buf, sizeof(buf), ZS_BASE64_STANDARD_NO_PAD);
  if (len != 3 || zs_memcmp(buf, "aGk", 3) != 0) return 0;
  len = zs_base64_encode(hi, sizeof(hi) - 1, buf, sizeof(buf), ZS_BASE64_URL_NO_PAD);
  if (len != 3 || zs_memcmp(buf, "aGk", 3) != 0) return 0;

  return 1;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/crypto") != 0) {
    return 0;
  }

  zs_u8 digest[32];
  zs_hmac_sha256(ZS_STR("supersecret"), ZS_STR("hello"), digest);

  char hmac_b64[64];
  zs_s64 hmac_len = zs_base64_encode(digest, sizeof(digest), hmac_b64, sizeof(hmac_b64), ZS_BASE64_STANDARD);

  zs_u8 rand_bytes[32];
  zs_s64 rand_len = zs_getrandom(rand_bytes, sizeof(rand_bytes));
  char rand_b64[64];
  zs_s64 rand_b64_len = zs_base64_encode(rand_bytes, rand_len, rand_b64, sizeof(rand_b64), ZS_BASE64_STANDARD);

  int ok = 1;
  if (hmac_len <= 0 || rand_len != (zs_s64)sizeof(rand_bytes) || rand_b64_len <= 0) ok = 0;
  if (!base64_roundtrip("hello", sizeof("hello") - 1, ZS_BASE64_STANDARD)) ok = 0;
  if (!base64_roundtrip("hello", sizeof("hello") - 1, ZS_BASE64_STANDARD_NO_PAD)) ok = 0;
  if (!base64_roundtrip("hello", sizeof("hello") - 1, ZS_BASE64_URL)) ok = 0;
  if (!base64_roundtrip("hello", sizeof("hello") - 1, ZS_BASE64_URL_NO_PAD)) ok = 0;
  if (!base64_expected()) ok = 0;

  char body[256];
  char *bp = zs_stpcpy(body, "{\"hmac_b64\":\"");
  zs_memcpy(bp, hmac_b64, hmac_len);
  bp += hmac_len;
  bp = zs_stpcpy(bp, "\",\"rand_b64\":\"");
  zs_memcpy(bp, rand_b64, rand_b64_len);
  bp += rand_b64_len;
  bp = zs_stpcpy(bp, "\",\"base64_ok\":");
  bp += zs_utoa10(ok, bp, 8);
  bp = zs_stpcpy(bp, "}\n");

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
  zs_respond(200, body, bp - body);
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "10-crypto-helpers.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/crypto`);
                assertEquals(res.status, 200);
                const payload = (await res.json()) as {
                    hmac_b64: string;
                    rand_b64: string;
                    base64_ok: number;
                };

                const key = await crypto.subtle.importKey(
                    "raw",
                    new TextEncoder().encode("supersecret"),
                    { name: "HMAC", hash: "SHA-256" },
                    false,
                    ["sign"],
                );
                const signature = new Uint8Array(
                    await crypto.subtle.sign(
                        "HMAC",
                        key,
                        new TextEncoder().encode("hello"),
                    ),
                );
                const expectedHmac = bytesToBase64(signature);
                assertEquals(payload.hmac_b64, expectedHmac);
                assertEquals(payload.base64_ok, 1);
                assertEquals(payload.rand_b64.length, 44);
                assert(payload.rand_b64.endsWith("="));
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: json helpers",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "json helpers\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

static int check_json(zs_u64 root) {
  zs_s64 name_h = zs_json_get(root, ZS_STR("name"));
  if (name_h == -1) return 0;

  char name[16];
  zs_s64 name_needed = zs_json_read_string(name_h, name, 0);
  if (name_needed != 3) return 0;
  zs_s64 name_len = zs_json_read_string(name_h, name, sizeof(name));
  if (name_len != name_needed) return 0;
  if (zs_memcmp(name, "Ada", 3) != 0) return 0;

  zs_s64 active_h = zs_json_get(root, ZS_STR("active"));
  if (active_h == -1) return 0;
  zs_u8 active = 0;
  zs_s64 active_len = zs_json_read_bool(active_h, &active, sizeof(active));
  if (active_len != 1 || active != 1) return 0;

  zs_s64 count_h = zs_json_get(root, ZS_STR("count"));
  if (count_h == -1) return 0;
  zs_s64 count = 0;
  zs_s64 count_len = zs_json_read_i64(count_h, &count, sizeof(count));
  if (count_len != (zs_s64)sizeof(count) || count != 42) return 0;

  zs_s64 delta_h = zs_json_get(root, ZS_STR("delta"));
  if (delta_h == -1) return 0;
  zs_s64 delta = 0;
  zs_s64 delta_len = zs_json_read_i64(delta_h, &delta, sizeof(delta));
  if (delta_len != (zs_s64)sizeof(delta) || delta != -7) return 0;

  zs_s64 nested_h = zs_json_get(root, ZS_STR("nested"));
  if (nested_h == -1) return 0;
  zs_s64 flag_h = zs_json_get(nested_h, ZS_STR("flag"));
  if (flag_h == -1) return 0;
  zs_u8 flag = 1;
  zs_s64 flag_len = zs_json_read_bool(flag_h, &flag, sizeof(flag));
  if (flag_len != 1 || flag != 0) return 0;

  zs_s64 tag_h = zs_json_get(nested_h, ZS_STR("tag"));
  if (tag_h == -1) return 0;
  char tag[16];
  zs_s64 tag_len = zs_json_read_string(tag_h, tag, sizeof(tag));
  if (tag_len != 5 || zs_memcmp(tag, "hello", 5) != 0) return 0;

  if (zs_json_reset(nested_h) != 0) return 0;
  zs_s64 reset_name_h = zs_json_get(nested_h, ZS_STR("name"));
  if (reset_name_h == -1) return 0;
  char name2[16];
  zs_s64 name2_len = zs_json_read_string(reset_name_h, name2, sizeof(name2));
  if (name2_len != 3 || zs_memcmp(name2, "Ada", 3) != 0) return 0;

  if (zs_json_get(root, ZS_STR("missing")) != -1) return 0;

  int ok = 1;
  zs_object_free(name_h);
  zs_object_free(active_h);
  zs_object_free(count_h);
  zs_object_free(delta_h);
  zs_object_free(flag_h);
  zs_object_free(tag_h);
  zs_object_free(reset_name_h);
  zs_object_free(nested_h);
  zs_object_free(root);
  return ok;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/json") != 0) {
    return 0;
  }

  char payload[256];
  zs_req_header(ZS_STR("x-json"), payload, sizeof(payload));
  zs_u64 payload_len = zs_strlen(payload);
  if (payload_len == 0) {
    zs_respond(400, ZS_STR("missing json\n"));
    return 0;
  }

  zs_s64 root = zs_json_parse(payload, payload_len);
  if (root == -1) {
    zs_respond(400, ZS_STR("parse failed\n"));
    return 0;
  }

  if (!check_json(root)) {
    zs_respond(500, ZS_STR("json helpers failed\n"));
    return 0;
  }

  zs_respond(200, ZS_STR("ok\n"));
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "12-json-helpers.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const payload =
                    '{"name":"Ada","active":true,"count":42,"delta":-7,"nested":{"flag":false,"tag":"hello"}}';

                const okRes = await fetch(`${baseUrl}/json`, {
                    headers: { "x-json": payload },
                });
                assertEquals(okRes.status, 200);
                assertEquals(await okRes.text(), "ok\n");

                const badRes = await fetch(`${baseUrl}/json`, {
                    headers: { "x-json": "{not-json}" },
                });
                assertEquals(badRes.status, 400);
                assertEquals(await badRes.text(), "parse failed\n");
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: load static json helper",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "static json helper\n",
            );

            const dataDir = join(siteDir, "data");
            await Deno.mkdir(dataDir, { recursive: true });
            await Deno.writeTextFile(
                join(dataDir, "config.json"),
                '{"name":"Ada","enabled":true,"count":3}',
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/static-json") != 0) {
    return 0;
  }

  zs_s64 bad = zs_load_static_json(ZS_STR("/data/config.json"));
  if (bad != -1) {
    zs_object_free(bad);
    zs_respond(500, ZS_STR("path normalization\n"));
    return 0;
  }

  zs_s64 root = zs_load_static_json(ZS_STR("data/config.json"));
  if (root == -1) {
    zs_respond(500, ZS_STR("load failed\n"));
    return 0;
  }

  zs_s64 name_h = zs_json_get(root, ZS_STR("name"));
  if (name_h == -1) {
    zs_respond(500, ZS_STR("missing name\n"));
    return 0;
  }
  char name[8];
  zs_s64 name_len = zs_json_read_string(name_h, name, sizeof(name));
  if (name_len != 3 || zs_memcmp(name, "Ada", 3) != 0) {
    zs_respond(500, ZS_STR("bad name\n"));
    return 0;
  }

  zs_s64 enabled_h = zs_json_get(root, ZS_STR("enabled"));
  if (enabled_h == -1) {
    zs_respond(500, ZS_STR("missing enabled\n"));
    return 0;
  }
  zs_u8 enabled = 0;
  zs_s64 enabled_len = zs_json_read_bool(enabled_h, &enabled, sizeof(enabled));
  if (enabled_len != 1 || enabled != 1) {
    zs_respond(500, ZS_STR("bad enabled\n"));
    return 0;
  }

  zs_s64 count_h = zs_json_get(root, ZS_STR("count"));
  if (count_h == -1) {
    zs_respond(500, ZS_STR("missing count\n"));
    return 0;
  }
  zs_s64 count = 0;
  zs_s64 count_len = zs_json_read_i64(count_h, &count, sizeof(count));
  if (count_len != (zs_s64)sizeof(count) || count != 3) {
    zs_respond(500, ZS_STR("bad count\n"));
    return 0;
  }

  zs_object_free(name_h);
  zs_object_free(enabled_h);
  zs_object_free(count_h);
  zs_object_free(root);

  zs_respond(200, ZS_STR("ok\n"));
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "13-load-static-json.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/static-json`);
                assertEquals(res.status, 200);
                assertEquals(await res.text(), "ok\n");
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: jwt helpers",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "jwt helpers\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

static int verify_jwt(const char *token, const char *secret, const char *expected_payload, zs_u64 expected_len, char *out, zs_u64 out_len, zs_u64 *decoded_len) {
  zs_u64 header_len = 0;
  zs_u64 payload_len = 0;
  zs_u64 sig_len = 0;

  while (token[header_len] != '\0' && token[header_len] != '.') header_len++;
  if (token[header_len] != '.') return 0;
  const char *payload = token + header_len + 1;
  while (payload[payload_len] != '\0' && payload[payload_len] != '.') payload_len++;
  if (payload[payload_len] != '.') return 0;
  const char *sig = payload + payload_len + 1;
  while (sig[sig_len] != '\0') sig_len++;
  if (sig_len == 0) return 0;

  zs_u8 digest[32];
  zs_u64 msg_len = header_len + 1 + payload_len;
  zs_hmac_sha256(secret, zs_strlen(secret), token, msg_len, digest);

  char sig_b64[64];
  zs_s64 sig_b64_len = zs_base64_encode(digest, sizeof(digest), sig_b64, sizeof(sig_b64), ZS_BASE64_URL_NO_PAD);
  if (sig_b64_len <= 0 || (zs_u64)sig_b64_len != sig_len) return 0;
  if (zs_memcmp(sig_b64, sig, sig_len) != 0) return 0;

  if (payload_len >= out_len) return 0;
  zs_memcpy(out, payload, payload_len);
  zs_s64 decoded = zs_base64_decode_in_place(out, payload_len, ZS_BASE64_URL_NO_PAD);
  if (decoded <= 0) return 0;
  if ((zs_u64)decoded != expected_len) return 0;
  if (zs_memcmp(out, expected_payload, expected_len) != 0) return 0;
  *decoded_len = (zs_u64)decoded;
  return 1;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/jwt") != 0) {
    return 0;
  }

  char auth[512];
  zs_req_header(ZS_STR("authorization"), auth, sizeof(auth));
  if (zs_strncmp(auth, "Bearer ", 7) != 0) {
    zs_respond(401, ZS_STR("missing bearer token\n"));
    return 0;
  }

  const char *token = auth + 7;
  const char expected_payload[] = "{\"sub\":\"1234567890\",\"name\":\"Ada Lovelace\",\"admin\":true}";
  char payload_buf[256];
  zs_u64 decoded_len = 0;
  int ok = verify_jwt(token, "jwtsecret", expected_payload, sizeof(expected_payload) - 1, payload_buf, sizeof(payload_buf), &decoded_len);
  if (!ok) {
    zs_respond(401, ZS_STR("invalid token\n"));
    return 0;
  }

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
  zs_respond(200, payload_buf, decoded_len);
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "11-jwt-helpers.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const headerJson = '{"alg":"HS256","typ":"JWT"}';
                const payloadJson =
                    '{"sub":"1234567890","name":"Ada Lovelace","admin":true}';
                const headerB64 = bytesToBase64Url(encoder.encode(headerJson));
                const payloadB64 = bytesToBase64Url(
                    encoder.encode(payloadJson),
                );
                const signingInput = `${headerB64}.${payloadB64}`;

                const key = await crypto.subtle.importKey(
                    "raw",
                    encoder.encode("jwtsecret"),
                    { name: "HMAC", hash: "SHA-256" },
                    false,
                    ["sign"],
                );
                const signature = new Uint8Array(
                    await crypto.subtle.sign(
                        "HMAC",
                        key,
                        encoder.encode(signingInput),
                    ),
                );

                {
                    const token = `${signingInput}.${bytesToBase64Url(signature)}`;
                    const res = await fetch(`${baseUrl}/jwt`, {
                        headers: {
                            authorization: `Bearer ${token}`,
                        },
                    });
                    assertEquals(res.status, 200);
                    assertEquals(await res.text(), payloadJson);
                }

                {
                    signature[0] ^= 0xff;
                    const token = `${signingInput}.${bytesToBase64Url(signature)}`;
                    const res = await fetch(`${baseUrl}/jwt`, {
                        headers: {
                            authorization: `Bearer ${token}`,
                        },
                    });
                    assertEquals(res.status, 401);
                    assertEquals(await res.text(), "invalid token\n");
                }
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});
