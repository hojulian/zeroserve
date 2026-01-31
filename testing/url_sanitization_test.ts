import { assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
    hasBpfToolchain,
    packSite,
    withZeroserve,
} from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();
const encoder = new TextEncoder();
const decoder = new TextDecoder();

type RawHttpResponse = {
    status: number;
    headers: Headers;
    body: Uint8Array;
};

// Send a raw HTTP request without URL normalization
async function sendRawRequest(
    hostname: string,
    port: number,
    path: string,
    method = "GET",
): Promise<RawHttpResponse> {
    const conn = await Deno.connect({ hostname, port });
    try {
        const request = `${method} ${path} HTTP/1.1\r\nHost: ${hostname}:${port}\r\nConnection: close\r\n\r\n`;
        await writeAll(conn, encoder.encode(request));

        // Read headers first
        let buffer: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        while (true) {
            const chunk = new Uint8Array(4096);
            const n = await conn.read(chunk);
            if (n === null || n === 0) break;
            buffer = concatBytes(buffer, chunk.subarray(0, n));

            // Check for header end
            const headerEnd = findHeaderEnd(buffer);
            if (headerEnd !== -1) {
                const response = parseHttpResponse(buffer, headerEnd);
                // Read remaining body based on Content-Length
                const contentLength = parseInt(response.headers.get("content-length") || "0", 10);
                const bodyStart = headerEnd + 4;
                const bodyReceived = buffer.length - bodyStart;

                if (bodyReceived < contentLength) {
                    // Need to read more body
                    let body = buffer.subarray(bodyStart);
                    while (body.length < contentLength) {
                        const moreData = new Uint8Array(contentLength - body.length);
                        const m = await conn.read(moreData);
                        if (m === null || m === 0) break;
                        body = concatBytes(body, moreData.subarray(0, m));
                    }
                    response.body = body;
                } else {
                    response.body = buffer.subarray(bodyStart, bodyStart + contentLength);
                }
                return response;
            }
        }
        throw new Error("Connection closed before headers received");
    } finally {
        conn.close();
    }
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
}

function findHeaderEnd(data: Uint8Array): number {
    for (let i = 0; i < data.length - 3; i++) {
        if (data[i] === 13 && data[i + 1] === 10 && data[i + 2] === 13 && data[i + 3] === 10) {
            return i;
        }
    }
    return -1;
}

async function writeAll(conn: Deno.Conn, data: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < data.length) {
        offset += await conn.write(data.subarray(offset));
    }
}

function parseHttpResponse(data: Uint8Array, headerEnd: number): RawHttpResponse {
    const headerSection = decoder.decode(data.subarray(0, headerEnd));

    const lines = headerSection.split("\r\n");
    const statusLine = lines[0];
    const statusMatch = statusLine.match(/HTTP\/\d\.\d (\d+)/);
    if (!statusMatch) {
        throw new Error(`Invalid status line: ${statusLine}`);
    }
    const status = parseInt(statusMatch[1], 10);

    const headers = new Headers();
    for (let i = 1; i < lines.length; i++) {
        const colonIdx = lines[i].indexOf(":");
        if (colonIdx > 0) {
            const name = lines[i].slice(0, colonIdx).trim();
            const value = lines[i].slice(colonIdx + 1).trim();
            headers.append(name, value);
        }
    }

    // Body will be filled in by caller
    return { status, headers, body: new Uint8Array(0) };
}

Deno.test("e2e: path traversal escape returns 400", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(join(siteDir, "index.html"), "hello\n");

        tarPath = await packSite(siteDir);

        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const host = url.hostname;
            const port = parseInt(url.port, 10);

            // Direct path traversal attempts should return 400
            // Using raw requests to bypass client-side URL normalization
            const res1 = await sendRawRequest(host, port, "/../../../etc/passwd");
            assertEquals(res1.status, 400, "path traversal should return 400");

            const res2 = await sendRawRequest(host, port, "/foo/../../../etc/passwd");
            assertEquals(res2.status, 400, "path traversal from subdir should return 400");

            const res3 = await sendRawRequest(host, port, "/..");
            assertEquals(res3.status, 400, "single .. traversal should return 400");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: encoded path traversal escape returns 400", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(join(siteDir, "index.html"), "hello\n");

        tarPath = await packSite(siteDir);

        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const host = url.hostname;
            const port = parseInt(url.port, 10);

            // Percent-encoded path traversal attempts should also return 400
            // %2e = .
            const res1 = await sendRawRequest(host, port, "/%2e%2e/%2e%2e/etc/passwd");
            assertEquals(res1.status, 400, "encoded .. should return 400");

            const res2 = await sendRawRequest(host, port, "/%2e%2e");
            assertEquals(res2.status, 400, "single encoded .. should return 400");

            // Mixed encoding
            const res3 = await sendRawRequest(host, port, "/foo/%2e%2e/%2e%2e/%2e%2e/etc/passwd");
            assertEquals(res3.status, 400, "mixed path traversal should return 400");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: valid paths work correctly", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(join(siteDir, "index.html"), "root\n");
        await Deno.mkdir(join(siteDir, "foo"), { recursive: true });
        await Deno.writeTextFile(join(siteDir, "foo", "bar.txt"), "nested\n");

        tarPath = await packSite(siteDir);

        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const host = url.hostname;
            const port = parseInt(url.port, 10);

            // Root path
            const res1 = await sendRawRequest(host, port, "/");
            assertEquals(res1.status, 200);
            assertEquals(decoder.decode(res1.body), "root\n");

            // Nested path
            const res2 = await sendRawRequest(host, port, "/foo/bar.txt");
            assertEquals(res2.status, 200);
            assertEquals(decoder.decode(res2.body), "nested\n");

            // Relative navigation that stays within root is OK
            const res3 = await sendRawRequest(host, port, "/foo/../foo/bar.txt");
            assertEquals(res3.status, 200);
            assertEquals(decoder.decode(res3.body), "nested\n");

            // . segments are ignored
            const res4 = await sendRawRequest(host, port, "/./foo/./bar.txt");
            assertEquals(res4.status, 200);
            assertEquals(decoder.decode(res4.body), "nested\n");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: encoded paths are decoded for file serving", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        // Create a file with a space in the name
        await Deno.mkdir(join(siteDir, "my docs"), { recursive: true });
        await Deno.writeTextFile(join(siteDir, "my docs", "file.txt"), "spaced\n");

        tarPath = await packSite(siteDir);

        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const host = url.hostname;
            const port = parseInt(url.port, 10);

            // Encoded space (%20) should work
            const res = await sendRawRequest(host, port, "/my%20docs/file.txt");
            assertEquals(res.status, 200);
            assertEquals(decoder.decode(res.body), "spaced\n");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test({
    name: "e2e: scripts receive sanitized paths",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "fallback\n");

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            // Script that echoes the request path back in the response for any path starting with /echo
            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[256];
  zs_s64 path_len = zs_req_path(path, sizeof(path));
  if (path_len < 0) {
    zs_respond(500, ZS_STR("zs_req_path failed"));
    return 0;
  }

  // Only handle /echo prefix
  if (path_len < 5 || path[0] != '/' || path[1] != 'e' || path[2] != 'c' ||
      path[3] != 'h' || path[4] != 'o') {
    return 0;
  }

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("text/plain"));
  zs_respond(200, path, path_len);
  return 0;
}
`;
            await Deno.writeTextFile(join(scriptsDir, "10-echo-path.c"), scriptSource);

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const host = url.hostname;
                const port = parseInt(url.port, 10);

                // Test that encoded path segments are decoded before reaching script
                const res1 = await sendRawRequest(host, port, "/echo/foo%2fbar");
                assertEquals(res1.status, 200);
                // %2f should be decoded to /
                assertEquals(decoder.decode(res1.body), "/echo/foo/bar");

                // Test that . segments are removed
                const res2 = await sendRawRequest(host, port, "/echo/./subdir");
                assertEquals(res2.status, 200);
                assertEquals(decoder.decode(res2.body), "/echo/subdir");

                // Test that .. within bounds is resolved
                const res3 = await sendRawRequest(host, port, "/echo/a/../b");
                assertEquals(res3.status, 200);
                assertEquals(decoder.decode(res3.body), "/echo/b");

                // Test that encoded space is decoded
                const res4 = await sendRawRequest(host, port, "/echo/hello%20world");
                assertEquals(res4.status, 200);
                assertEquals(decoder.decode(res4.body), "/echo/hello world");

                // Test .. that navigates up within allowed space
                const res5 = await sendRawRequest(host, port, "/echo/a/b/../c");
                assertEquals(res5.status, 200);
                assertEquals(decoder.decode(res5.body), "/echo/a/c");
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
    name: "e2e: scripts receive sanitized URIs",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "fallback\n");

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            // Script that echoes the request URI back in the response
            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char uri[256];
  zs_s64 uri_len = zs_req_uri(uri, sizeof(uri));
  if (uri_len < 0) {
    zs_respond(500, ZS_STR("zs_req_uri failed"));
    return 0;
  }

  char path[64];
  zs_req_path(path, sizeof(path));
  // Match /echo-uri exactly
  if (zs_strcmp(path, "/echo-uri") != 0) {
    return 0;
  }

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("text/plain"));
  zs_respond(200, uri, uri_len);
  return 0;
}
`;
            await Deno.writeTextFile(join(scriptsDir, "10-echo-uri.c"), scriptSource);

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const host = url.hostname;
                const port = parseInt(url.port, 10);

                // Test that URI includes sanitized path and original query
                const res1 = await sendRawRequest(host, port, "/a/../echo-uri?foo=bar");
                assertEquals(res1.status, 200);
                // Path is sanitized, query is preserved
                assertEquals(decoder.decode(res1.body), "/echo-uri?foo=bar");

                // Test with encoded characters in query (should be preserved as-is)
                const res2 = await sendRawRequest(host, port, "/echo-uri?name=hello%20world");
                assertEquals(res2.status, 200);
                assertEquals(decoder.decode(res2.body), "/echo-uri?name=hello%20world");

                // Test URI without query
                const res3 = await sendRawRequest(host, port, "/echo-uri");
                assertEquals(res3.status, 200);
                assertEquals(decoder.decode(res3.body), "/echo-uri");
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});
