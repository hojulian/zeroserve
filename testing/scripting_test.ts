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
const decoder = new TextDecoder();
type ByteArray = Uint8Array<ArrayBufferLike>;

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
    handler: (req: Request) => Response | Promise<Response>,
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

async function startWebsocketBackend(): Promise<{
    httpUrl: string;
    close: () => Promise<void>;
}> {
    const controller = new AbortController();
    let port = 0;
    const sockets = new Set<WebSocket>();
    const server = Deno.serve(
        {
            hostname: "127.0.0.1",
            port: 0,
            signal: controller.signal,
            onListen: ({ port: listenPort }) => {
                port = listenPort;
            },
        },
        (req) => {
            const upgrade = req.headers.get("upgrade") ?? "";
            if (!upgrade.toLowerCase().includes("websocket")) {
                return new Response("upgrade required", { status: 426 });
            }
            const { socket, response } = Deno.upgradeWebSocket(req);
            sockets.add(socket);
            socket.addEventListener("message", (event) => {
                socket.send(`echo:${event.data}`);
            });
            socket.addEventListener("close", () => {
                sockets.delete(socket);
            });
            return response;
        },
    );

    if (port === 0) {
        await new Promise((resolve) => setTimeout(resolve, 0));
    }

    if (port === 0) {
        controller.abort();
        await server.finished;
        throw new Error("failed to start websocket backend");
    }

    return {
        httpUrl: `http://127.0.0.1:${port}`,
        close: async () => {
            const pending = Array.from(sockets, (socket) =>
                new Promise<void>((resolve) => {
                    if (socket.readyState === WebSocket.CLOSED) {
                        resolve();
                        return;
                    }
                    socket.addEventListener("close", () => resolve(), {
                        once: true,
                    });
                    try {
                        socket.close();
                    } catch {
                        resolve();
                    }
                })
            );
            await Promise.all(pending);
            controller.abort();
            await server.finished;
        },
    };
}

async function assertWebsocketEcho(url: string, payload: string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        const ws = new WebSocket(url);
        let done = false;
        let timer: number | null = null;
        const closePromise = new Promise<void>((resolveClose) => {
            ws.onclose = () => resolveClose();
        });
        const finish = (err?: Error) => {
            if (done) {
                return;
            }
            done = true;
            if (timer !== null) {
                clearTimeout(timer);
            }
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        };
        const terminate = (err: Error) => {
            try {
                ws.close();
            } catch {
                // ignore close errors on error path
            }
            closePromise.then(() => finish(err));
        };
        timer = setTimeout(() => {
            terminate(new Error("websocket timeout"));
        }, 2000);

        ws.onopen = () => {
            ws.send(payload);
        };

        ws.onmessage = (event) => {
            if (event.data === `echo:${payload}`) {
                try {
                    ws.close();
                } catch {
                    // ignore close errors on shutdown path
                }
                closePromise.then(() => finish());
            }
        };

        ws.onerror = () => {
            terminate(new Error("websocket error"));
        };
    });
}

type RawHttpResponse = {
    status: number;
    headers: Headers;
    body: ByteArray;
};

async function writeAll(conn: Deno.Conn, data: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < data.length) {
        offset += await conn.write(data.subarray(offset));
    }
}

function concatBuffers(chunks: ByteArray[], total: number): ByteArray {
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

function appendBuffer(buffer: ByteArray, chunk: ByteArray): ByteArray {
    if (buffer.length === 0) {
        return chunk;
    }
    const out = new Uint8Array(buffer.length + chunk.length);
    out.set(buffer);
    out.set(chunk, buffer.length);
    return out;
}

function indexOfSequence(buffer: ByteArray, needle: ByteArray): number {
    if (needle.length === 0 || buffer.length < needle.length) {
        return -1;
    }
    outer:
    for (let i = 0; i <= buffer.length - needle.length; i++) {
        for (let j = 0; j < needle.length; j++) {
            if (buffer[i + j] !== needle[j]) {
                continue outer;
            }
        }
        return i;
    }
    return -1;
}

async function readUntil(
    conn: Deno.Conn,
    delimiter: ByteArray,
): Promise<{ head: ByteArray; rest: ByteArray }> {
    let buffer: ByteArray = new Uint8Array();
    while (true) {
        const index = indexOfSequence(buffer, delimiter);
        if (index >= 0) {
            const head = buffer.subarray(0, index);
            const rest = buffer.subarray(index + delimiter.length);
            return { head, rest };
        }
        const chunk: ByteArray = new Uint8Array(8192);
        const n = await conn.read(chunk);
        if (n === null || n === 0) {
            throw new Error("unexpected eof while reading headers");
        }
        buffer = appendBuffer(buffer, chunk.subarray(0, n));
    }
}

async function readChunkedBody(
    conn: Deno.Conn,
    initial: ByteArray,
): Promise<ByteArray> {
    const crlf = encoder.encode("\r\n");
    let buffer = initial;
    const chunks: ByteArray[] = [];
    let total = 0;

    const readMore = async () => {
        const chunk: ByteArray = new Uint8Array(8192);
        const n = await conn.read(chunk);
        if (n === null || n === 0) {
            throw new Error("unexpected eof while reading chunked body");
        }
        buffer = appendBuffer(buffer, chunk.subarray(0, n));
    };

    while (true) {
        let lineEnd = indexOfSequence(buffer, crlf);
        while (lineEnd === -1) {
            await readMore();
            lineEnd = indexOfSequence(buffer, crlf);
        }
        const line = decoder.decode(buffer.subarray(0, lineEnd));
        buffer = buffer.subarray(lineEnd + crlf.length);
        const sizePart = line.split(";")[0].trim();
        const size = Number.parseInt(sizePart, 16);
        if (!Number.isFinite(size)) {
            throw new Error(`invalid chunk size: ${line}`);
        }
        if (size === 0) {
            while (true) {
                let trailerEnd = indexOfSequence(buffer, crlf);
                while (trailerEnd === -1) {
                    await readMore();
                    trailerEnd = indexOfSequence(buffer, crlf);
                }
                const trailer = decoder.decode(buffer.subarray(0, trailerEnd));
                buffer = buffer.subarray(trailerEnd + crlf.length);
                if (trailer.length === 0) {
                    return concatBuffers(chunks, total);
                }
            }
        }
        while (buffer.length < size + crlf.length) {
            await readMore();
        }
        const chunk = buffer.subarray(0, size);
        const trailer = buffer.subarray(size, size + crlf.length);
        if (
            trailer.length !== crlf.length ||
            indexOfSequence(trailer, crlf) !== 0
        ) {
            throw new Error("missing chunk trailer");
        }
        chunks.push(chunk);
        total += chunk.length;
        buffer = buffer.subarray(size + crlf.length);
    }
}

async function readContentLengthBody(
    conn: Deno.Conn,
    initial: ByteArray,
    length: number,
): Promise<ByteArray> {
    let buffer = initial;
    while (buffer.length < length) {
        const chunk: ByteArray = new Uint8Array(8192);
        const n = await conn.read(chunk);
        if (n === null || n === 0) {
            throw new Error("unexpected eof while reading body");
        }
        buffer = appendBuffer(buffer, chunk.subarray(0, n));
    }
    return buffer.subarray(0, length);
}

async function readToEnd(conn: Deno.Conn, initial: ByteArray): Promise<ByteArray> {
    const chunks: ByteArray[] = [];
    let total = 0;
    if (initial.length > 0) {
        chunks.push(initial);
        total += initial.length;
    }
    while (true) {
        const chunk: ByteArray = new Uint8Array(8192);
        const n = await conn.read(chunk);
        if (n === null || n === 0) {
            break;
        }
        const slice = chunk.subarray(0, n);
        chunks.push(slice);
        total += slice.length;
    }
    return concatBuffers(chunks, total);
}

async function sendRawHttpRequest(
    hostname: string,
    port: number,
    path: string,
    body: string,
    chunked: boolean,
): Promise<RawHttpResponse> {
    const conn = await Deno.connect({ hostname, port });
    try {
        const bodyBytes = encoder.encode(body);
        const headers = [
            `Host: ${hostname}:${port}`,
            "User-Agent: deno-test",
            "Accept: */*",
            "Content-Type: text/plain",
        ];
        if (chunked) {
            headers.push("Transfer-Encoding: chunked");
        } else {
            headers.push(`Content-Length: ${bodyBytes.length}`);
        }
        const headerText = `POST ${path} HTTP/1.1\r\n${headers.join("\r\n")}\r\n\r\n`;
        await writeAll(conn, encoder.encode(headerText));
        if (chunked) {
            const mid = Math.max(1, Math.floor(body.length / 2));
            const parts = [body.slice(0, mid), body.slice(mid)];
            for (const part of parts) {
                if (part.length === 0) {
                    continue;
                }
                const chunk = encoder.encode(part);
                const prefix = `${chunk.length.toString(16)}\r\n`;
                await writeAll(conn, encoder.encode(prefix));
                await writeAll(conn, chunk);
                await writeAll(conn, encoder.encode("\r\n"));
            }
            await writeAll(conn, encoder.encode("0\r\n\r\n"));
        } else if (bodyBytes.length > 0) {
            await writeAll(conn, bodyBytes);
        }

        const delimiter = encoder.encode("\r\n\r\n");
        const { head, rest } = await readUntil(conn, delimiter);
        const headerTextResp = decoder.decode(head);
        const lines = headerTextResp.split("\r\n").filter((line) => line.length > 0);
        if (lines.length === 0) {
            throw new Error("missing response status line");
        }
        const [_, statusCode] = lines[0].split(" ");
        const status = Number.parseInt(statusCode ?? "", 10);
        if (!Number.isFinite(status)) {
            throw new Error(`invalid response status: ${lines[0]}`);
        }
        const headersOut = new Headers();
        for (const line of lines.slice(1)) {
            const idx = line.indexOf(":");
            if (idx === -1) {
                continue;
            }
            const name = line.slice(0, idx).trim();
            const value = line.slice(idx + 1).trim();
            headersOut.append(name, value);
        }

        const transferEncoding = headersOut.get("transfer-encoding");
        const contentLength = headersOut.get("content-length");
        let bodyBytesOut: Uint8Array;
        if (transferEncoding && transferEncoding.toLowerCase().includes("chunked")) {
            bodyBytesOut = await readChunkedBody(conn, rest);
        } else if (contentLength) {
            const length = Number.parseInt(contentLength, 10);
            bodyBytesOut = await readContentLengthBody(conn, rest, length);
        } else {
            bodyBytesOut = await readToEnd(conn, rest);
        }

        return {
            status,
            headers: headersOut,
            body: bodyBytesOut,
        };
    } finally {
        conn.close();
    }
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
    name: "e2e: websocket reverse proxy",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startWebsocketBackend();
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "websocket proxy\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/socket") == 0) {
    zs_reverse_proxy(ZS_STR("${backend.httpUrl}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "15-ws-proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const wsUrl = `${baseUrl.replace("http://", "ws://")}/socket`;
                await assertWebsocketEcho(wsUrl, "ping");
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
    name: "e2e: reverse proxy chunked and fixed bodies",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startBackend(async (req) => {
            const url = new URL(req.url);
            const body = await req.text();
            const payload = JSON.stringify({
                body,
                contentLength: req.headers.get("content-length"),
                transferEncoding: req.headers.get("transfer-encoding"),
            });

            if (url.pathname === "/chunked") {
                const stream = new ReadableStream<Uint8Array>({
                    start(controller) {
                        const bytes = encoder.encode(payload);
                        const mid = Math.max(1, Math.floor(bytes.length / 2));
                        controller.enqueue(bytes.subarray(0, mid));
                        controller.enqueue(bytes.subarray(mid));
                        controller.close();
                    },
                });
                return new Response(stream, {
                    headers: { "content-type": "application/json" },
                });
            }

            return new Response(payload, {
                headers: { "content-type": "application/json" },
            });
        });

        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  zs_reverse_proxy(ZS_STR("${backend.url}"));
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "20-proxy-bodies.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const hostname = url.hostname;
                const port = Number(url.port);

                const fixedFixed = await sendRawHttpRequest(
                    hostname,
                    port,
                    "/fixed",
                    "fixed-body",
                    false,
                );
                assertEquals(fixedFixed.status, 200);
                const fixedFixedPayload = JSON.parse(
                    decoder.decode(fixedFixed.body),
                ) as {
                    body: string;
                    contentLength: string | null;
                    transferEncoding: string | null;
                };
                assertEquals(fixedFixedPayload.body, "fixed-body");
                assertEquals(fixedFixedPayload.transferEncoding, null);
                assertEquals(fixedFixedPayload.contentLength, "10");
                assertEquals(
                    fixedFixed.headers.get("transfer-encoding"),
                    null,
                );
                assert(fixedFixed.headers.get("content-length") !== null);

                const chunkedFixed = await sendRawHttpRequest(
                    hostname,
                    port,
                    "/fixed",
                    "chunked-body",
                    true,
                );
                const chunkedFixedPayload = JSON.parse(
                    decoder.decode(chunkedFixed.body),
                ) as {
                    body: string;
                    contentLength: string | null;
                    transferEncoding: string | null;
                };
                assertEquals(chunkedFixedPayload.body, "chunked-body");
                assertEquals(chunkedFixedPayload.contentLength, null);
                assert(
                    chunkedFixedPayload.transferEncoding?.toLowerCase().includes(
                        "chunked",
                    ),
                );
                assertEquals(
                    chunkedFixed.headers.get("transfer-encoding"),
                    null,
                );
                assert(chunkedFixed.headers.get("content-length") !== null);

                const fixedChunked = await sendRawHttpRequest(
                    hostname,
                    port,
                    "/chunked",
                    "fixed-to-chunked",
                    false,
                );
                const fixedChunkedPayload = JSON.parse(
                    decoder.decode(fixedChunked.body),
                ) as {
                    body: string;
                    contentLength: string | null;
                    transferEncoding: string | null;
                };
                assertEquals(fixedChunkedPayload.body, "fixed-to-chunked");
                assertEquals(fixedChunkedPayload.transferEncoding, null);
                assertEquals(fixedChunkedPayload.contentLength, "16");
                assert(
                    fixedChunked.headers.get("transfer-encoding")?.toLowerCase()
                        .includes("chunked"),
                );
                assertEquals(fixedChunked.headers.get("content-length"), null);

                const chunkedChunked = await sendRawHttpRequest(
                    hostname,
                    port,
                    "/chunked",
                    "chunked-to-chunked",
                    true,
                );
                const chunkedChunkedPayload = JSON.parse(
                    decoder.decode(chunkedChunked.body),
                ) as {
                    body: string;
                    contentLength: string | null;
                    transferEncoding: string | null;
                };
                assertEquals(chunkedChunkedPayload.body, "chunked-to-chunked");
                assertEquals(chunkedChunkedPayload.contentLength, null);
                assert(
                    chunkedChunkedPayload.transferEncoding?.toLowerCase().includes(
                        "chunked",
                    ),
                );
                assert(
                    chunkedChunked.headers.get("transfer-encoding")?.toLowerCase()
                        .includes("chunked"),
                );
                assertEquals(chunkedChunked.headers.get("content-length"), null);
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
            const configJson = '{"name":"Ada","enabled":true,"count":3}';
            const configPath = join(dataDir, "config.json");
            await Deno.writeTextFile(configPath, configJson);
            const expectedMtime = 1_700_000_000;
            const expectedMtimeDate = new Date(expectedMtime * 1000);
            await Deno.utime(configPath, expectedMtimeDate, expectedMtimeDate);
            const expectedSize = encoder.encode(configJson).length;

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

  zs_s64 bad_meta = zs_load_file_metadata(ZS_STR("/data/config.json"));
  if (bad_meta != -1) {
    zs_object_free(bad_meta);
    zs_respond(500, ZS_STR("meta path normalization\n"));
    return 0;
  }

  zs_s64 meta = zs_load_file_metadata(ZS_STR("data/config.json"));
  if (meta == -1) {
    zs_respond(500, ZS_STR("meta load failed\n"));
    return 0;
  }

  zs_s64 size_h = zs_json_get(meta, ZS_STR("size"));
  if (size_h == -1) {
    zs_respond(500, ZS_STR("missing size\n"));
    return 0;
  }
  zs_s64 size = 0;
  zs_s64 size_len = zs_json_read_i64(size_h, &size, sizeof(size));
  if (size_len != (zs_s64)sizeof(size) || size != ${expectedSize}) {
    zs_respond(500, ZS_STR("bad size\n"));
    return 0;
  }

  zs_s64 mtime_h = zs_json_get(meta, ZS_STR("mtime"));
  if (mtime_h == -1) {
    zs_respond(500, ZS_STR("missing mtime\n"));
    return 0;
  }
  zs_s64 mtime = 0;
  zs_s64 mtime_len = zs_json_read_i64(mtime_h, &mtime, sizeof(mtime));
  if (mtime_len != (zs_s64)sizeof(mtime) || mtime != ${expectedMtime}) {
    zs_respond(500, ZS_STR("bad mtime\n"));
    return 0;
  }

  zs_s64 etag_h = zs_json_get(meta, ZS_STR("etag"));
  if (etag_h == -1) {
    zs_respond(500, ZS_STR("missing etag\n"));
    return 0;
  }
  char etag[64];
  zs_s64 etag_len = zs_json_read_string(etag_h, etag, sizeof(etag));
  if (etag_len != 32) {
    zs_respond(500, ZS_STR("bad etag length\n"));
    return 0;
  }
  for (int i = 0; i < 32; i++) {
    char c = etag[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      zs_respond(500, ZS_STR("bad etag chars\n"));
      return 0;
    }
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
  zs_object_free(size_h);
  zs_object_free(mtime_h);
  zs_object_free(etag_h);
  zs_object_free(meta);

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
