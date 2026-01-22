import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
    generateSelfSignedCert,
    hasBpfToolchain,
    packSite,
    withZeroserve,
    withZeroserveTls,
} from "./test_utils.ts";
import * as http2 from "node:http2";
import { Buffer } from "node:buffer";

const canRunScripts = await hasBpfToolchain();
const encoder = new TextEncoder();

interface SSEEvent {
    event?: string;
    data: string;
    id?: string;
}

function parseSSEEvents(text: string): SSEEvent[] {
    const events: SSEEvent[] = [];
    const blocks = text.split("\n\n").filter((b) => b.trim().length > 0);

    for (const block of blocks) {
        const lines = block.split("\n");
        const event: SSEEvent = { data: "" };
        const dataLines: string[] = [];

        for (const line of lines) {
            if (line.startsWith("event:")) {
                event.event = line.slice(6).trim();
            } else if (line.startsWith("data:")) {
                dataLines.push(line.slice(5).trim());
            } else if (line.startsWith("id:")) {
                event.id = line.slice(3).trim();
            }
        }

        event.data = dataLines.join("\n");
        if (event.data || event.event) {
            events.push(event);
        }
    }

    return events;
}

async function startSSEBackend(
    events: SSEEvent[],
    delayMs = 50,
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
        async (req) => {
            const url = new URL(req.url);

            if (url.pathname !== "/events") {
                return new Response("not found", { status: 404 });
            }

            const stream = new ReadableStream<Uint8Array>({
                async start(streamController) {
                    for (let i = 0; i < events.length; i++) {
                        const event = events[i];
                        let chunk = "";
                        if (event.event) {
                            chunk += `event: ${event.event}\n`;
                        }
                        if (event.id) {
                            chunk += `id: ${event.id}\n`;
                        }
                        chunk += `data: ${event.data}\n\n`;

                        streamController.enqueue(encoder.encode(chunk));

                        if (i < events.length - 1 && delayMs > 0) {
                            await new Promise((r) => setTimeout(r, delayMs));
                        }
                    }
                    streamController.close();
                },
            });

            return new Response(stream, {
                headers: {
                    "content-type": "text/event-stream",
                    "cache-control": "no-cache",
                    "connection": "keep-alive",
                },
            });
        },
    );

    if (port === 0) {
        await new Promise((resolve) => setTimeout(resolve, 0));
    }

    if (port === 0) {
        controller.abort();
        await server.finished;
        throw new Error("failed to start SSE backend server");
    }

    return {
        url: `http://127.0.0.1:${port}`,
        close: async () => {
            controller.abort();
            await server.finished;
        },
    };
}

interface TimedSSEEvent extends SSEEvent {
    receivedAt: number;
}

async function readSSEStreamWithTiming(
    res: Response,
): Promise<TimedSSEEvent[]> {
    const events: TimedSSEEvent[] = [];
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
        const { done, value } = await reader.read();
        const receivedAt = performance.now();

        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // Parse complete events from buffer
        const parts = buffer.split("\n\n");
        buffer = parts.pop() || "";

        for (const block of parts) {
            if (block.trim().length === 0) continue;

            const lines = block.split("\n");
            const event: TimedSSEEvent = { data: "", receivedAt };
            const dataLines: string[] = [];

            for (const line of lines) {
                if (line.startsWith("event:")) {
                    event.event = line.slice(6).trim();
                } else if (line.startsWith("data:")) {
                    dataLines.push(line.slice(5).trim());
                } else if (line.startsWith("id:")) {
                    event.id = line.slice(3).trim();
                }
            }

            event.data = dataLines.join("\n");
            if (event.data || event.event) {
                events.push(event);
            }
        }
    }

    return events;
}

function h2cSSERequestWithTiming(
    hostname: string,
    port: number,
    path: string,
    timeoutMs = 10000,
): Promise<{ status: number; events: TimedSSEEvent[] }> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);
        let timer: ReturnType<typeof setTimeout> | null = null;

        const cleanup = () => {
            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
        };

        client.on("error", (err) => {
            cleanup();
            client.close();
            reject(err);
        });

        const req = client.request({ ":path": path, ":method": "GET" });

        let status = 0;
        const events: TimedSSEEvent[] = [];
        let buffer = "";

        timer = setTimeout(() => {
            cleanup();
            client.close();
            reject(new Error("h2c SSE request timed out"));
        }, timeoutMs);

        req.on("response", (hdrs) => {
            status = hdrs[":status"] as number;
        });

        req.on("data", (chunk: Buffer) => {
            const receivedAt = performance.now();
            buffer += chunk.toString("utf-8");

            // Parse complete events from buffer
            const parts = buffer.split("\n\n");
            buffer = parts.pop() || "";

            for (const block of parts) {
                if (block.trim().length === 0) continue;

                const lines = block.split("\n");
                const event: TimedSSEEvent = { data: "", receivedAt };
                const dataLines: string[] = [];

                for (const line of lines) {
                    if (line.startsWith("event:")) {
                        event.event = line.slice(6).trim();
                    } else if (line.startsWith("data:")) {
                        dataLines.push(line.slice(5).trim());
                    } else if (line.startsWith("id:")) {
                        event.id = line.slice(3).trim();
                    }
                }

                event.data = dataLines.join("\n");
                if (event.data || event.event) {
                    events.push(event);
                }
            }
        });

        req.on("end", () => {
            cleanup();
            client.close();
            resolve({ status, events });
        });

        req.on("error", (err) => {
            cleanup();
            client.close();
            reject(err);
        });

        req.end();
    });
}

function h2cSSERequest(
    hostname: string,
    port: number,
    path: string,
    timeoutMs = 5000,
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);
        let timer: ReturnType<typeof setTimeout> | null = null;

        const cleanup = () => {
            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
        };

        client.on("error", (err) => {
            cleanup();
            client.close();
            reject(err);
        });

        const req = client.request({ ":path": path, ":method": "GET" });

        let status = 0;
        const headers: Record<string, string> = {};
        const chunks: Buffer[] = [];

        timer = setTimeout(() => {
            cleanup();
            client.close();
            reject(new Error("h2c SSE request timed out"));
        }, timeoutMs);

        req.on("response", (hdrs) => {
            status = hdrs[":status"] as number;
            for (const [key, value] of Object.entries(hdrs)) {
                if (!key.startsWith(":")) {
                    headers[key] = Array.isArray(value)
                        ? value[0]
                        : (value as string);
                }
            }
        });

        req.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
        });

        req.on("end", () => {
            cleanup();
            client.close();
            const body = Buffer.concat(chunks).toString("utf-8");
            resolve({ status, headers, body });
        });

        req.on("error", (err) => {
            cleanup();
            client.close();
            reject(err);
        });

        req.end();
    });
}

async function h2SSERequest(
    hostname: string,
    port: number,
    path: string,
    certPath: string,
): Promise<{
    status: number;
    headers: Record<string, string>;
    body: string;
}> {
    const caCert = await Deno.readTextFile(certPath);
    const client = Deno.createHttpClient({
        caCerts: [caCert],
        http2: true,
    });

    try {
        const res = await fetch(`https://${hostname}:${port}${path}`, {
            client,
        });
        const body = await res.text();
        const headers: Record<string, string> = {};
        for (const [key, value] of res.headers.entries()) {
            headers[key] = value;
        }
        return { status: res.status, headers, body };
    } finally {
        client.close();
    }
}

Deno.test({
    name: "e2e: SSE reverse proxy over h1",
    ignore: !canRunScripts,
    fn: async () => {
        const testEvents: SSEEvent[] = [
            { event: "message", data: "hello", id: "1" },
            { event: "update", data: "world", id: "2" },
            { data: "no event type", id: "3" },
            { event: "done", data: "finished", id: "4" },
        ];

        const backend = await startSSEBackend(testEvents, 10);
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;

        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "SSE proxy test\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/sse") == 0) {
    zs_req_set_uri(ZS_STR("/events"));
    zs_reverse_proxy(ZS_STR("${backend.url}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-sse-proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                // Test SSE over h1 (HTTP/1.1)
                const res = await fetch(`${baseUrl}/sse`);
                assertEquals(res.status, 200);

                const contentType = res.headers.get("content-type");
                assert(
                    contentType?.includes("text/event-stream"),
                    `Expected text/event-stream, got ${contentType}`,
                );

                const body = await res.text();
                const events = parseSSEEvents(body);

                assertEquals(events.length, 4, "Should receive 4 SSE events");
                assertEquals(events[0].event, "message");
                assertEquals(events[0].data, "hello");
                assertEquals(events[0].id, "1");
                assertEquals(events[1].event, "update");
                assertEquals(events[1].data, "world");
                assertEquals(events[2].data, "no event type");
                assertEquals(events[3].event, "done");
                assertEquals(events[3].data, "finished");
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
    name: "e2e: SSE reverse proxy over h2c",
    ignore: !canRunScripts,
    fn: async () => {
        const testEvents: SSEEvent[] = [
            { event: "start", data: "beginning", id: "a" },
            { event: "progress", data: "50%", id: "b" },
            { event: "progress", data: "100%", id: "c" },
            { event: "complete", data: "all done", id: "d" },
        ];

        const backend = await startSSEBackend(testEvents, 10);
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;

        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "SSE proxy test h2c\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/sse") == 0) {
    zs_req_set_uri(ZS_STR("/events"));
    zs_reverse_proxy(ZS_STR("${backend.url}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-sse-proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const hostname = url.hostname;
                const port = Number(url.port);

                // Test SSE over h2c (HTTP/2 cleartext)
                const res = await h2cSSERequest(hostname, port, "/sse");

                assertEquals(res.status, 200);
                assert(
                    res.headers["content-type"]?.includes("text/event-stream"),
                    `Expected text/event-stream, got ${res.headers["content-type"]}`,
                );

                const events = parseSSEEvents(res.body);

                assertEquals(events.length, 4, "Should receive 4 SSE events over h2c");
                assertEquals(events[0].event, "start");
                assertEquals(events[0].data, "beginning");
                assertEquals(events[1].event, "progress");
                assertEquals(events[1].data, "50%");
                assertEquals(events[2].event, "progress");
                assertEquals(events[2].data, "100%");
                assertEquals(events[3].event, "complete");
                assertEquals(events[3].data, "all done");
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
    name: "e2e: SSE reverse proxy over h2 (TLS)",
    ignore: !canRunScripts,
    fn: async () => {
        const testEvents: SSEEvent[] = [
            { event: "init", data: "secure connection", id: "x1" },
            { event: "data", data: '{"count": 42}', id: "x2" },
            { event: "data", data: '{"count": 43}', id: "x3" },
            { event: "end", data: "goodbye", id: "x4" },
        ];

        const backend = await startSSEBackend(testEvents, 10);
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();

        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "SSE proxy test h2\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/sse") == 0) {
    zs_req_set_uri(ZS_STR("/events"));
    zs_reverse_proxy(ZS_STR("${backend.url}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-sse-proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserveTls(
                tarPath,
                cert.certPath,
                cert.keyPath,
                async (_httpUrl, httpsUrl) => {
                    const url = new URL(httpsUrl);
                    const hostname = url.hostname;
                    const port = Number(url.port);

                    // Test SSE over h2 (HTTP/2 over TLS)
                    const res = await h2SSERequest(
                        hostname,
                        port,
                        "/sse",
                        cert.certPath,
                    );

                    assertEquals(res.status, 200);
                    assert(
                        res.headers["content-type"]?.includes(
                            "text/event-stream",
                        ),
                        `Expected text/event-stream, got ${res.headers["content-type"]}`,
                    );

                    const events = parseSSEEvents(res.body);

                    assertEquals(
                        events.length,
                        4,
                        "Should receive 4 SSE events over h2",
                    );
                    assertEquals(events[0].event, "init");
                    assertEquals(events[0].data, "secure connection");
                    assertEquals(events[1].event, "data");
                    assertEquals(events[1].data, '{"count": 42}');
                    assertEquals(events[2].event, "data");
                    assertEquals(events[2].data, '{"count": 43}');
                    assertEquals(events[3].event, "end");
                    assertEquals(events[3].data, "goodbye");
                },
            );
        } finally {
            await backend.close().catch(() => {});
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            await cert.cleanup();
        }
    },
});

Deno.test({
    name: "e2e: SSE reverse proxy streaming behavior",
    ignore: !canRunScripts,
    fn: async () => {
        // Test with more events to verify streaming works correctly
        const testEvents: SSEEvent[] = [];
        for (let i = 0; i < 10; i++) {
            testEvents.push({
                event: "tick",
                data: `event-${i}`,
                id: String(i),
            });
        }

        const backend = await startSSEBackend(testEvents, 5);
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();

        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "SSE streaming test\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/stream") == 0) {
    zs_req_set_uri(ZS_STR("/events"));
    zs_reverse_proxy(ZS_STR("${backend.url}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-sse-stream.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserveTls(
                tarPath,
                cert.certPath,
                cert.keyPath,
                async (httpUrl, httpsUrl) => {
                    // Test all three protocols with streaming
                    const httpUrlObj = new URL(httpUrl);
                    const httpsUrlObj = new URL(httpsUrl);

                    // h1 streaming
                    const h1Res = await fetch(`${httpUrl}/stream`);
                    assertEquals(h1Res.status, 200);
                    const h1Events = parseSSEEvents(await h1Res.text());
                    assertEquals(
                        h1Events.length,
                        10,
                        "h1: Should receive all 10 events",
                    );

                    // h2c streaming
                    const h2cRes = await h2cSSERequest(
                        httpUrlObj.hostname,
                        Number(httpUrlObj.port),
                        "/stream",
                    );
                    assertEquals(h2cRes.status, 200);
                    const h2cEvents = parseSSEEvents(h2cRes.body);
                    assertEquals(
                        h2cEvents.length,
                        10,
                        "h2c: Should receive all 10 events",
                    );

                    // h2 streaming
                    const h2Res = await h2SSERequest(
                        httpsUrlObj.hostname,
                        Number(httpsUrlObj.port),
                        "/stream",
                        cert.certPath,
                    );
                    assertEquals(h2Res.status, 200);
                    const h2Events = parseSSEEvents(h2Res.body);
                    assertEquals(
                        h2Events.length,
                        10,
                        "h2: Should receive all 10 events",
                    );

                    // Verify event order and content
                    for (let i = 0; i < 10; i++) {
                        assertEquals(h1Events[i].event, "tick");
                        assertEquals(h1Events[i].data, `event-${i}`);
                        assertEquals(h1Events[i].id, String(i));

                        assertEquals(h2cEvents[i].event, "tick");
                        assertEquals(h2cEvents[i].data, `event-${i}`);
                        assertEquals(h2cEvents[i].id, String(i));

                        assertEquals(h2Events[i].event, "tick");
                        assertEquals(h2Events[i].data, `event-${i}`);
                        assertEquals(h2Events[i].id, String(i));
                    }
                },
            );
        } finally {
            await backend.close().catch(() => {});
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            await cert.cleanup();
        }
    },
});

Deno.test({
    name: "e2e: SSE events delivered incrementally (not buffered)",
    ignore: !canRunScripts,
    fn: async () => {
        const eventDelayMs = 150;
        const numEvents = 5;
        const testEvents: SSEEvent[] = [];
        for (let i = 0; i < numEvents; i++) {
            testEvents.push({ event: "tick", data: `event-${i}`, id: String(i) });
        }

        const backend = await startSSEBackend(testEvents, eventDelayMs);
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;

        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "SSE timing test\n");

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/timed") == 0) {
    zs_req_set_uri(ZS_STR("/events"));
    zs_reverse_proxy(ZS_STR("${backend.url}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(join(scriptsDir, "10-sse-timed.c"), scriptSource);

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);

                // Test h1 streaming timing
                const h1Res = await fetch(`${baseUrl}/timed`);
                assertEquals(h1Res.status, 200);
                const h1Events = await readSSEStreamWithTiming(h1Res);
                assertEquals(h1Events.length, numEvents, "h1: Should receive all events");

                // Test h2c streaming timing
                const h2cResult = await h2cSSERequestWithTiming(url.hostname, Number(url.port), "/timed");
                assertEquals(h2cResult.status, 200);
                assertEquals(h2cResult.events.length, numEvents, "h2c: Should receive all events");

                // Verify events arrived incrementally by checking time spread.
                // If buffered, all events would arrive at once with ~0ms spread.
                const h1Spread = h1Events[numEvents - 1].receivedAt - h1Events[0].receivedAt;
                const h2cSpread = h2cResult.events[numEvents - 1].receivedAt - h2cResult.events[0].receivedAt;
                const minSpread = (numEvents - 1) * eventDelayMs * 0.5;

                assert(h1Spread >= minSpread, `h1: Events should arrive incrementally. Spread: ${h1Spread}ms, expected >= ${minSpread}ms`);
                assert(h2cSpread >= minSpread, `h2c: Events should arrive incrementally. Spread: ${h2cSpread}ms, expected >= ${minSpread}ms`);
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
