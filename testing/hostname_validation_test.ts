import { assertEquals } from "@std/assert";
import { join } from "@std/path";
import { packSite, withZeroserve, getZeroservePath } from "./test_utils.ts";
import * as http2 from "node:http2";
import { Buffer } from "node:buffer";

// Simple HTTP/1.1 request using raw TCP since Deno's fetch overrides the Host header
async function http1Request(
    hostname: string,
    port: number,
    path: string,
    hostHeader: string,
): Promise<{ status: number; body: string }> {
    const conn = await Deno.connect({ hostname, port });
    conn.setKeepAlive(false);

    try {
        const request =
            `GET ${path} HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n\r\n`;
        await conn.write(new TextEncoder().encode(request));

        // Read with timeout
        const chunks: Uint8Array[] = [];
        const buf = new Uint8Array(4096);
        const timeout = 5000; // 5 second timeout
        const start = Date.now();

        while (Date.now() - start < timeout) {
            try {
                conn.setNoDelay(true);
                const n = await Promise.race([
                    conn.read(buf),
                    new Promise<null>((_, reject) =>
                        setTimeout(() => reject(new Error("timeout")), 1000)
                    ),
                ]);
                if (n === null) break;
                chunks.push(buf.slice(0, n as number));
            } catch (e) {
                if ((e as Error).message === "timeout") break;
                throw e;
            }
        }

        const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
        const response = new Uint8Array(totalLen);
        let offset = 0;
        for (const chunk of chunks) {
            response.set(chunk, offset);
            offset += chunk.length;
        }

        const text = new TextDecoder().decode(response);
        const headerEnd = text.indexOf("\r\n\r\n");
        if (headerEnd === -1) {
            return { status: 0, body: "" };
        }

        const headerSection = text.slice(0, headerEnd);
        const body = text.slice(headerEnd + 4);

        const statusMatch = headerSection.match(/HTTP\/1\.1 (\d+)/);
        const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;

        return { status, body };
    } finally {
        conn.close();
    }
}

function h2cRequestWithHost(
    hostname: string,
    port: number,
    path: string,
    hostHeader: string,
): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
        // Connect to the actual server IP, but set :authority to the desired host
        const client = http2.connect(`http://${hostname}:${port}`);

        client.on("error", (err) => {
            client.close();
            reject(err);
        });

        const req = client.request({
            ":path": path,
            ":method": "GET",
            ":authority": hostHeader,
        });

        let status = 0;
        const chunks: Buffer[] = [];

        req.on("response", (hdrs) => {
            status = hdrs[":status"] as number;
        });

        req.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
        });

        req.on("end", () => {
            client.close();
            const body = Buffer.concat(chunks).toString("utf-8");
            resolve({ status, body });
        });

        req.on("error", (err) => {
            client.close();
            reject(err);
        });

        req.end();
    });
}

async function withZeroserveHostnames(
    tarPath: string,
    hostnames: string[],
    fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
    const zeroservePath = await getZeroservePath();
    const port = await getFreePort();
    const child = new Deno.Command(zeroservePath, {
        args: [
            "--addr",
            `127.0.0.1:${port}`,
            "--disable-request-logging",
            "--validate-hostnames",
            hostnames.join(","),
            tarPath,
        ],
        cwd: repoRoot,
        stdin: "null",
        stdout: "null",
        stderr: "inherit",
    }).spawn();
    const statusPromise = child.status;
    try {
        await waitForServer("127.0.0.1", port, statusPromise);
        await fn(`http://127.0.0.1:${port}`);
    } finally {
        await stopProcess(child, statusPromise);
    }
}

async function getFreePort(): Promise<number> {
    const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
    const port = (listener.addr as Deno.NetAddr).port;
    listener.close();
    return port;
}

async function waitForServer(
    hostname: string,
    port: number,
    statusPromise: Promise<Deno.CommandStatus>,
    timeoutMs = 10_000,
): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const exited = await checkExited(statusPromise);
        if (exited) {
            throw new Error(
                `zeroserve exited early with code ${exited.code}`,
            );
        }
        try {
            const conn = await Deno.connect({ hostname, port });
            conn.close();
            return;
        } catch {
            await delay(100);
        }
    }
    throw new Error(`timed out waiting for zeroserve at ${hostname}:${port}`);
}

async function stopProcess(
    child: Deno.ChildProcess,
    statusPromise: Promise<Deno.CommandStatus>,
): Promise<void> {
    try {
        child.kill("SIGTERM");
    } catch {
        return;
    }

    const status = await raceWithTimeout(statusPromise, 1000);
    if (status) {
        return;
    }

    try {
        child.kill("SIGKILL");
    } catch {
        return;
    }
    await statusPromise;
}

async function checkExited(
    statusPromise: Promise<Deno.CommandStatus>,
): Promise<Deno.CommandStatus | null> {
    const exited = await Promise.race([
        statusPromise,
        immediate(),
    ]);
    return exited ?? null;
}

function delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function immediate(): Promise<null> {
    return new Promise((resolve) => queueMicrotask(() => resolve(null)));
}

async function raceWithTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
): Promise<T | null> {
    let timer: number | null = null;
    try {
        return await Promise.race([
            promise,
            new Promise<null>((resolve) => {
                timer = setTimeout(() => resolve(null), timeoutMs);
            }),
        ]);
    } finally {
        if (timer !== null) {
            clearTimeout(timer);
        }
    }
}

import { fromFileUrl } from "@std/path";
const repoRoot = fromFileUrl(new URL("..", import.meta.url));

Deno.test("e2e: HTTP/1 hostname validation allows matching hostname", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["example.com", "test.local"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with matching Host header should succeed
            const res = await http1Request(hostname, port, "/", "example.com");
            assertEquals(res.status, 200);
            assertEquals(res.body, "<h1>hello</h1>\n");

            // Request with another matching Host header should succeed
            const res2 = await http1Request(hostname, port, "/", "test.local");
            assertEquals(res2.status, 200);
            assertEquals(res2.body, "<h1>hello</h1>\n");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation rejects non-matching hostname with 421", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["example.com"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with non-matching Host header should return 421
            const res = await http1Request(hostname, port, "/", "evil.com");
            assertEquals(res.status, 421);
            assertEquals(res.body, "Misdirected Request");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation is case-insensitive", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["Example.COM"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with different case should match
            const res = await http1Request(hostname, port, "/", "example.com");
            assertEquals(res.status, 200);

            const res2 = await http1Request(hostname, port, "/", "EXAMPLE.COM");
            assertEquals(res2.status, 200);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation strips port", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["example.com"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with port should match hostname without port
            const res = await http1Request(hostname, port, "/", "example.com:8080");
            assertEquals(res.status, 200);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: h2c hostname validation rejects non-matching hostname with 421", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>h2c hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["example.com"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // h2c request with non-matching :authority should return 421
            const res = await h2cRequestWithHost(hostname, port, "/", "evil.com");
            assertEquals(res.status, 421);
            assertEquals(res.body, "Misdirected Request");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation handles IPv6 with port", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["::1"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // IPv6 with port [::1]:port should match ::1
            const res = await http1Request(hostname, port, "/", "[::1]:8080");
            assertEquals(res.status, 200);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation handles IPv6 without port", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["::1"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // IPv6 without port [::1] should match ::1
            const res = await http1Request(hostname, port, "/", "[::1]");
            assertEquals(res.status, 200);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: HTTP/1 hostname validation rejects non-matching IPv6", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        await withZeroserveHostnames(tarPath, ["::1"], async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Different IPv6 should be rejected
            const res = await http1Request(hostname, port, "/", "[2001:db8::1]");
            assertEquals(res.status, 421);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

// Note: h2c acceptance tests (matching hostname, case-insensitivity, port stripping)
// are covered by HTTP/1 tests. The h2c rejection test above verifies that HTTP/2
// hostname validation is active. Node's http2 client has stricter :authority
// validation that makes acceptance tests difficult without proper DNS/TLS setup.

Deno.test("e2e: server without hostname validation accepts any host", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<h1>hello</h1>\n",
        );

        tarPath = await packSite(siteDir);

        // Use regular withZeroserve which doesn't specify --validate-hostnames
        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            // Request with any Host header should succeed
            const res = await http1Request(hostname, port, "/", "any-host.com");
            assertEquals(res.status, 200);
            assertEquals(res.body, "<h1>hello</h1>\n");

            const res2 = await http1Request(hostname, port, "/", "another-host.org");
            assertEquals(res2.status, 200);
            assertEquals(res2.body, "<h1>hello</h1>\n");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});
