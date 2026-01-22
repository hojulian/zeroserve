import { fromFileUrl, join } from "@std/path";

const decoder = new TextDecoder();
export const repoRoot = fromFileUrl(new URL("..", import.meta.url));

let zeroservePathPromise: Promise<string> | null = null;

export async function getZeroservePath(): Promise<string> {
  return join(repoRoot, "target", "release", "zeroserve")
}

export async function packSite(siteRoot: string): Promise<string> {
  const zeroservePath = await getZeroservePath();
  const tarPath = await Deno.makeTempFile({ suffix: ".tar" });
  const output = await runCommand(
    zeroservePath,
    ["--pack", siteRoot],
    { cwd: repoRoot },
  );
  await Deno.writeFile(tarPath, output.stdout);
  return tarPath;
}

export async function withZeroserve(
  tarPath: string,
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const zeroservePath = await getZeroservePath();
  const port = await getFreePort();
  const child = new Deno.Command(zeroservePath, {
    args: [
      "--addr",
      `127.0.0.1:${port}`,
      "--disable-request-logging",
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

export async function withZeroserveTls(
  tarPath: string,
  certPath: string,
  keyPath: string,
  fn: (httpUrl: string, httpsUrl: string) => Promise<void>,
): Promise<void> {
  const zeroservePath = await getZeroservePath();
  const httpPort = await getFreePort();
  const httpsPort = await getFreePort();
  const child = new Deno.Command(zeroservePath, {
    args: [
      "--addr",
      `127.0.0.1:${httpPort}`,
      "--tls-addr",
      `127.0.0.1:${httpsPort}`,
      "--cert",
      certPath,
      "--key",
      keyPath,
      "--disable-request-logging",
      tarPath,
    ],
    cwd: repoRoot,
    stdin: "null",
    stdout: "null",
    stderr: "inherit",
  }).spawn();
  const statusPromise = child.status;
  try {
    await waitForServer("127.0.0.1", httpPort, statusPromise);
    await waitForServer("127.0.0.1", httpsPort, statusPromise);
    await fn(`http://127.0.0.1:${httpPort}`, `https://127.0.0.1:${httpsPort}`);
  } finally {
    await stopProcess(child, statusPromise);
  }
}

export async function hasBpfToolchain(): Promise<boolean> {
  return await hasCommand("clang") && await hasCommand("llc");
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

async function getFreePort(): Promise<number> {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  listener.close();
  return port;
}

async function runCommand(
  command: string,
  args: string[],
  options: Deno.CommandOptions = {},
): Promise<Deno.CommandOutput> {
  const output = await new Deno.Command(command, {
    args,
    ...options,
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (output.code !== 0) {
    const stderr = decoder.decode(output.stderr);
    const stdout = decoder.decode(output.stdout);
    throw new Error(
      `command failed: ${command} ${args.join(" ")}\n${stderr}${stdout}`,
    );
  }
  return output;
}

async function hasCommand(command: string): Promise<boolean> {
  try {
    const output = await new Deno.Command(command, {
      args: ["--version"],
      stdout: "null",
      stderr: "null",
    }).output();
    return output.code === 0;
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) {
      return false;
    }
    throw err;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

function immediate(): Promise<null> {
  return new Promise((resolve) => queueMicrotask(() => resolve(null)));
}

export async function generateSelfSignedCert(): Promise<{
  certPath: string;
  keyPath: string;
  cleanup: () => Promise<void>;
}> {
  const certPath = await Deno.makeTempFile({ suffix: ".pem" });
  const keyPath = await Deno.makeTempFile({ suffix: ".pem" });

  const genCmd = new Deno.Command("openssl", {
    args: [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "1",
      "-nodes",
      "-subj",
      "/CN=localhost",
      "-addext",
      "basicConstraints=CA:FALSE",
      "-addext",
      "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ],
    stdout: "null",
    stderr: "null",
  });
  const output = await genCmd.output();
  if (!output.success) {
    throw new Error("Failed to generate self-signed certificate");
  }

  return {
    certPath,
    keyPath,
    cleanup: async () => {
      await Deno.remove(certPath).catch(() => {});
      await Deno.remove(keyPath).catch(() => {});
    },
  };
}
