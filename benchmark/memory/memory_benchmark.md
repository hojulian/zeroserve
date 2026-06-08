# Zeroserve Memory Benchmark Report

This report documents the memory efficiency of running multiple concurrent zeroserve instances under load across two scenarios.

## Test Configuration

| Parameter         | Value                                                         |
| ----------------- | ------------------------------------------------------------- |
| Instances         | 1,000                                                         |
| Site tarball size | 100 MB                                                        |
| Load generator    | wrk -t2 -c10 -d1s per instance                                |
| Load pattern      | All 1,000 instances hit concurrently                          |

### Scripting Runtime

Zeroserve uses the `async-ebpf` crate to execute eBPF bytecode entirely in **userspace**—no kernel eBPF subsystem is involved. Scripts are:

1. **Compiled** with clang/llc to eBPF object files (`-target bpf -march=bpf -mcpu=v3`)
2. **Loaded** into a userspace VM at startup via `async-ebpf`'s `ProgramLoader`
3. **Executed** per-request with async preemption and timeslicing

Each request receives a dedicated `ScriptExecutionContext` with:

- Per-request metadata map shared across script chain
- External object registry (max 32 handles for JSON objects, etc.)
- Memory footprint tracking with configurable limits (default 256 KB)
- Lazy body loading

The runtime enforces timeslicing (yields after 1ms, throttles after 20ms) to prevent scripts from blocking the async executor.

## Methodology

### Memory Measurement

Summing RSS (Resident Set Size) across processes is **incorrect** for measuring total memory consumption because it double-counts shared memory (e.g., the zeroserve binary and shared libraries loaded by each process). Instead, we use:

1. **PSS (Proportional Set Size)**: Divides shared memory proportionally among all processes sharing it. Read from `/proc/[pid]/smaps`.

2. **System-wide consumption**: Difference in `MemAvailable` from `/proc/meminfo` before and after starting instances.

### Test Procedure

1. Record baseline `MemAvailable`
2. Start 1,000 zeroserve instances on consecutive ports (10000-10999)
3. Wait for initialization
4. Measure memory before load
5. Launch 1,000 concurrent wrk processes (one per instance, 1 second each)
6. Sample memory at 50ms intervals during load to capture peak
7. Record final memory measurements

## Scenarios

### `static` — Static file serving with eBPF middleware

Instances serve a 100 MB tarball. An eBPF middleware script handles a `/health` endpoint and injects a custom response header on every request.

### `kv-proxy` — kv map lookup + header strip/re-inject

Instances use `--kv-map-file` to load a routing table. An eBPF middleware script:

1. Reads `x-execution-id` and `x-microvm-id` from the incoming request
2. Looks up the backend URL by `exec-id` via `zs_kv_get`
3. Pre-registers both headers for deferred re-injection on the response (`zs_meta_set("zs.response.header.*", ...)`)
4. Strips both headers from the forwarded request (`zs_req_set_header(..., "", 0)`)
5. Responds (or proxies)

This exercises the full ingress/egress header-manipulation path representative of the `microvm-proxyd` use case.

## Results

### Startup Performance

| Metric                         | `static`             | `kv-proxy`           |
| ------------------------------ | -------------------- | -------------------- |
| Time to start 1,000 instances  | 4.76s                | —                    |
| Instances successfully started | 1,000 / 1,000 (100%) | —                    |
| Load test duration             | 5.83s                | —                    |

### Memory Before Load

| Metric         | `static` total | `static` per-instance | `kv-proxy` total | `kv-proxy` per-instance |
| -------------- | -------------- | --------------------- | ---------------- | ----------------------- |
| PSS (correct)  | 717.08 MB      | 734 KB                | —                | —                       |
| RSS (inflated) | 4,966.69 MB    | 5,086 KB              | —                | —                       |

### Peak Memory During Load

| Metric            | `static`        | `static` per-inst | `kv-proxy` | `kv-proxy` per-inst |
| ----------------- | --------------- | ----------------- | ---------- | ------------------- |
| **PSS (correct)** | **1,160.84 MB** | **1,189 KB**      | —          | —                   |
| RSS (inflated)    | 5,503.65 MB     | 5,636 KB          | —          | —                   |
| System consumed   | 1,581.08 MB     | 1,619 KB          | —          | —                   |

### Shared Memory Efficiency

| Metric        | `static`    | `kv-proxy` |
| ------------- | ----------- | ---------- |
| RSS overcount | 4,342.81 MB | —          |
| Sharing ratio | 4.74x       | —          |

*`—` cells will be filled after `kv-proxy` is run on the benchmark machine.*

### Peak PSS per-instance (KB) — thread-count sweep

| Scenario    | t=1       | t=2 | t=4 | t=8 |
| ----------- | --------- | --- | --- | --- |
| `static`    | 1,189 KB  | —   | —   | —   |
| `kv-proxy`  | —         | —   | —   | —   |

*Run with `--scenario all --threads 1 2 4 8` to populate.*

## Reproducing the Benchmark

### Prerequisites

- Linux system with `/proc` filesystem
- `wrk` load testing tool
- Built zeroserve binary (`cargo build --release`)
- BPF toolchain (`clang`, `llc`) for script compilation

### Setup: `static` scenario

```bash
mkdir -p /tmp/zeroserve-bench/site/.zeroserve/scripts

# 100 MB content
dd if=/dev/urandom of=/tmp/zeroserve-bench/site/large-asset.bin bs=1M count=100

echo '<!DOCTYPE html><html><body><h1>Benchmark</h1></body></html>' \
  > /tmp/zeroserve-bench/site/index.html

cat > /tmp/zeroserve-bench/site/.zeroserve/scripts/10-middleware.c << 'EOF'
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char path[128];
    zs_req_path(path, sizeof(path));

    if (zs_strcmp(path, "/health") == 0) {
        zs_meta_set(ZS_STR("zs.response.header.content-type"),
                    ZS_STR("application/json"));
        zs_respond(200, ZS_STR("{\"status\":\"ok\"}\n"));
    }

    zs_meta_set(ZS_STR("zs.response.header.x-benchmark"), ZS_STR("true"));
    return 0;
}
EOF

./target/release/zeroserve --pack /tmp/zeroserve-bench/site \
  > /tmp/zeroserve-bench/site.tar
```

### Setup: `kv-proxy` scenario

```bash
mkdir -p /tmp/zeroserve-bench/kv-proxy-site/.zeroserve/scripts

# kv map: exec-bench → dummy backend URL
cat > /tmp/zeroserve-bench/kvmap.json << 'EOF'
{"exec-bench": "http://127.0.0.1:9090"}
EOF

cat > /tmp/zeroserve-bench/kv-proxy-site/.zeroserve/scripts/proxy.c << 'EOF'
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char exec_id[256];
    zs_s64 exec_id_len = zs_req_header("x-execution-id", 14,
                                        exec_id, sizeof(exec_id));
    char vm_id[256];
    zs_s64 vm_id_len   = zs_req_header("x-microvm-id", 12,
                                        vm_id, sizeof(vm_id));

    if (exec_id_len <= 0 || vm_id_len <= 0) {
        zs_respond(400, ZS_STR("missing headers\n"));
        return 0;
    }

    char backend_url[512];
    zs_s64 url_len = zs_kv_get(exec_id, (zs_u64)exec_id_len,
                                backend_url, sizeof(backend_url));
    if (url_len <= 0) {
        zs_respond(503, ZS_STR("no backend\n"));
        return 0;
    }

    /* Pre-register headers to re-inject on the response (deferred) */
    zs_meta_set(ZS_STR("zs.response.header.x-execution-id"),
                exec_id, (zs_u64)exec_id_len);
    zs_meta_set(ZS_STR("zs.response.header.x-microvm-id"),
                vm_id, (zs_u64)vm_id_len);

    /* Strip routing headers so the backend never sees them */
    zs_req_set_header("x-execution-id", 14, "", 0);
    zs_req_set_header("x-microvm-id", 12, "", 0);

    zs_respond(200, ZS_STR("ok\n"));
    return 0;
}
EOF

./target/release/zeroserve --pack /tmp/zeroserve-bench/kv-proxy-site \
  > /tmp/zeroserve-bench/kv-proxy.tar
```

### Run

```bash
# Single scenario, default 1 thread
python3 benchmark/memory/benchmark.py --scenario static
python3 benchmark/memory/benchmark.py --scenario kv-proxy

# Sweep thread counts for one scenario
python3 benchmark/memory/benchmark.py --scenario static --threads 1 4 8

# Full matrix: all scenarios × all thread counts
python3 benchmark/memory/benchmark.py --scenario all --threads 1 4 8
```

The `--threads N` flag maps directly to zeroserve's `--threads` flag. Each instance is started with that many worker threads (each running its own io_uring event loop, sharing the site tarball and kv map via `SO_REUSEPORT`). More threads increase per-instance memory but allow each instance to saturate more CPU cores.

## Analysis

### Per-Instance Overhead (`static`)

Under load with a 100 MB site tarball and active userspace eBPF middleware:

- **~1.2 MB per instance** (PSS)
- Memory growth during load: ~455 KB per instance (from 734 KB idle to 1,189 KB under load)

### Memory Efficiency

The low per-instance overhead is achieved through:

1. **Shared binary mappings**: The zeroserve executable and linked libraries are shared across all instances via the OS page cache
2. **Metadata-only indexing**: Only tarball metadata is held in memory (~100 bytes per file: path, byte offset, size, ETag, mtime). The 100 MB tarball's file content is never loaded into memory.
3. **Streaming with positional reads**: File content is served on-demand via `read_at()` at the entry's byte offset, streamed in configurable chunks (default 64 KB) directly to the socket
4. **Thread-local file handle cache**: Each thread maintains its own cloned file descriptor, enabling concurrent reads without contention
5. **Compact script runtime**: The userspace eBPF VM (`async-ebpf`) has minimal overhead; compiled scripts are small and per-request context is bounded

### Scalability Projection (`static`)

| Instances | Estimated PSS | Notes     |
| --------- | ------------- | --------- |
| 1,000     | ~1.2 GB       | Measured  |
| 5,000     | ~6 GB         | Projected |
| 10,000    | ~12 GB        | Projected |

## Conclusion

Zeroserve demonstrates efficient memory utilization when running many concurrent instances:

- **Peak memory: 1.16 GB** for 1,000 instances under concurrent load (`static` scenario)
- **Per-instance overhead: ~1.2 MB** including a 100 MB site tarball and userspace eBPF middleware
- **Shared memory savings: 4.74x** compared to naive RSS summation

The `kv-proxy` scenario adds kv map lookup and per-request header manipulation on top of the base overhead; results pending.

The userspace eBPF scripting model (via `async-ebpf`) provides sandboxed request processing with bounded per-request memory allocation and no kernel dependencies, making zeroserve portable and suitable for high-density deployments.
