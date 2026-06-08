# Zeroserve Memory Benchmark Report

This report documents the memory efficiency of running multiple concurrent zeroserve instances under load across two scenarios and three thread counts.

## Test Configuration

| Parameter         | Value                                                         |
| ----------------- | ------------------------------------------------------------- |
| Instances         | 1,000                                                         |
| Site tarball size | 100 MB (static) / 3.5 KB (kv-proxy)                          |
| Thread counts     | 1, 2, 4 workers per instance                                  |
| Load generator    | wrk -t2 -c10 -d1s per instance                                |
| Load pattern      | All 1,000 instances hit concurrently                          |
| Platform          | Linux (Docker, aarch64)                                       |

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
5. Responds

This exercises the full ingress/egress header-manipulation path representative of the `microvm-proxyd` use case.

## Results

### Startup Performance

| Scenario   | Threads | Startup time | Running instances |
| ---------- | ------- | ------------ | ----------------- |
| `static`   | 1       | 3.41s        | 1,000 / 1,000     |
| `static`   | 2       | 3.73s        | 1,000 / 1,000     |
| `static`   | 4       | 3.50s        | 1,000 / 1,000     |
| `kv-proxy` | 1       | 0.64s        | 1,000 / 1,000     |
| `kv-proxy` | 2       | 0.64s        | 1,000 / 1,000     |
| `kv-proxy` | 4       | 0.67s        | 1,000 / 1,000     |

`kv-proxy` starts ~5× faster than `static` because the tarball is 3.5 KB vs 100 MB.

### Peak Memory During Load

#### `static` scenario

| Threads | PSS total    | PSS per-instance | RSS total     | RSS per-instance | Sharing ratio |
| ------- | ------------ | ---------------- | ------------- | ---------------- | ------------- |
| 1       | 2,765.85 MB  | 2,832 KB         | 9,728.64 MB   | 9,962 KB         | 3.52×         |
| 2       | 2,028.52 MB  | 2,077 KB         | 6,629.38 MB   | 6,788 KB         | 3.27×         |
| 4       | 1,602.33 MB  | 1,641 KB         | 4,619.44 MB   | 4,730 KB         | 2.88×         |

#### `kv-proxy` scenario

| Threads | PSS total    | PSS per-instance | RSS total    | RSS per-instance | Sharing ratio |
| ------- | ------------ | ---------------- | ------------ | ---------------- | ------------- |
| 1       | 2,121.19 MB  | 2,172 KB         | 7,314.69 MB  | 7,490 KB         | 3.45×         |
| 2       | 1,865.66 MB  | 1,910 KB         | 5,908.15 MB  | 6,050 KB         | 3.17×         |
| 4       | 1,534.03 MB  | 1,571 KB         | 4,282.12 MB  | 4,385 KB         | 2.79×         |

### Thread-count comparison matrix — peak PSS per-instance (KB)

| Scenario   |   t=1    |   t=2    |   t=4    |
| ---------- | -------- | -------- | -------- |
| `static`   | 2,832 KB | 2,077 KB | 1,641 KB |
| `kv-proxy` | 2,172 KB | 1,910 KB | 1,571 KB |

PSS per-instance decreases as thread count increases because each additional worker thread in a process shares the process's binary and library mappings with the other 999 instances, amortizing those pages more broadly. The tarball file content (100 MB for `static`) is served via positional reads and is never copied into private memory, so it too is shared.

The `kv-proxy` scenario consistently uses less PSS than `static` at every thread count. The difference is entirely attributable to the tarball size: `static` indexes a 100 MB tarball (file metadata, ETags) while `kv-proxy`'s tarball is 3.5 KB.

## Analysis

### Sharing ratio

The sharing ratio (RSS/PSS) falls as thread count rises: from 3.52× at t=1 to 2.88× at t=4 for `static`. Each additional thread per process introduces private memory (io_uring rings, thread stacks) that is not shared across processes, shrinking the shared-to-private ratio even as total PSS falls.

### Load test duration

| Scenario   | t=1    | t=2    | t=4    |
| ---------- | ------ | ------ | ------ |
| `static`   | 4.09s  | 5.58s  | 6.30s  |
| `kv-proxy` | 4.08s  | 5.31s  | 5.74s  |

Load test duration increases with thread count. On the benchmark machine (containerised Linux, limited CPU), running 1,000 instances × 4 threads = 4,000 event-loop threads concurrently with 1,000 wrk processes saturates the available cores and raises scheduler latency. In a deployment with dedicated CPU cores per instance this effect would not appear.

### Memory overhead of kv-proxy vs static

At t=1, `kv-proxy` uses **660 KB less PSS per instance** than `static` (2,172 KB vs 2,832 KB). The kv map itself (one JSON key-value entry) adds negligible overhead. The kv lookup, header stripping, and deferred header injection add no measurable per-instance memory cost on top of the base script runtime.

## Reproducing the Benchmark

### Prerequisites

- Linux system with `/proc` filesystem
- `wrk` load testing tool
- Built zeroserve binary (`cargo build --release`)
- BPF toolchain (`clang`, `llc`) for script compilation
- Python 3.x

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
python3 benchmark/memory/benchmark.py --scenario all --threads 1 2 4
```

The `--threads N` flag maps directly to zeroserve's `--threads` flag. Each instance is started with that many worker threads (each running its own io_uring event loop, sharing the site tarball and kv map via `SO_REUSEPORT`). More threads increase per-instance private memory (io_uring rings, thread stacks) but allow each instance to saturate more CPU cores.

## Scalability Projection

Based on measured per-instance PSS at t=1:

| Instances | `static` (t=1) | `kv-proxy` (t=1) |
| --------- | -------------- | ---------------- |
| 1,000     | ~2.77 GB       | ~2.12 GB         |
| 5,000     | ~13.8 GB       | ~10.6 GB         |
| 10,000    | ~27.7 GB       | ~21.2 GB         |

## Conclusion

- **`static` (t=1):** 2,832 KB PSS per instance under load with a 100 MB tarball and eBPF middleware
- **`kv-proxy` (t=1):** 2,172 KB PSS per instance — 660 KB less than `static`, attributable entirely to the smaller tarball; the kv map and header operations add no measurable overhead
- **Threading:** Increasing worker threads per instance reduces PSS per instance (more shared mappings amortised across a smaller process count) — from 2,832 KB at t=1 to 1,641 KB at t=4 for `static`, and 2,172 KB to 1,571 KB for `kv-proxy`
- **Sharing ratio:** 2.79–3.52× depending on scenario and thread count; RSS dramatically overstates true consumption
- **Startup:** `kv-proxy` starts 5× faster than `static` (0.64s vs 3.41s) due to the smaller tarball
