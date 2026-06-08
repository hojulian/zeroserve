#!/usr/bin/env python3
"""
Zeroserve benchmark: Start 1000 instances, hit each with wrk, measure peak memory.
Uses PSS (Proportional Set Size) for correct memory accounting with shared memory.

Scenarios
---------
static    Static file serving with eBPF middleware (health endpoint + custom header).
kv-proxy  kv map lookup + request header strip + response header re-injection.
all       Run all scenario × thread-count combinations and print a comparison matrix.

Thread counts
-------------
Pass --threads 1 4 8 (space-separated) to sweep multiple worker thread counts.
Each scenario is run once per thread count; results are printed in a matrix table.
Default: 1 thread.
"""

import argparse
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

ZEROSERVE = "./target/release/zeroserve"
NUM_INSTANCES = 1000
BASE_PORT = 10000
WRK_DURATION = "1s"
WRK_THREADS = 2
WRK_CONNECTIONS = 10

# ── scenario registry ─────────────────────────────────────────────────────────

SCENARIOS = {
    "static": {
        "description": "Static file serving with eBPF middleware (health endpoint + custom header)",
        "tarball": "/tmp/zeroserve-bench/site.tar",
        "extra_args": [],
        "wrk_headers": [],
    },
    "kv-proxy": {
        "description": "kv map lookup + request header strip + response header re-injection",
        "tarball": "/tmp/zeroserve-bench/kv-proxy.tar",
        "extra_args": ["--kv-map-file", "/tmp/zeroserve-bench/kvmap.json"],
        "wrk_headers": [
            "-H", "x-execution-id: exec-bench",
            "-H", "x-microvm-id: vm-42",
        ],
    },
}

# ── memory helpers ────────────────────────────────────────────────────────────

def get_pss_kb(pid):
    """PSS (Proportional Set Size) — correct for shared memory."""
    try:
        total = 0
        with open(f"/proc/{pid}/smaps") as f:
            for line in f:
                if line.startswith("Pss:"):
                    total += int(line.split()[1])
        return total
    except (FileNotFoundError, PermissionError):
        return 0


def get_rss_kb(pid):
    """RSS — overcounts shared memory."""
    try:
        with open(f"/proc/{pid}/statm") as f:
            pages = int(f.read().split()[1])
            return pages * 4
    except (FileNotFoundError, PermissionError):
        return 0


def get_mem_available_kb():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])
    return 0


def get_total_memory(processes):
    total_pss = total_rss = 0
    for proc in processes:
        if proc.poll() is None:
            total_pss += get_pss_kb(proc.pid)
            total_rss += get_rss_kb(proc.pid)
    return total_pss, total_rss


# ── wrk ───────────────────────────────────────────────────────────────────────

def run_wrk(port, extra_headers=()):
    try:
        cmd = [
            "wrk",
            f"-t{WRK_THREADS}",
            f"-c{WRK_CONNECTIONS}",
            f"-d{WRK_DURATION}",
            *extra_headers,
            f"http://127.0.0.1:{port}/",
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return True
    except Exception:
        return False


# ── scenario runner ───────────────────────────────────────────────────────────

def run_scenario(name, threads=1):
    cfg = SCENARIOS[name]
    tarball = cfg["tarball"]
    extra_args = cfg["extra_args"]
    wrk_headers = cfg["wrk_headers"]

    processes = []
    peak = {"pss": 0, "rss": 0, "consumed": 0}
    peak_lock = threading.Lock()
    stop_evt = threading.Event()

    def memory_monitor():
        baseline = get_mem_available_kb()
        while not stop_evt.is_set():
            pss, rss = get_total_memory(processes)
            consumed = baseline - get_mem_available_kb()
            with peak_lock:
                peak["pss"] = max(peak["pss"], pss)
                peak["rss"] = max(peak["rss"], rss)
                peak["consumed"] = max(peak["consumed"], consumed)
            time.sleep(0.05)

    def cleanup():
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(0.5)
        for p in processes:
            try:
                p.kill()
            except Exception:
                pass

    print(f"\n{'=' * 60}")
    print(f"SCENARIO: {name}  |  threads: {threads}")
    print(f"  {cfg['description']}")
    print(f"{'=' * 60}")

    tarball_size = os.path.getsize(tarball) / (1024 * 1024)
    print(f"Tarball: {tarball} ({tarball_size:.1f} MB)")

    baseline_available = get_mem_available_kb()
    print(f"Baseline MemAvailable: {baseline_available} KB")

    print(f"\nStarting {NUM_INSTANCES} instances...")
    t0 = time.time()
    for i in range(NUM_INSTANCES):
        port = BASE_PORT + i
        proc = subprocess.Popen(
            [ZEROSERVE, "--addr", f"127.0.0.1:{port}",
             "--disable-request-logging", "--threads", str(threads),
             *extra_args, tarball],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(proc)
        if (i + 1) % 100 == 0:
            print(f"  {i + 1} started...")
    startup_time = time.time() - t0
    print(f"All started in {startup_time:.2f}s")

    time.sleep(2)
    alive = sum(1 for p in processes if p.poll() is None)
    print(f"Running: {alive} / {NUM_INSTANCES}")
    if alive < NUM_INSTANCES:
        print("WARNING: some instances failed to start")

    pss_before, rss_before = get_total_memory(processes)
    print(f"\nMemory before load:  PSS {pss_before/1024:.2f} MB  |  RSS {rss_before/1024:.2f} MB")

    monitor = threading.Thread(target=memory_monitor, daemon=True)
    monitor.start()

    print(f"\nRunning wrk ({WRK_DURATION}/instance, all concurrent)...")
    t1 = time.time()
    with ThreadPoolExecutor(max_workers=NUM_INSTANCES) as ex:
        futs = [ex.submit(run_wrk, BASE_PORT + i, wrk_headers) for i in range(NUM_INSTANCES)]
        done = 0
        for _ in as_completed(futs):
            done += 1
            if done % 200 == 0:
                print(f"  {done}/{NUM_INSTANCES} done...")
    wrk_time = time.time() - t1
    stop_evt.set()
    print(f"Load test done in {wrk_time:.2f}s")

    cleanup()

    return {
        "name": name,
        "threads": threads,
        "description": cfg["description"],
        "tarball_mb": tarball_size,
        "startup_s": startup_time,
        "alive": alive,
        "wrk_s": wrk_time,
        "pss_before_kb": pss_before,
        "peak_pss_kb": peak["pss"],
        "peak_rss_kb": peak["rss"],
        "peak_consumed_kb": peak["consumed"],
    }


def print_results(r):
    alive = r["alive"]
    print(f"\n{'=' * 50}")
    print(f"RESULTS: {r['name']}  |  threads: {r['threads']}")
    print(f"{'=' * 50}")
    print(f"Instances started: {r['startup_s']:.2f}s  |  running: {alive}/{NUM_INSTANCES}")
    print(f"Load test duration: {r['wrk_s']:.2f}s")
    print()
    print("Peak memory during load (PSS — correct):")
    print(f"  Total:        {r['peak_pss_kb']/1024:.2f} MB")
    print(f"  Per-instance: {r['peak_pss_kb']/alive:.2f} KB")
    print()
    print("Peak memory (RSS — inflated, for comparison):")
    print(f"  Total:        {r['peak_rss_kb']/1024:.2f} MB")
    print(f"  Per-instance: {r['peak_rss_kb']/alive:.2f} KB")
    print()
    print("System-wide memory consumed from baseline:")
    print(f"  Peak:         {r['peak_consumed_kb']/1024:.2f} MB")
    print(f"  Per-instance: {r['peak_consumed_kb']/alive:.2f} KB")
    if r["peak_pss_kb"] > 0:
        ratio = r["peak_rss_kb"] / r["peak_pss_kb"]
        print(f"\nSharing ratio (RSS/PSS): {ratio:.2f}x")


def print_comparison(results):
    """Print a scenario × thread-count matrix for peak PSS per-instance (KB)."""
    import itertools

    scenarios = list(dict.fromkeys(r["name"] for r in results))
    thread_counts = list(dict.fromkeys(r["threads"] for r in results))

    # Index results by (name, threads)
    idx = {(r["name"], r["threads"]): r for r in results}

    col_w = 14
    label_w = 40

    def sep():
        print("-" * (label_w + 1 + col_w * len(thread_counts)))

    METRICS = [
        ("Peak PSS total (MB)",        lambda r: f"{r['peak_pss_kb']/1024:.2f}"),
        ("Peak PSS per-instance (KB)", lambda r: f"{r['peak_pss_kb']/r['alive']:.2f}"),
        ("Peak RSS total (MB)",        lambda r: f"{r['peak_rss_kb']/1024:.2f}"),
        ("System consumed (MB)",       lambda r: f"{r['peak_consumed_kb']/1024:.2f}"),
        ("Startup time (s)",           lambda r: f"{r['startup_s']:.2f}"),
        ("Load test time (s)",         lambda r: f"{r['wrk_s']:.2f}"),
    ]

    def matrix_section(scenario):
        print(f"\n  scenario: {scenario}")
        header = f"  {'Metric':<{label_w - 2}}" + "".join(f"{'t='+str(t):>{col_w}}" for t in thread_counts)
        print(header)
        sep()
        for label, fn in METRICS:
            vals = ""
            for t in thread_counts:
                r = idx.get((scenario, t))
                vals += f"{fn(r) if r else '—':>{col_w}}"
            print(f"  {label:<{label_w - 2}}{vals}")

    print(f"\n{'=' * 60}")
    print("COMPARISON MATRIX")
    print(f"{'=' * 60}")
    for scenario in scenarios:
        matrix_section(scenario)

    # Cross-scenario summary: per-instance PSS at each thread count
    if len(scenarios) > 1:
        print(f"\n  --- peak PSS per-instance (KB) across scenarios ---")
        header = f"  {'Scenario':<{label_w - 2}}" + "".join(f"{'t='+str(t):>{col_w}}" for t in thread_counts)
        print(header)
        sep()
        for scenario in scenarios:
            vals = ""
            for t in thread_counts:
                r = idx.get((scenario, t))
                cell = f"{r['peak_pss_kb']/r['alive']:.2f}" if r else "—"
                vals += f"{cell:>{col_w}}"
            print(f"  {scenario:<{label_w - 2}}{vals}")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=[*SCENARIOS, "all"], default="static",
                        help="Which scenario to run (default: static)")
    parser.add_argument("--threads", type=int, nargs="+", default=[1], metavar="N",
                        help="Worker thread counts to benchmark (default: 1). "
                             "Pass multiple values to sweep, e.g. --threads 1 4 8")
    args = parser.parse_args()

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    thread_counts = sorted(set(args.threads))

    all_results = []
    for threads in thread_counts:
        for name in names:
            r = run_scenario(name, threads=threads)
            print_results(r)
            all_results.append(r)

    if len(all_results) > 1:
        print_comparison(all_results)


if __name__ == "__main__":
    main()
