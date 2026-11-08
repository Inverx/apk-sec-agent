#!/usr/bin/env python3
"""Concurrent benchmark for core API endpoints.

Usage::

    python scripts/benchmark.py --base-url http://127.0.0.1:8000 \
        --users 32 --duration 10

Scenarios:
- health    GET  /health                (no auth, pipeline-free baseline)
- login     POST /api/v1/auth/login     (bcrypt CPU cost)
- tasks     GET  /api/v1/tasks          (JWT + SQLite read path)

Output: per-scenario QPS, P50/P95/P99 latency in milliseconds.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import threading
import time
from pathlib import Path
from typing import Any

import httpx


def percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(int(len(sorted_values) * p), len(sorted_values) - 1)
    return sorted_values[index]


def scenario(
    name: str,
    method: str,
    url: str,
    headers: dict[str, str],
    json_body: dict[str, Any] | None,
    duration: float,
    latencies: list[float],
    errors: list[str],
) -> None:
    """One virtual user: its own event loop + connection pool (avoids the
    single-loop client CPU ceiling that would otherwise bottleneck results)."""

    async def run() -> None:
        limits = httpx.Limits(max_connections=8, max_keepalive_connections=8)
        async with httpx.AsyncClient(
            base_url=BASE_URL[0], limits=limits, timeout=15.0
        ) as client:
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                started = time.perf_counter()
                try:
                    response = await client.request(
                        method, url, headers=headers, json=json_body
                    )
                    elapsed_ms = (time.perf_counter() - started) * 1000
                    if response.status_code < 400:
                        latencies.append(elapsed_ms)
                    else:
                        errors.append(f"{name}:{response.status_code}")
                except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                    errors.append(f"{name}:{type(exc).__name__}")

    asyncio.run(run())


BASE_URL: list[str] = [""]


def run_benchmark(base_url: str, users: int, duration: float) -> tuple[dict[str, Any], str]:
    results: dict[str, Any] = {}
    BASE_URL[0] = base_url

    # setup via one short-lived client
    with httpx.Client(base_url=base_url, timeout=15.0) as setup_client:
        setup_client.get("/health")
        username = f"bench-{int(time.time())}"
        setup_client.post(
            "/api/v1/auth/register",
            json={"username": username, "password": "Bench@12345"},
        )
        token = setup_client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": "Bench@12345"},
        ).json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    scenarios = {
        "health": ("GET", "/health", {}, None),
        "login": ("POST", "/api/v1/auth/login", {},
                  {"username": username, "password": "Bench@12345"}),
        "tasks": ("GET", "/api/v1/tasks", headers, None),
    }

    for name, (method, url, hdrs, body) in scenarios.items():
        latencies: list[float] = []
        errors: list[str] = []
        threads = [
            threading.Thread(
                target=scenario,
                args=(name, method, url, hdrs, body, duration, latencies, errors),
            )
            for _ in range(users)
        ]
        started = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall = time.perf_counter() - started

        latencies.sort()
        total_requests = len(latencies) + len(errors)
        results[name] = {
            "requests": total_requests,
            "errors": len(errors),
            "qps": round(len(latencies) / wall, 1),
            "p50_ms": round(percentile(latencies, 0.50), 2),
            "p95_ms": round(percentile(latencies, 0.95), 2),
            "p99_ms": round(percentile(latencies, 0.99), 2),
            "mean_ms": round(statistics.mean(latencies), 2) if latencies else 0.0,
        }
    return results, username


def cleanup_bench_users(db_path: str) -> int:
    """Remove bench-* accounts created by this run (and earlier runs)."""
    import sqlite3

    if not Path(db_path).exists():
        return 0
    removed = 0
    try:
        with sqlite3.connect(db_path, timeout=5.0) as conn:
            cursor = conn.execute(
                "DELETE FROM users WHERE username LIKE 'bench-%'"
            )
            removed = cursor.rowcount or 0
            conn.commit()
    except sqlite3.Error as exc:
        print(f"cleanup warning: could not prune bench users ({exc})")
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description="APK-SecAgent API benchmark")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--users", type=int, default=32, help="concurrent virtual users")
    parser.add_argument("--duration", type=float, default=10.0, help="seconds per scenario")
    parser.add_argument("--output", default="", help="write JSON results to this file")
    parser.add_argument(
        "--db",
        default=str(Path(__file__).resolve().parents[1] / "data" / "apksec.db"),
        help="SQLite file used to prune bench-* accounts after the run",
    )
    args = parser.parse_args()

    print(f"benchmark: base_url={args.base_url} users={args.users} duration={args.duration}s")
    results, bench_user = run_benchmark(args.base_url, args.users, args.duration)

    print(f"\n{'scenario':<10} {'reqs':>8} {'QPS':>9} {'P50(ms)':>9} {'P95(ms)':>9} "
          f"{'P99(ms)':>9} {'mean':>9} {'errors':>7}")
    print("-" * 74)
    for name, stats in results.items():
        print(
            f"{name:<10} {stats['requests']:>8} {stats['qps']:>9} {stats['p50_ms']:>9} "
            f"{stats['p95_ms']:>9} {stats['p99_ms']:>9} {stats['mean_ms']:>9} {stats['errors']:>7}"
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\nresults written to {args.output}")

    removed = cleanup_bench_users(args.db)
    print(f"cleanup: removed {removed} bench-* account(s) (this run: {bench_user})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
