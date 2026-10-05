#!/usr/bin/env python3
"""Confirm X25519 TLS 1.3 handshakes for hosts that passed the first-stage scan."""

import argparse
import asyncio
import datetime
import json
from pathlib import Path
import time


async def run(args):
    candidates = {}
    for line in args.input.read_text().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if (row.get("eligible") and row.get("tls") == "TLSv1.3"
                and row.get("alpn") == "h2" and row.get("certificate_valid")
                and row.get("http_status") == 200):
            candidates[row["host"]] = row
        else:
            candidates.pop(row["host"], None)
    previous = {}
    if args.resume and args.output.exists():
        for line in args.output.read_text().splitlines():
            row = json.loads(line)
            previous[row["host"]] = row["ip"]
    queue = asyncio.Queue()
    for host, row in candidates.items():
        if previous.get(host) != row["ip"]:
            queue.put_nowait(row)
    total = queue.qsize()
    completed = 0
    passed = 0
    started = time.monotonic()
    gates = {}

    async def check(row):
        result = {
            "host": row["host"], "ip": row["ip"], "passed": False,
            "checked_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        }
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", row["ip"] + ":443",
                "-servername", row["host"], "-tls1_3", "-alpn", "h2",
                "-groups", "X25519", "-verify_hostname", row["host"],
                "-verify_return_error", "-brief",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), args.timeout)
            text = (stdout + stderr).decode("utf-8", "replace")
            result["passed"] = (
                process.returncode == 0 and "Protocol version: TLSv1.3" in text
                and "Server Temp Key: X25519" in text and "Verification: OK" in text
            )
            if not result["passed"]:
                result["reason"] = text[:1200] or f"OpenSSL exit {process.returncode}"
        except Exception as error:
            result["reason"] = f"{type(error).__name__}: {error}"
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
        return result

    async def worker(output):
        nonlocal completed, passed
        while True:
            row = await queue.get()
            try:
                gate = gates.setdefault(row["ip"], asyncio.Semaphore(2))
                async with gate:
                    result = await check(row)
                output.write(json.dumps(result) + "\n")
                completed += 1
                passed += int(result["passed"])
                if completed % 250 == 0 or completed == total:
                    print(json.dumps({
                        "x25519_checked": completed, "batch_total": total,
                        "x25519_passed": passed,
                        "elapsed_s": round(time.monotonic() - started),
                    }), flush=True)
            finally:
                queue.task_done()

    with args.output.open("a" if args.resume else "w", buffering=1) as output:
        workers = [asyncio.create_task(worker(output)) for _ in range(args.workers)]
        await queue.join()
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=6)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.workers <= 64 or args.timeout <= 0:
        parser.error("Use 1 to 64 workers and a positive timeout")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
