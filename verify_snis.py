#!/usr/bin/env python3
"""Check public IPv4 HTTPS hosts for TLS 1.3, h2, and HTTP 200.

Uses the Python standard library. It makes ordinary TLS connections and HTTP
GET requests; it does not configure or test a VLESS/REALITY proxy.
"""

import argparse
import asyncio
import csv
import datetime
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def tls_context(protocols):
    context = ssl.create_default_context()
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(protocols)
    return context


class Checker:
    def __init__(self, args):
        self.args = args
        self.h2_context = tls_context(["h2", "http/1.1"])
        self.http_context = tls_context(["http/1.1"])
        self.ip_limits = {}
        self.unreachable_ips = {}
        self.results = {}
        self.queued = set()
        self.queue = asyncio.Queue()
        self.root_ranks = {}
        self.started = time.monotonic()
        self.root_count = 0

    def enqueue(self, host, rank=None, root=False, source="previous"):
        host = host.lower().strip().rstrip(".").encode("idna").decode("ascii")
        if host in self.queued or not host or "/" in host or ":" in host:
            return
        self.queued.add(host)
        if root:
            self.root_ranks[host] = rank
        self.queue.put_nowait((host, rank, root, source))

    async def close(self, writer):
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.2)
            except Exception:
                writer.transport.abort()

    async def connect(self, host, ip, context):
        cached = self.unreachable_ips.get(ip)
        if cached and time.monotonic() - cached[0] < 600:
            raise ConnectionError(f"Cached TCP connection failure for {ip}: {cached[1]}")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, limit=65536), self.args.timeout,
            )
        except (TimeoutError, ConnectionRefusedError, OSError) as error:
            self.unreachable_ips[ip] = (time.monotonic(), f"{type(error).__name__}: {error}")
            raise
        try:
            await asyncio.wait_for(
                writer.start_tls(context, server_hostname=host,
                                 ssl_handshake_timeout=self.args.timeout),
                self.args.timeout,
            )
            return reader, writer
        except BaseException:
            writer.transport.abort()
            raise

    async def http_status(self, host, ip):
        path = "/"
        for hop in range(3):
            writer = None
            try:
                reader, writer = await self.connect(host, ip, self.http_context)
                writer.write((
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                    "User-Agent: Mozilla/5.0\r\n"
                    "Accept: */*\r\nConnection: close\r\n\r\n"
                ).encode("ascii"))
                await asyncio.wait_for(writer.drain(), self.args.timeout)
                for _ in range(4):
                    headers = await asyncio.wait_for(
                        reader.readuntil(b"\r\n\r\n"), self.args.timeout
                    )
                    lines = headers.decode("iso-8859-1").split("\r\n")
                    status = int(lines[0].split()[1])
                    if status >= 200:
                        break
                fields = {}
                for line in lines[1:]:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        fields[key.lower()] = value.strip()
                info = {
                    "http_status": status, "http_path": path,
                    "same_host_redirects": hop,
                    "content_type": fields.get("content-type", ""),
                }
                location = fields.get("location", "")
                if location:
                    info["location"] = location[:1024]
                if status in (301, 302, 303, 307, 308) and location:
                    target = urlsplit(urljoin(f"https://{host}{path}", location))
                    if (target.scheme == "https" and target.hostname == host
                            and target.port in (None, 443) and hop < 2
                            and not any(x in target.path.lower() for x in ("captcha", "challenge"))):
                        path = target.path or "/"
                        if target.query:
                            path += "?" + target.query
                        if any(ord(c) < 32 or ord(c) > 126 for c in path):
                            return info
                        continue
                return info
            finally:
                await self.close(writer)

    async def probe(self, host, rank, source):
        result = {
            "host": host, "rank_ru": rank, "source": source,
            "checked_utc": utc_now(), "tls_ok": False, "eligible": False,
        }
        writer = None
        try:
            addresses = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(
                    host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM,
                ), self.args.timeout,
            )
            ips = list(dict.fromkeys(row[4][0] for row in addresses))
            ips = [ip for ip in ips if ipaddress.ip_address(ip).is_global]
            if not ips:
                raise ValueError("No public IPv4 address")
            errors = []
            for ip in ips[:2]:
                gate = self.ip_limits.setdefault(ip, asyncio.Semaphore(2))
                async with gate:
                    try:
                        start = time.monotonic()
                        _, writer = await self.connect(host, ip, self.h2_context)
                        tls = writer.get_extra_info("ssl_object")
                        result.update(
                            ip=ip, tls=tls.version(), alpn=tls.selected_alpn_protocol(),
                            certificate_valid=True,
                            handshake_ms=round((time.monotonic() - start) * 1000),
                            cert_expires=tls.getpeercert().get("notAfter", ""),
                        )
                        result["tls_ok"] = result["alpn"] == "h2"
                        await self.close(writer)
                        writer = None
                        if result["alpn"] != "h2":
                            result["reason"] = "HTTP/2 not negotiated"
                            return result
                        result.update(await self.http_status(host, ip))
                        result["eligible"] = result["http_status"] == 200
                        if not result["eligible"]:
                            result["reason"] = f"HTTP {result['http_status']}"
                        return result
                    except Exception as error:
                        errors.append(f"{type(error).__name__}: {error}")
                    finally:
                        await self.close(writer)
                        writer = None
            result["reason"] = errors[-1] if errors else "No connection"
        except Exception as error:
            result["reason"] = f"{type(error).__name__}: {error}"
        return result

    def progress(self):
        values = list(self.results.values())
        print(json.dumps({
            "checked_hosts": len(values), "queued_total": len(self.queued),
            "root_domains_done": sum(host in self.results for host in self.root_ranks),
            "root_domains_total": self.root_count,
            "tls_passed": sum(r["tls_ok"] for r in values),
            "http_200_passed": sum(r["eligible"] for r in values),
            "elapsed_s": round(time.monotonic() - self.started),
        }), flush=True)

    async def worker(self, output):
        while True:
            host, rank, root, source = await self.queue.get()
            try:
                if host in self.results:
                    result = self.results[host]
                else:
                    result = await self.probe(host, rank, source)
                    self.results[host] = result
                    output.write(json.dumps(result, ensure_ascii=True) + "\n")
                if (root or host in self.root_ranks) and not result["eligible"]:
                    self.enqueue("www." + host, self.root_ranks.get(host, rank), source="www fallback")
            finally:
                self.queue.task_done()

    async def heartbeat(self):
        while True:
            await asyncio.sleep(15)
            self.progress()

    async def run(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        if self.args.resume and self.args.output.exists():
            for line in self.args.output.read_text().splitlines():
                try:
                    item = json.loads(line)
                    self.results[item["host"]] = item
                except (ValueError, KeyError):
                    pass
        if self.args.previous:
            for host in self.args.previous.read_text().splitlines():
                if host.strip():
                    self.enqueue(host)
        with self.args.dataset.open(newline="") as source:
            for row in csv.DictReader(source):
                host = row["Domain"].strip().lower()
                rank = int(row["Rank"])
                if self.args.limit and rank > self.args.limit:
                    continue
                self.root_ranks[host] = rank
                self.enqueue(host, rank, root=True, source="NetAPI .ru Top 1M")
        self.root_count = len(self.root_ranks)
        mode = "a" if self.args.resume else "w"
        with self.args.output.open(mode, buffering=1) as output:
            workers = [asyncio.create_task(self.worker(output)) for _ in range(self.args.workers)]
            heartbeat = asyncio.create_task(self.heartbeat())
            await self.queue.join()
            heartbeat.cancel()
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, heartbeat, return_exceptions=True)
        self.progress()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=48)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.workers <= 128 or args.timeout <= 0:
        parser.error("Use 1 to 128 workers and a positive timeout")
    asyncio.run(Checker(args).run())


if __name__ == "__main__":
    main()
