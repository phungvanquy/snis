#!/usr/bin/env python3
"""Download, check, and validate a fresh snapshot before replacing tracked data."""

import argparse
import csv
import io
import ipaddress
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request


BASE = Path(__file__).resolve().parent
SOURCE_URL = "https://netapi.com/top-websites/ru/download/"
OUTPUT_FILES = (
    "russian-reality-snis.txt",
    "russian-sni-source.csv",
    "sni-verification.jsonl",
    "sni-x25519-verification.jsonl",
    "sni-verification.csv",
    "sni-verification-summary.json",
    "sni-verification-notes.txt",
)
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def read_source(text, minimum=1000):
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    if reader.fieldnames != ["Rank", "Domain"]:
        raise ValueError("Source must be a Rank,Domain CSV")
    domains = {}
    for row in reader:
        host = (row.get("Domain") or "").strip().lower()
        if (None in row or len(host) > 253 or not host.endswith(".ru")
                or not all(LABEL.fullmatch(label) for label in host.split("."))):
            raise ValueError(f"Invalid source hostname: {host!r}")
        rank = int(row["Rank"])
        if rank < 1 or host in domains:
            raise ValueError(f"Invalid rank or duplicate source hostname: {host}")
        domains[host] = rank
    if len(domains) < minimum:
        raise ValueError(f"Source has only {len(domains)} domains; need {minimum}")
    return domains


def download_source(previous_count):
    # Reject HTML, oversized responses, and obviously truncated source pools.
    minimum = max(1000, math.ceil(previous_count * 0.5))
    for attempt in range(3):
        try:
            request = urllib.request.Request(SOURCE_URL, headers={
                "User-Agent": "snis-daily-refresh/1.0 (+https://github.com/phungvanquy/snis)",
            })
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(10_000_001)
            if len(data) > 10_000_000:
                raise ValueError("Source response exceeds 10 MB")
            return read_source(data.decode("utf-8-sig"), minimum)
        except (OSError, ValueError):
            if attempt == 2:
                raise
            time.sleep(2 * (attempt + 1))


def read_records(path):
    results = {}
    for line in path.read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            host = row["host"]
            if not isinstance(host, str) or not host:
                raise ValueError(f"Invalid hostname in {path.name}")
            results[host] = row
    return results


def eligible(row):
    return (row.get("eligible") is True and row.get("tls") == "TLSv1.3"
            and row.get("alpn") == "h2" and row.get("certificate_valid") is True
            and row.get("http_status") == 200)


def validate_measurements(stage, domains, seeds):
    results = read_records(stage / "sni-verification.jsonl")
    missing = (set(domains) | set(seeds)) - results.keys()
    if missing:
        raise ValueError(f"Incomplete scan: {len(missing)} source/seed hosts missing")
    for host, row in results.items():
        if (not isinstance(row.get("eligible"), bool)
                or not isinstance(row.get("tls_ok"), bool)
                or not row.get("checked_utc")):
            raise ValueError(f"Incomplete measurement for {host}")
        if row["eligible"] and not eligible(row):
            raise ValueError(f"Contradictory protocol measurement for {host}")
    for host in domains:
        row = results[host]
        if not row["eligible"] and "www." + host not in results:
            raise ValueError(f"Missing www fallback for {host}")
    keys = read_records(stage / "sni-x25519-verification.jsonl")
    selected = set()
    for host, row in results.items():
        if not eligible(row):
            continue
        check = keys.get(host, {})
        if (not isinstance(check.get("passed"), bool)
                or check.get("ip") != row.get("ip")):
            raise ValueError(f"Missing or mismatched X25519 measurement for {host}")
        address = ipaddress.ip_address(row["ip"])
        if address.version != 4 or not address.is_global:
            raise ValueError(f"Non-public IPv4 result for {host}")
        if check["passed"]:
            selected.add(host)
    return results, selected


def validate_snapshot(stage, domains, seeds, previous_count, minimum_ratio=0.5):
    if not math.isfinite(minimum_ratio) or not 0 <= minimum_ratio <= 1:
        raise ValueError("Minimum retained ratio must be between 0 and 1")
    results, selected = validate_measurements(stage, domains, seeds)
    hosts = (stage / "russian-reality-snis.txt").read_text().splitlines()
    if not hosts or len(hosts) != len(set(hosts)) or set(hosts) != selected:
        raise ValueError("Exported list is empty, duplicated, or disagrees with measurements")
    if len(hosts) < previous_count * minimum_ratio:
        raise ValueError(
            f"Candidate count fell from {previous_count} to {len(hosts)}; "
            f"minimum retained ratio is {minimum_ratio}. Existing snapshot preserved."
        )
    summary = json.loads((stage / "sni-verification-summary.json").read_text())
    if (summary.get("selected_hosts") != len(hosts)
            or summary.get("checked_unique_hosts") != len(results)
            or summary.get("source_ru_domains") != len(domains)
            or summary.get("x25519_checked") is not True):
        raise ValueError("Summary does not match measurements")
    with (stage / "sni-verification.csv").open(newline="") as handle:
        report = list(csv.DictReader(handle))
    if (len(report) != len(results) or {row["host"] for row in report} != set(results)
            or {row["host"] for row in report if row["included"] == "True"} != selected):
        raise ValueError("CSV report does not match measurements")
    for filename in OUTPUT_FILES:
        if not (stage / filename).is_file() or not (stage / filename).stat().st_size:
            raise ValueError(f"Missing or empty snapshot file: {filename}")
    return summary


def publish_snapshot(stage, destination, domains, seeds, previous_count, minimum_ratio):
    summary = validate_snapshot(stage, domains, seeds, previous_count, minimum_ratio)
    # Copy all outputs first. A failed scan/validation never touches tracked files.
    for filename in OUTPUT_FILES:
        shutil.copyfile(stage / filename, destination / (filename + ".tmp"))
    for filename in OUTPUT_FILES:
        (destination / (filename + ".tmp")).replace(destination / filename)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-dir", type=Path, default=BASE / "refresh-output")
    parser.add_argument("--min-retained-ratio", type=float, default=0.5)
    parser.add_argument("--origin", default="the machine running the checker")
    args = parser.parse_args()
    if not math.isfinite(args.min_retained_ratio) or not 0 <= args.min_retained_ratio <= 1:
        parser.error("--min-retained-ratio must be between 0 and 1")
    stage = args.stage_dir.resolve()
    if stage == BASE or (stage.exists() and any(stage.iterdir())):
        parser.error("--stage-dir must be a new or empty directory")
    stage.mkdir(parents=True, exist_ok=True)
    seeds = (BASE / "russian-reality-snis.txt").read_text().splitlines()
    seeds = list(dict.fromkeys(host for host in seeds if host))
    old_source = read_source((BASE / "russian-sni-source.csv").read_text(), minimum=1)
    domains = download_source(len(old_source))
    with (stage / "russian-sni-source.csv").open("w", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["Rank", "Domain"])
        writer.writerows((rank, host) for host, rank in domains.items())
    (stage / "previous-snis.txt").write_text("\n".join(seeds) + "\n")
    shutil.copyfile(BASE / "russian-reality-snis.original.txt",
                    stage / "russian-reality-snis.original.txt")
    commands = [
        [sys.executable, str(BASE / "verify_snis.py"),
         "--dataset", str(stage / "russian-sni-source.csv"),
         "--previous", str(stage / "previous-snis.txt"),
         "--output", str(stage / "sni-verification.jsonl")],
        [sys.executable, str(BASE / "verify_x25519.py"),
         "--input", str(stage / "sni-verification.jsonl"),
         "--output", str(stage / "sni-x25519-verification.jsonl")],
    ]
    for command in commands:
        subprocess.run(command, check=True)
    validate_measurements(stage, domains, seeds)
    subprocess.run([sys.executable, str(BASE / "export_snis.py"),
                    "--directory", str(stage), "--origin", args.origin], check=True)
    summary = publish_snapshot(stage, BASE, domains, seeds, len(seeds), args.min_retained_ratio)
    print(f"Published validated snapshot: {summary['selected_hosts']} candidates", flush=True)


if __name__ == "__main__":
    main()
