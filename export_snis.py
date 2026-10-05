#!/usr/bin/env python3
"""Export checked SNI candidates and their verification results."""

import argparse
import csv
import datetime
import json
from pathlib import Path


BASE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=BASE)
    parser.add_argument("--origin", default="the machine running the checker")
    args = parser.parse_args()
    base = args.directory
    results = {}
    for line in (base / "sni-verification.jsonl").read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            results[row["host"]] = row
    with (base / "russian-sni-source.csv").open(newline="") as source:
        ranks = {row["Domain"]: int(row["Rank"]) for row in csv.DictReader(source)}
    previous = (base / "russian-reality-snis.original.txt").read_text().splitlines()
    previous_order = {host: index for index, host in enumerate(previous)}

    def rank_for(host):
        labels = host.split(".")
        for index in range(len(labels) - 1):
            rank = ranks.get(".".join(labels[index:]))
            if rank is not None:
                return rank
        return 10**9

    def sort_key(host):
        return (0, previous_order[host], host) if host in previous_order else (
            1, rank_for(host), host,
        )

    hosts = sorted((
        host for host, row in results.items()
        if row.get("eligible") and row.get("tls") == "TLSv1.3"
        and row.get("alpn") == "h2" and row.get("certificate_valid")
        and row.get("http_status") == 200
    ), key=sort_key)
    key_checks_path = base / "sni-x25519-verification.jsonl"
    key_checks = {}
    if key_checks_path.exists():
        for line in key_checks_path.read_text().splitlines():
            row = json.loads(line)
            key_checks[row["host"]] = row
        hosts = [host for host in hosts if key_checks.get(host, {}).get("passed")
                 and key_checks[host]["ip"] == results[host]["ip"]]
    passed = set(hosts)
    target = base / "russian-reality-snis.txt"
    temporary = target.with_suffix(".txt.tmp")
    temporary.write_text("\n".join(hosts) + "\n")
    temporary.replace(target)

    fields = [
        "host", "included", "source_rank_ru", "ip", "tls", "alpn",
        "certificate_valid", "x25519_verified", "http_status", "http_path",
        "same_host_redirects", "handshake_ms", "checked_utc", "cert_expires",
        "reason", "location",
    ]
    with (base / "sni-verification.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for host in sorted(results, key=sort_key):
            row = results[host]
            item = {field: row.get(field, "") for field in fields}
            item.update(
                included=host in passed,
                source_rank_ru=rank_for(host) if rank_for(host) < 10**9 else "",
                x25519_verified=key_checks.get(host, {}).get("passed", ""),
            )
            if row.get("eligible") and host not in passed and key_checks:
                check = key_checks.get(host, {})
                if not check:
                    item["reason"] = "X25519 check missing"
                elif check.get("ip") != row.get("ip"):
                    item["reason"] = "X25519 check used a different IP"
                else:
                    detail = check.get("reason", "handshake failed").replace("\n", " | ")
                    item["reason"] = "X25519: " + detail[:400]
            # Keep untrusted response headers inert in spreadsheet applications.
            for field, value in item.items():
                if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
                    item[field] = "'" + value
            writer.writerow(item)

    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    summary = {
        "exported_utc": now,
        "source_ru_domains": len(ranks),
        "checked_unique_hosts": len(results),
        "tls_13_h2_valid_certificate_hosts": sum(
            row.get("tls_ok", False) and row.get("alpn") == "h2"
            for row in results.values()
        ),
        "selected_hosts": len(hosts),
        "new_hosts": len(passed - set(previous)),
        "previous_hosts_retained": len(passed & set(previous)),
        "previous_hosts_excluded": sorted(set(previous) - passed),
        "x25519_checked": bool(key_checks),
        "source": "https://netapi.com/top-websites/ru/download/",
        "source_license": "CC BY 4.0",
        "verification_origin": args.origin,
    }
    (base / "sni-verification-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (base / "sni-verification-notes.txt").write_text(
        f"Russian REALITY SNI candidates\nExported: {now}\n\n"
        f"Selected: {len(hosts)} unique hostnames\n"
        f"Checked: {len(results)} unique hostnames\n"
        f"Source dataset: {len(ranks)} .ru domains, plus earlier candidates\n\n"
        "Selection requirements:\n"
        "- Public IPv4 HTTPS service on TCP port 443.\n"
        "- Successful TLS 1.3 handshake with normal certificate-chain and hostname verification.\n"
        "- HTTP/2 selected through ALPN (h2).\n"
        "- HTTP 200 from a separate HTTP/1.1 GET, after at most two HTTPS redirects\n"
        "  within the same hostname. Captcha/challenge redirect paths are not followed.\n"
        + ("- Separate verified TLS 1.3 handshake using X25519 only.\n" if key_checks else "")
        + "\nScope and interpretation:\n"
        "- Every base hostname in the downloaded .ru dataset was considered.\n"
        "- A www hostname is additionally tried when the base hostname fails selection.\n"
        "- Previous selected hostnames are also checked, retaining discovered subdomains\n"
        "  only when they pass the current measurements.\n"
        "- The initial snapshot included extra redirect discovery and transient retries;\n"
        "  scheduled refreshes perform fresh checks of source domains and existing candidates.\n"
        "- At most two resolved public IPv4 addresses are tried per hostname.\n"
        "- TCP connection failures for a shared IP are cached for up to 10 minutes;\n"
        "  names skipped for that reason are excluded from the selected list.\n"
        "- TLS/HTTP behavior can differ by address, time, location, or client fingerprint.\n"
        f"- Verification origin: {args.origin}. Results depend on this network location.\n"
        "- A full authenticated VLESS/REALITY connection was not tested.\n"
        "- A .ru suffix does not establish Russian ownership, hosting, or ISP allowlisting.\n"
        "- HTTP/2 application traffic, site content/reputation, OCSP stapling, and\n"
        "  post-quantum key exchange were not assessed.\n"
        "- Existing candidates are first; additions follow the dataset's relative rank.\n"
        "- Different hostnames may share an IP or infrastructure.\n\n"
        "Sources and attribution:\n"
        "NetAPI: https://netapi.com/\n"
        "Dataset: https://netapi.com/top-websites/ru/download/\n"
        "Dataset description: https://netapi.com/ru/top-websites/ru/\n"
        "License: Creative Commons Attribution 4.0 (CC BY 4.0)\n"
        "https://creativecommons.org/licenses/by/4.0/\n"
        "The source was filtered and supplemented with live network measurements\n"
        "and www hostname variants. NetAPI does not endorse these recommendations.\n"
        "REALITY target guidance: https://github.com/XTLS/REALITY/blob/main/README.en.md\n\n"
        "To repeat the first-stage checks from a VPS using Python 3.11+:\n"
        "python3 verify_snis.py --dataset russian-sni-source.csv "
        "--previous russian-reality-snis.original.txt --output sni-verification.jsonl\n"
        "python3 verify_x25519.py --input sni-verification.jsonl "
        "--output sni-x25519-verification.jsonl\n"
        "python3 export_snis.py\n"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
