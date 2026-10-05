# Russian REALITY SNI candidates

An observed list of TLS-compatible hostnames for evaluating VLESS/REALITY targets, with the measurements and scripts used to select them.

The **2026-10-05 UTC snapshot contains 8,509 candidates**, selected from **35,668 screened hostnames**. The starting dataset contained 21,421 `.ru` domains; the scan also included previous candidates, `www` alternatives, and subdomains discovered through redirects.

## Download

- [SNI list](russian-reality-snis.txt): one hostname per line.
- [Verification report](sni-verification.csv): individual results, tested IPv4 addresses, HTTP responses, and exclusion reasons.
- [Snapshot summary](sni-verification-summary.json): counts and export time.
- [Method and source notes](sni-verification-notes.txt): detailed criteria, scope, and attribution.

Each selected hostname passed:

1. A TLS 1.3 handshake on TCP port 443 with certificate-chain and hostname verification.
2. HTTP/2 negotiation through ALPN (`h2`).
3. An HTTP 200 response to a separate HTTP/1.1 GET, allowing at most two HTTPS redirects within the same hostname.
4. A separate OpenSSL TLS 1.3 handshake offering only X25519, against the same tested IPv4 address.

These are measurements from one network and time. Test an actual REALITY connection from your VPS and client network. A `.ru` suffix does not establish Russian hosting, ownership, or ISP allowlisting. HTTP/2 application traffic, site content, and reputation were not assessed.

## Use a candidate

For a hostname such as `st.ozone.ru`, use `st.ozone.ru:443` as the server's REALITY `target`, include `st.ozone.ru` in the server's `serverNames`, and use the same hostname as the client's `serverName`/SNI. Keep the rest of your existing authentication and transport configuration.

See the [official REALITY configuration documentation](https://xtls.github.io/en/config/transports/reality.html).

## Refresh the measurements

Requirements: Python 3.11 or newer, OpenSSL 3.x on `PATH`, system CA certificates, and outbound DNS/HTTPS access. The scripts use the Python standard library.

Run from the repository root. These commands replace the measurement files and generated list, so commit a snapshot before starting a fresh scan.

```sh
python3 verify_snis.py \
  --dataset russian-sni-source.csv \
  --previous russian-reality-snis.txt \
  --output sni-verification.jsonl

python3 verify_x25519.py \
  --input sni-verification.jsonl \
  --output sni-x25519-verification.jsonl

python3 export_snis.py
```

The first stage defaults to 48 workers, two concurrent probes per IP, and five-second timeouts. It tries a `www` alternative when a source domain fails selection. Use `--workers` and `--timeout` to adjust the scan. Both checking scripts support `--resume` for continuing an interrupted run; omit it when collecting fresh measurements.

The committed source CSV is a fixed snapshot. To update the source pool first:

```sh
curl --fail --location --output russian-sni-source.csv \
  https://netapi.com/top-websites/ru/download/
```

To rebuild the list and reports from the committed measurements without making network requests:

```sh
python3 export_snis.py
```

The initial snapshot also includes one-time retries of transient failures and extra subdomains discovered through redirects. Their results are preserved in the raw log. When a hostname has multiple measurements, the exporter uses its last measurement. The refresh command retains the current list as additional probe seeds.

## Tracked files

| File | Purpose |
| --- | --- |
| `russian-reality-snis.txt` | Current selected hostnames |
| `russian-reality-snis.original.txt` | Original 31-host seed list, retained for comparison |
| `russian-sni-source.csv` | NetAPI source dataset snapshot |
| `sni-verification.jsonl` | Raw TLS/HTTP measurements, including retries |
| `sni-x25519-verification.jsonl` | Raw OpenSSL X25519 results |
| `sni-verification.csv` | Combined report for all screened hostnames |
| `sni-verification-summary.json` | Snapshot counts |
| `sni-verification-notes.txt` | Methodology and source attribution |
| `verify_snis.py` | TLS/HTTP checker |
| `verify_x25519.py` | X25519 checker |
| `export_snis.py` | List and report exporter |

ZIP bundles and Python caches are excluded from Git.

## Source attribution

The source dataset is provided by [NetAPI](https://netapi.com/) under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). See the [dataset description](https://netapi.com/ru/top-websites/ru/) and [CSV download](https://netapi.com/top-websites/ru/download/).

The dataset was filtered and supplemented with hostname variants and independent network measurements. NetAPI does not endorse the resulting list. The source license applies to the NetAPI dataset; this notice does not assign a license to the repository's code.
