# Russian REALITY SNI candidates

An observed list of TLS-compatible hostnames for evaluating VLESS/REALITY targets, with the measurements and scripts used to select them.

The list is refreshed every three days. See the [snapshot summary](sni-verification-summary.json) for its current export time and counts. The initial 2026-10-05 snapshot contained 8,509 candidates from 35,668 screened hostnames, including previous candidates, `www` alternatives, and subdomains discovered through redirects.

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

The [GitHub Actions workflow](.github/workflows/update-snis.yml) refreshes the list **every three UTC calendar days at 03:17 UTC** and offers **Run workflow** for immediate manual refreshes. A lightweight daily check reads the last successful snapshot's export date; the full scan runs only on or after the third calendar day following that date. This keeps the three-day interval consistent across month boundaries. Between refreshes, the scan and tests are skipped. Manual refreshes run immediately and reset the interval when their snapshot is committed. Failed refreshes are retried on the next scheduled check. Scheduled runs may start later when GitHub is busy. Each full refresh downloads a fresh NetAPI CSV, checks every source domain and the current selected candidates, and tries `www` fallbacks where needed.

Only a complete, validated snapshot replaces the tracked data. Empty lists, missing source/seed/fallback measurements, missing or mismatched X25519 checks, invalid exports, and candidate counts below 50% of the previous snapshot fail the run. The source CSV must contain at least 1,000 domains and retain at least 50% of the previous source count. Failed scans leave the existing tracked snapshot untouched; staged scan files remain available as workflow artifacts for seven days.

On success, `github-actions[bot]` commits the list, source CSV, raw measurements, reports, summary, and notes together to the default branch. It stages only those seven data files and skips a commit if none changed. Measurement timestamps usually produce a commit for each successful refresh even when the hostname list stays the same. It uses GitHub's temporary built-in token; no token value or personal access token is stored in this repository. Write permission is limited to the scheduled/manual refresh job. Push and pull-request events run validation tests only, so a data commit cannot start another refresh. Pushes never force-update the branch; branch protection or concurrent edits can cause a push to fail.

The automated measurements come from a GitHub-hosted runner. Verify shortlisted targets from your own VPS and client network. Review failures in the [Actions page](https://github.com/phungvanquy/snis/actions/workflows/update-snis.yml). A manually started run can lower `min_retained_ratio` after you investigate a real drop; an empty result is always rejected.

To run the same download/check/validate process locally:

```sh
python3 refresh_snis.py --stage-dir refresh-output --origin 'my VPS'
```

Use a new or empty staging directory for each run. The default is the Git-ignored `refresh-output/`. The original 31-host seed file and the code are preserved. Snapshot summary fields named `new_hosts` and `previous_hosts_*` compare with that original seed file, rather than yesterday's list.

For lower-level checks using the committed source CSV, run these commands from the repository root. They directly replace measurement files and generated outputs, so commit a snapshot before starting:

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

The committed source CSV is the source pool used for the last successful snapshot. To download it separately:

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
| `refresh_snis.py` | Staged refresh with publication guards |
| `.github/workflows/update-snis.yml` | Scheduled/manual updates and bot commits |

ZIP bundles, staged refresh outputs, and Python caches are excluded from Git.

## Source attribution

The source dataset is provided by [NetAPI](https://netapi.com/) under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). See the [dataset description](https://netapi.com/ru/top-websites/ru/) and [CSV download](https://netapi.com/top-websites/ru/download/).

The dataset was filtered and supplemented with hostname variants and independent network measurements. NetAPI does not endorse the resulting list. The source license applies to the NetAPI dataset; this notice does not assign a license to the repository's code.
