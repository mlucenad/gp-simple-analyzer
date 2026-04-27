# GlobalProtect Session Analyzer

Single-file Python tool that consolidates Palo Alto GlobalProtect VPN
session exports and produces an interactive anomaly-detection dashboard
you can open directly in a browser.

- **Stdlib-only**, so there is no `pip install` and no `requirements.txt`.
  Runs on Python 3.8+.
- **23 anomaly rules** covering credentials, devices, geography, and
  behavior, with all thresholds collected in one place.
- **Self-contained HTML dashboard** that opens offline, with no server
  and no external assets. The data is embedded inside the file as
  gzip+base64.
- **Locale-independent**, and the baseline region is auto-detected from
  the data, so the tool works for any organization without configuration.
- **Fully local**, with no network calls, no telemetry, and no
  third-party GeoIP services. Sensitive data never leaves your machine.

> **Disclaimer.** This is an independent open-source project. It is not
> affiliated with, endorsed by, or sponsored by Palo Alto Networks, Inc.
> "GlobalProtect" and "Palo Alto Networks" are trademarks of their
> respective owners.

---

## Why this exists

GlobalProtect's built-in gateway view shows live sessions row by row,
but it gives no way to spot patterns over weeks of data, such as
concurrent logins from different countries, impossible travel,
beaconing, or dormant accounts resurfacing. Feeding the CSV exports
into a SIEM solves this, but for many teams that is overkill.

This tool sits in between. You drop the exports in a folder, run one
Python command, and open the resulting HTML in your browser. No
infrastructure, no data egress, no learning curve.

---

## Quick start

Replace `YOUR_USERNAME` with your GitHub username, or use the HTTPS or
SSH URL of a fork:

```bash
git clone https://github.com/YOUR_USERNAME/gp-simple-analyzer.git
cd gp-simple-analyzer

# Drop your GlobalProtect Gateway CSV exports next to the script
python3 analyze_globalprotect.py
open summary.html        # macOS, or use xdg-open on Linux, or just double-click
```

If you only want the script and not the repo:

```bash
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/gp-simple-analyzer/main/analyze_globalprotect.py
python3 analyze_globalprotect.py --input-dir /path/to/exports
```

Output:

```
17:35:39 INFO    Loaded 1082 session(s), 0 parse error(s).
17:35:39 INFO    Baseline region (auto-detected): ES.
17:35:39 INFO    Generated 632 findings across 23 rules over 1082 sessions.
17:35:39 INFO    Wrote ./consolidated_sessions.csv (1082 rows).
17:35:39 INFO    Wrote ./summary.html (194.4 KB).
17:35:39 INFO    Done. Findings by severity: critical=1, high=4, medium=161, low=2, info=464
```

---

## Input

Drop one or more GlobalProtect Gateway CSV exports in the working
directory, or use `--input-dir`. Both formats are supported and can be
mixed:

| Format | Distinguishing column | Treated as |
|---|---|---|
| Closed sessions | `Logout At` | finished |
| Active sessions | `Lifetime (S)` | ongoing (logout = +inf for overlap analysis) |

Filenames following the GP convention
`export_network_global_protect_gateways_<MMDDYYYY>_<HHMMSS>gmt+<N>.csv`
let the script auto-infer the year for each session. If a filename does
not match that convention, today's date is used as anchor, and you can
override this with `--anchor-date YYYY-MM-DD`.

---

## Output

| File | Description |
|---|---|
| `consolidated_sessions.csv` | Deduplicated sessions, year-resolved, ordered by login time |
| `summary.html` | Self-contained interactive dashboard (no JS dependencies) |

If either file already exists when the script runs, it is first renamed
to `<stem>.<YYYYMMDDTHHMMSS>.<ext>` using its mtime, and only then is
the new output written, so you never silently lose a previous report.
Pass `--no-archive` to overwrite instead.

---

## Dashboard tour

The dashboard is a single HTML file with hash-based routing, so every
URL is linkable and shareable.

| Route | What you see |
|---|---|
| `#/` | Overview: KPIs, findings by rule (grouped by severity), top users, day×hour activity heatmap, sessions per region |
| `#/findings` | All findings, filterable by rule, severity, and free text |
| `#/finding/<id>` | Single finding detail with evidence sessions |
| `#/users` | All users with finding counts and activity stats |
| `#/user/<name>` | Per-user dashboard with timeline, finding markers, and sessions table |
| `#/user/<name>/computer/<id>` | Drill-down on a single device for a user |
| `#/sessions` | Full sessions table (region, status, off-hours filters) |
| `#/regions` | Sessions per Source Region |
| `#/rules` | Catalog of every rule (id, severity, count, fired or idle status) |
| `#/timelines` | Stacked per-user timelines with shared time axis (top-N flagged users, severity-colored finding markers) |

Tables use virtual scrolling, so volumes of 100k+ sessions remain
responsive.

---

## Anomaly rules

23 rules, all configurable from the `THRESHOLDS` dict at the top of
`analyze_globalprotect.py`. Severities, from lowest to highest: `info`,
`data-quality`, `low`, `medium`, `high`, `critical`.

| ID | Severity | Rule |
|---|---|---|
| R01 | high | Concurrent sessions with different Public IP |
| R02 | critical | Concurrent sessions with different Source Region |
| R03 | critical | Impossible travel (speed > threshold between regions) |
| R04 | medium | Unusual region for user (outside their personal top-K) |
| R05 | medium | Multiple Computers on the same day |
| R06 | info | Public IP not previously seen for this user |
| R07 | low | Session with anomalously long duration |
| R08 | low | Repeated logins outside working hours |
| R09 | medium | Computer shared between multiple Users |
| R10 | info | Source Region equal to a private range (geoip unresolved) |
| R11 | medium | Abrupt Client/OS change with different region within 24h |
| R12 | info | Same Public IP used by more than N users |
| R13 | medium | Lifetime exceeds maximum policy |
| R14 | data-quality | Corrupt row (Logout earlier than Login, or unparseable) |
| R15 | high | Different Domain for the same User |
| R16 | info | Non-routable Public IP (bogon) |
| R17 | medium | Beaconing: regular periodic reconnections |
| R18 | medium | New user whose first activity is outside the baseline |
| R19 | medium | Login burst (many logins in a short window) |
| R20 | low | Tunnel Type flapping between SSL and IPSec on the same Computer |
| R21 | medium | New Computer for an established user |
| R22 | medium | Dormant user resurfaces after long inactivity |
| R23 | low | Weekend activity for a weekday-only user |

Geography rules (R03 and R04) use an embedded country-centroid table
of around 180 entries, so no external GeoIP database is required.

The personal baseline used by R04 considers each user's top-K regions
(default K=2) as habitual, so legitimate travelers do not get flagged.

The organization baseline region used by R18 is auto-detected as the
most common ISO-2 region in the dataset, and you can override it with
`--baseline-region XX` if needed.

---

## CLI reference

```text
python3 analyze_globalprotect.py [options]

Options:
  --input-dir DIR        Directory with CSV exports (default: cwd).
  --output-dir DIR       Where to write outputs (default: --input-dir).
  --anchor-date YYYY-MM-DD
                         Override year inference (default: per-file from filename).
  --baseline-region XX   ISO-2 region considered the organization's "home" for R18.
                         Default: most common ISO-2 region in the data.
  --no-html              Skip HTML output.
  --no-csv               Skip consolidated CSV output.
  --no-archive           Overwrite existing outputs instead of timestamp-archiving them.
  -v, --verbose          Verbose logging.
```

---

## Configuration

Every threshold lives in the `THRESHOLDS` dict at the top of
`analyze_globalprotect.py`, giving you a single place to tune the rule
engine. A few highlights:

| Threshold | Default | Used by |
|---|---|---|
| `impossible_travel_kmh` | 900 | R03 |
| `user_baseline_top_k` | 2 | R04 |
| `long_session_seconds` | 12 h | R07 |
| `off_hours_start` and `off_hours_end` | 22 and 7 | R08 |
| `beacon_min_streak` | 5 | R17 |
| `burst_min_logins` and `burst_window_seconds` | 10 and 600 | R19 |
| `dormant_min_days` | 45 | R22 |

See the script for the full list of around 20 thresholds.

---

## Privacy

This tool is fully local. No data ever leaves your machine.

- The HTML dashboard embeds the data inside the file (gzip + base64,
  decompressed in-browser via `DecompressionStream`).
- Country geolocation is done from the embedded centroid table, so
  there are no API calls.
- The script makes no network requests.

Treat the CSVs you analyze as sensitive, since they contain usernames,
public IPs, and device identifiers. The included `.gitignore` excludes
`*.csv` and `*.html` by default so you do not accidentally commit them.

---

## Tests

```bash
python3 -m unittest discover tests
```

41 tests covering rule logic, dedupe, year inference, HTML payload
integrity, archive-on-overwrite behavior, baseline auto-detection, and
a 50k-row scale smoke test that runs in around 30 seconds.

---

## Project structure

```
analyze_globalprotect.py            # the deliverable: stdlib-only, single file
tests/test_analyze_globalprotect.py # unittests
README.md
.gitignore
```

The script is stdlib-only by design. The country-centroid table, the
bogon CIDR list, and the entire HTML dashboard template are all
embedded inside it, so the file can be copied into any directory and
run.

---

## Browser compatibility

The dashboard requires `DecompressionStream` for client-side gzip
decoding:

- Chrome and Edge 80+
- Safari 16.4+
- Firefox 113+

---

## Contributing

Bug reports and pull requests are welcome via
[GitHub Issues](../../issues) and
[Pull Requests](../../pulls).

When adding a new rule:

1. Add the entry to `RULE_CATALOG` (id, name, default severity).
2. Add any new threshold to `THRESHOLDS`.
3. Implement the rule as a pure function that returns findings.
4. Register it in `run_all_rules`.
5. Add a unittest under `tests/`.
6. Bump the rule count in this README.

The deliverable must remain a single file, so please do not split the
script into a package.

---

## License

[MIT](LICENSE) © 2026 Manuel Lucena.

You may use, modify, and redistribute this software under the terms of
the MIT License. See the [`LICENSE`](LICENSE) file for the full text.

---

## No warranty

This software is provided as-is, without warranty of any kind. Anomaly
rules are heuristics, so you should review findings in context before
acting on them, and tune the thresholds in `THRESHOLDS` to your
environment.
