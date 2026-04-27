#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Manuel Lucena
"""GlobalProtect connection log analyzer.

Drop this script into a directory containing GlobalProtect CSV exports
(both active-session "Lifetime (S)" format and historic "Logout At" format)
and run:

    python3 analyze_globalprotect.py

It will produce, in the same directory:

  * consolidated_sessions.csv  -- deduplicated, ordered consolidation
  * summary.html               -- self-contained interactive dashboard
                                  with anomaly findings, drill-down by user
                                  and machine, virtual-scrolling tables, etc.

Only the Python standard library is required. The HTML uses vanilla JS
(no external libraries) and embeds data as gzip+base64, decompressing in
the browser via DecompressionStream (Chrome 80+, Edge 80+, Safari 16.4+,
Firefox 113+).

CLI:
    python3 analyze_globalprotect.py [--input-dir DIR] [--output-dir DIR]
                                     [--anchor-date YYYY-MM-DD]
                                     [--baseline-region ES]
                                     [--no-html] [--no-csv] [-v]
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import glob
import gzip
import hashlib
import json
import logging
import math
import os
import re
import statistics
import sys
from collections import Counter, defaultdict


# ============================================================
# CONFIG
# ============================================================

CONSOLIDATED_CSV = "consolidated_sessions.csv"
SUMMARY_HTML = "summary.html"

# Default cap on input rows. Above this, load_csvs aborts to protect
# against accidental or malicious huge inputs (the per-user O(n^2)
# overlap rules degrade badly past a few hundred thousand rows). Override
# with --max-rows. Use 0 to disable the cap entirely.
DEFAULT_MAX_ROWS = 1_000_000

# Baseline = the user's "home" region (used by R18 to flag new users whose
# first activity comes from somewhere other than the org's normal location).
# Default is auto-detected from the data (most common ISO-2 region). The user
# can still pin it explicitly via --baseline-region.
DEFAULT_BASELINE_REGION = None

# All thresholds in one place so you can tweak in production.
THRESHOLDS = {
    # R03
    "impossible_travel_kmh": 900.0,
    # R04
    "user_baseline_top_k": 2,
    # R05
    "multi_computer_min": 3,
    # R07 / R13
    "long_session_seconds": 12 * 3600,
    "lifetime_max_seconds": 24 * 3600,
    # R08
    "off_hours_start": 22,  # 22:00 inclusive
    "off_hours_end": 7,     # 07:00 exclusive
    "off_hours_min_count": 5,
    # R12
    "shared_ip_user_threshold": 5,
    # R17
    "beacon_min_streak": 5,
    "beacon_max_period_seconds": 3600,
    "beacon_period_tolerance_pct": 0.20,
    # R18
    "first_seen_max_sessions": 3,
    # R19
    "burst_window_seconds": 600,         # 10 minutes
    "burst_min_logins": 10,              # >= N logins in the window
    # R20
    "tunnel_flap_window_seconds": 24 * 3600,
    "tunnel_flap_min_switches": 4,       # SSL<->IPSec switches in window
    # R21
    "new_computer_min_history": 5,       # min prior sessions to consider user "established"
    # R22
    "dormant_min_days": 45,              # gap that defines dormancy (~6 weeks)
    "dormant_min_resurfacing_sessions": 1,
    "dormant_min_prior_sessions": 5,     # only flag users with some history
    # R23
    "weekday_only_min_weekday": 8,         # min weekday sessions for a "weekday-baselined" user
    "weekday_only_max_weekend_ratio": 0.20,  # weekend/weekday ratio must stay <= this
}

# Severity vocabulary, ordered low → high. The dashboard uses the rank.
SEVERITY_LEVELS = ["info", "data-quality", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_LEVELS)}

# Rule catalog. Names + default severity. Description shown in the UI.
RULE_CATALOG = {
    "R01": ("Concurrent sessions with different Public IP", "high"),
    "R02": ("Concurrent sessions with different Source Region", "critical"),
    "R03": ("Impossible travel (speed > threshold between regions)", "critical"),
    "R04": ("Unusual region for user (outside their personal top-K)", "medium"),
    "R05": ("Multiple Computers on the same day", "medium"),
    "R06": ("Public IP not previously seen for this user", "info"),
    "R07": ("Session with anomalously long duration", "low"),
    "R08": ("Repeated logins outside working hours", "low"),
    "R09": ("Computer shared between multiple Users", "medium"),
    "R10": ("Source Region == private range (geoip unresolved)", "info"),
    "R11": ("Abrupt Client/OS change + different region within 24h", "medium"),
    "R12": ("Same Public IP used by > N users", "info"),
    "R13": ("Lifetime exceeds maximum policy", "medium"),
    "R14": ("Corrupt row (Logout < Login or unparseable)", "data-quality"),
    "R15": ("Different Domain for the same User", "high"),
    "R16": ("Non-routable Public IP (bogon)", "info"),
    "R17": ("Beaconing: regular periodic reconnections", "medium"),
    "R18": ("New user whose first activity is outside the baseline", "medium"),
    "R19": ("Login burst (many logins in a short window)", "medium"),
    "R20": ("Tunnel Type flapping (SSL<->IPSec on same Computer)", "low"),
    "R21": ("New Computer for an established user", "medium"),
    "R22": ("Dormant user resurfaces after long inactivity", "medium"),
    "R23": ("Weekend activity for a weekday-only user", "low"),
}


# ============================================================
# Country centroids (ISO-2 → lat, lon). Public domain approximations.
# Used by R03 (impossible travel). If a region is missing, R03 just skips.
# ============================================================

COUNTRY_CENTROIDS = {
    # Europe
    "AD": (42.5, 1.5), "AL": (41.0, 20.0), "AT": (47.5, 14.5),
    "AX": (60.2, 19.9), "BA": (44.0, 18.0), "BE": (50.5, 4.5),
    "BG": (43.0, 25.0), "BY": (53.7, 28.0), "CH": (46.8, 8.2),
    "CY": (35.0, 33.0), "CZ": (49.7, 15.5), "DE": (51.0, 9.0),
    "DK": (56.0, 10.0), "EE": (58.6, 25.0), "ES": (40.0, -4.0),
    "FI": (64.0, 26.0), "FO": (62.0, -7.0), "FR": (46.0, 2.0),
    "GB": (54.0, -2.0), "GI": (36.1, -5.4), "GR": (39.0, 22.0),
    "HR": (45.5, 16.0), "HU": (47.0, 19.5), "IE": (53.0, -8.0),
    "IS": (65.0, -18.0), "IT": (42.8, 12.5), "LI": (47.2, 9.5),
    "LT": (55.4, 24.0), "LU": (49.6, 6.1), "LV": (56.9, 24.6),
    "MC": (43.7, 7.4), "MD": (47.0, 28.5), "ME": (42.7, 19.3),
    "MK": (41.6, 21.7), "MT": (35.9, 14.4), "NL": (52.5, 5.5),
    "NO": (62.0, 10.0), "PL": (52.0, 19.0), "PT": (39.5, -8.0),
    "RO": (46.0, 25.0), "RS": (44.0, 21.0), "RU": (61.5, 105.0),
    "SE": (62.0, 15.0), "SI": (46.1, 14.8), "SK": (48.7, 19.5),
    "SM": (43.9, 12.4), "UA": (49.0, 32.0), "VA": (41.9, 12.4),
    # North America
    "CA": (60.0, -95.0), "MX": (23.0, -102.0), "US": (38.0, -97.0),
    # Central America & Caribbean
    "BS": (24.3, -76.0), "BZ": (17.2, -88.7), "CR": (10.0, -84.0),
    "CU": (21.5, -78.0), "DO": (19.0, -70.7), "GT": (15.5, -90.3),
    "HN": (15.0, -86.5), "HT": (19.0, -72.4), "JM": (18.1, -77.3),
    "NI": (12.9, -85.2), "PA": (9.0, -80.0), "PR": (18.2, -66.5),
    "SV": (13.7, -88.9), "TT": (10.7, -61.3),
    # South America
    "AR": (-34.0, -64.0), "BO": (-17.0, -65.0), "BR": (-10.0, -55.0),
    "CL": (-30.0, -71.0), "CO": (4.0, -72.0), "EC": (-1.4, -78.0),
    "GY": (5.0, -59.0), "PE": (-10.0, -76.0), "PY": (-23.0, -58.0),
    "SR": (4.0, -56.0), "UY": (-33.0, -56.0), "VE": (8.0, -66.0),
    # Africa
    "AO": (-12.5, 18.5), "BF": (13.0, -2.0), "BI": (-3.5, 30.0),
    "BJ": (9.5, 2.3), "BW": (-22.0, 24.0), "CD": (0.0, 25.0),
    "CF": (7.0, 21.0), "CG": (-1.0, 15.0), "CI": (8.0, -5.5),
    "CM": (6.0, 12.0), "CV": (16.0, -24.0), "DJ": (11.5, 43.0),
    "DZ": (28.0, 3.0), "EG": (27.0, 30.0), "ER": (15.0, 39.0),
    "ET": (8.0, 38.0), "GA": (-1.0, 11.7), "GH": (8.0, -1.0),
    "GM": (13.5, -16.5), "GN": (11.0, -10.0), "GQ": (1.7, 10.3),
    "GW": (12.0, -15.0), "KE": (1.0, 38.0), "KM": (-12.0, 44.0),
    "LR": (6.5, -9.5), "LS": (-29.5, 28.5), "LY": (25.0, 17.0),
    "MA": (32.0, -5.0), "MG": (-20.0, 47.0), "ML": (17.0, -4.0),
    "MR": (20.0, -12.0), "MU": (-20.3, 57.5), "MW": (-13.5, 34.0),
    "MZ": (-18.0, 35.0), "NA": (-22.0, 17.0), "NE": (16.0, 8.0),
    "NG": (10.0, 8.0), "RW": (-2.0, 30.0), "SC": (-4.6, 55.5),
    "SD": (15.0, 30.0), "SN": (14.0, -14.5), "SL": (8.5, -11.5),
    "SO": (10.0, 49.0), "SS": (8.0, 30.0), "ST": (1.0, 7.0),
    "SZ": (-26.5, 31.5), "TD": (15.0, 19.0), "TG": (8.0, 1.2),
    "TN": (34.0, 9.0), "TZ": (-6.0, 35.0), "UG": (1.0, 32.0),
    "ZA": (-29.0, 24.0), "ZM": (-15.0, 28.0), "ZW": (-19.0, 30.0),
    # Asia
    "AE": (24.0, 54.0), "AF": (33.0, 65.0), "AM": (40.0, 45.0),
    "AZ": (40.0, 47.5), "BD": (24.0, 90.0), "BH": (26.0, 50.5),
    "BN": (4.5, 114.5), "BT": (27.5, 90.5), "CN": (35.0, 105.0),
    "GE": (42.0, 43.5), "HK": (22.3, 114.2), "ID": (-2.0, 118.0),
    "IL": (31.5, 35.0), "IN": (21.0, 78.0), "IQ": (33.0, 44.0),
    "IR": (32.0, 53.0), "JO": (31.0, 36.0), "JP": (36.0, 138.0),
    "KG": (41.0, 75.0), "KH": (13.0, 105.0), "KP": (40.0, 127.0),
    "KR": (37.0, 127.5), "KW": (29.5, 47.5), "KZ": (48.0, 68.0),
    "LA": (18.0, 105.0), "LB": (33.8, 35.8), "LK": (7.0, 81.0),
    "MM": (22.0, 98.0), "MN": (46.0, 105.0), "MO": (22.2, 113.5),
    "MV": (3.2, 73.2), "MY": (2.5, 112.5), "NP": (28.0, 84.0),
    "OM": (21.0, 57.0), "PH": (13.0, 122.0), "PK": (30.0, 70.0),
    "PS": (32.0, 35.3), "QA": (25.5, 51.2), "SA": (25.0, 45.0),
    "SG": (1.4, 103.8), "SY": (35.0, 38.0), "TH": (15.0, 100.0),
    "TJ": (39.0, 71.0), "TL": (-8.6, 125.5), "TM": (40.0, 60.0),
    "TR": (39.0, 35.0), "TW": (23.5, 121.0), "UZ": (41.5, 64.0),
    "VN": (16.0, 106.0), "YE": (15.0, 48.0),
    # Oceania
    "AU": (-25.0, 135.0), "FJ": (-18.0, 178.0), "NC": (-21.5, 165.5),
    "NZ": (-41.0, 174.0), "PF": (-17.6, -149.4), "PG": (-6.0, 147.0),
    "SB": (-9.6, 160.0), "VU": (-16.0, 167.0), "WS": (-13.6, -172.4),
}


# ============================================================
# Bogon networks (RFC 6890 + reserved). Used by R16.
# ============================================================

BOGON_CIDRS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
]


# ============================================================
# Regex / parsing helpers
# ============================================================

PRIVATE_REGION_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$")
ISO2_RE = re.compile(r"^[A-Z]{2}$")
LOGIN_RE = re.compile(r"^([A-Za-z]{3,9})\.\s*(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
FILENAME_DATE_RE = re.compile(r"_(\d{2})(\d{2})(\d{4})_\d{6}gmt", re.IGNORECASE)

MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12,
}


def parse_login_token(token, anchor):
    """Parse 'Apr.27 07:29:09' into a datetime, inferring year from ``anchor``.

    Returns ``None`` on any parse failure (caller decides what to do)."""
    if not token:
        return None
    m = LOGIN_RE.match(token.strip())
    if not m:
        return None
    mon_tok, day_s, hh, mm, ss = m.groups()
    mon = MONTH_MAP.get(mon_tok.lower())
    if mon is None:
        mon = MONTH_MAP.get(mon_tok.lower()[:3])
    if mon is None:
        return None
    try:
        day = int(day_s)
        year = anchor.year if (mon, day) <= (anchor.month, anchor.day) else anchor.year - 1
        return dt.datetime(year, mon, day, int(hh), int(mm), int(ss))
    except ValueError:
        return None


def haversine_km(a, b):
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))


def is_private_region(region):
    return bool(region and PRIVATE_REGION_RE.match(region))


def is_iso2_region(region):
    return bool(region and ISO2_RE.match(region))


def detect_baseline_region(sessions):
    """Pick the user's 'home' region from the data: the most common ISO-2
    Source Region across all sessions. Returns None if none found
    (caller should treat 'no baseline' gracefully)."""
    counts = Counter()
    for s in sessions:
        r = s.get("Source Region")
        if is_iso2_region(r):
            counts[r] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def _ip_to_int(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in nums):
        return None
    return (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]


_BOGON_PARSED = None


def _parsed_bogons():
    global _BOGON_PARSED
    if _BOGON_PARSED is None:
        out = []
        for net in BOGON_CIDRS:
            ip, bits = net.split("/")
            base = _ip_to_int(ip) or 0
            bits = int(bits)
            mask = ((1 << 32) - 1) ^ ((1 << (32 - bits)) - 1) if bits else 0
            out.append((base & mask, mask))
        _BOGON_PARSED = out
    return _BOGON_PARSED


def is_bogon_ip(ip):
    n = _ip_to_int(ip)
    if n is None:
        return False
    for base, mask in _parsed_bogons():
        if (n & mask) == base:
            return True
    return False


def make_session_id(*parts):
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:12]


def fmt_dt(d):
    return d.strftime("%Y-%m-%d %H:%M:%S") if d else ""


def parse_anchor_arg(s):
    return dt.date.fromisoformat(s)


# ============================================================
# Loading + dedupe
# ============================================================

REQUIRED_COLS = {
    "Domain", "User", "Computer", "Public IP", "Source Region",
    "Tunnel Type", "Login At",
}

OUTPUT_FIELDS = [
    "_id", "Domain", "User", "Primary Username", "Computer", "Client",
    "Private IP", "Public IP", "Source Region", "Tunnel Type",
    "Login At", "Logout At", "Status", "Lifetime (S)", "_file",
]


def detect_anchor_from_filename(filename):
    m = FILENAME_DATE_RE.search(os.path.basename(filename))
    if not m:
        return None
    mm, dd, yyyy = (int(x) for x in m.groups())
    try:
        return dt.date(yyyy, mm, dd)
    except ValueError:
        return None


def load_csvs(input_dir, anchor_override, logger, max_rows=None):
    """Read every CSV in ``input_dir``; return ``(sessions, parse_errors)``.

    Each session is a dict with the original CSV columns plus internal
    underscore-prefixed fields used by analysis (datetimes, flags). Year is
    inferred from the filename anchor (or from ``anchor_override`` when set).

    If ``max_rows`` is set and the cumulative number of accepted session
    rows exceeds that cap, loading aborts with ``SystemExit``. This is a
    safety net against accidentally pointing the tool at a directory with
    far more data than the per-user O(n^2) rules can analyze in
    reasonable time. Pass ``None`` (or 0) to disable the cap.
    """
    pattern = os.path.join(input_dir, "*.csv")
    consolidated_stem = os.path.splitext(CONSOLIDATED_CSV)[0]

    def _is_own_output(basename):
        # Skip the canonical consolidated CSV and any archived variant
        # (e.g. 'consolidated_sessions.20260427T123012.csv'). They share the
        # consolidated schema, not the GP export schema, so feeding them back
        # in produces 100% parse errors.
        if basename == CONSOLIDATED_CSV:
            return True
        return (basename.startswith(consolidated_stem + ".")
                and basename.endswith(".csv"))

    files = sorted(f for f in glob.glob(pattern)
                   if not _is_own_output(os.path.basename(f)))
    if not files:
        raise SystemExit("No CSV files found in {0!r}".format(input_dir))

    sessions = []
    errors = []

    for f in files:
        if anchor_override:
            anchor = anchor_override
        else:
            anchor = detect_anchor_from_filename(f) or dt.date.today()

        with open(f, encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            cols = set(reader.fieldnames or [])
            missing = REQUIRED_COLS - cols
            if missing:
                logger.warning("Skipping %s — missing columns: %s",
                               os.path.basename(f), sorted(missing))
                continue
            has_lifetime = "Lifetime (S)" in cols
            has_logout = "Logout At" in cols

            for row in reader:
                login_dt = parse_login_token(row.get("Login At", ""), anchor)
                if not login_dt:
                    errors.append({
                        "file": os.path.basename(f),
                        "reason": "unparseable Login At",
                        "row": dict(row),
                    })
                    continue

                ongoing = False
                logout_dt = None
                lifetime_s = None
                corrupt = False

                if has_logout and (row.get("Logout At") or "").strip():
                    logout_dt = parse_login_token(row.get("Logout At", ""), anchor)
                    if logout_dt is None:
                        errors.append({
                            "file": os.path.basename(f),
                            "reason": "unparseable Logout At",
                            "row": dict(row),
                        })
                        # keep the session anyway, mark corrupt for R14
                        corrupt = True
                    else:
                        if logout_dt < login_dt:
                            corrupt = True
                        lifetime_s = int((logout_dt - login_dt).total_seconds())
                elif has_lifetime:
                    ongoing = True
                    raw = (row.get("Lifetime (S)") or "").strip()
                    try:
                        lifetime_s = int(raw) if raw else None
                    except ValueError:
                        lifetime_s = None
                else:
                    # No way to derive end of session
                    ongoing = True

                user = (row.get("User") or "").strip()
                computer = (row.get("Computer") or "").strip()
                pub_ip = (row.get("Public IP") or "").strip()
                priv_ip = (row.get("Private IP") or "").strip()
                region = (row.get("Source Region") or "").strip()
                tunnel = (row.get("Tunnel Type") or "").strip()
                client = (row.get("Client") or "").strip()
                domain = (row.get("Domain") or "").strip()
                primary = (row.get("Primary Username") or "").strip()

                sid = make_session_id(user, computer, fmt_dt(login_dt), pub_ip)

                sessions.append({
                    "_id": sid,
                    "_file": os.path.basename(f),
                    "Domain": domain,
                    "User": user,
                    "Primary Username": primary,
                    "Computer": computer,
                    "Client": client,
                    "Private IP": priv_ip,
                    "Public IP": pub_ip,
                    "Source Region": region,
                    "Tunnel Type": tunnel,
                    "Login At": fmt_dt(login_dt),
                    "Logout At": fmt_dt(logout_dt) if logout_dt else "",
                    "Status": "ongoing" if ongoing else "closed",
                    "Lifetime (S)": "" if lifetime_s is None else str(lifetime_s),
                    # Internal fields
                    "_login_dt": login_dt,
                    "_logout_dt": logout_dt,
                    "_ongoing": ongoing,
                    "_corrupt": corrupt,
                })

                if max_rows and len(sessions) > max_rows:
                    raise SystemExit(
                        "Aborting: more than {0} session rows loaded. "
                        "Raise --max-rows (or pass --max-rows 0 to "
                        "disable the cap) if this is intentional.".format(
                            max_rows))

    deduped = dedupe_sessions(sessions)
    deduped.sort(key=lambda r: (r["_login_dt"], r.get("Logout At") or ""))
    return deduped, errors


def dedupe_sessions(sessions):
    """Dedupe by (User, Computer, Login At, Public IP). Closed > ongoing."""
    by_key = {}
    for s in sessions:
        k = (s["User"], s["Computer"], s["Login At"], s["Public IP"])
        existing = by_key.get(k)
        if existing is None:
            by_key[k] = s
            continue
        # keep the closed (logout known) one
        if existing["_ongoing"] and not s["_ongoing"]:
            by_key[k] = s
    return list(by_key.values())


# ============================================================
# Analysis: each rule is a generator-like fn returning findings.
# Findings are dicts: rule_id, severity, user, description, evidence (list
# of session ids), window_start, window_end, extra (free-form).
# ============================================================


def _logout_or_inf(s):
    return s["_logout_dt"] if s["_logout_dt"] is not None else dt.datetime.max


def _make_finding(rule_id, user, description, evidence,
                  window_start=None, window_end=None,
                  severity=None, extra=None):
    if severity is None:
        severity = RULE_CATALOG[rule_id][1]
    return {
        "rule_id": rule_id,
        "rule_name": RULE_CATALOG[rule_id][0],
        "severity": severity,
        "user": user,
        "description": description,
        "evidence": list(evidence),
        "window_start": fmt_dt(window_start) if window_start else "",
        "window_end": fmt_dt(window_end) if window_end else "",
        "extra": extra or {},
    }


def overlap_pairs_per_user(user_sessions):
    s = sorted(user_sessions, key=lambda x: x["_login_dt"])
    active = []
    pairs = []
    for cur in s:
        cur_login = cur["_login_dt"]
        active = [a for a in active if _logout_or_inf(a) > cur_login]
        for prev in active:
            pairs.append((prev, cur))
        active.append(cur)
    return pairs


def rule_R01_simul_public_ip(by_user):
    findings = []
    for user, sess in by_user.items():
        for a, b in overlap_pairs_per_user(sess):
            ip_a, ip_b = a["Public IP"], b["Public IP"]
            if ip_a and ip_b and ip_a != ip_b:
                findings.append(_make_finding(
                    "R01", user,
                    "Concurrent sessions with different Public IPs: "
                    "{0} and {1}.".format(ip_a, ip_b),
                    [a["_id"], b["_id"]],
                    window_start=max(a["_login_dt"], b["_login_dt"]),
                    window_end=min(_logout_or_inf(a), _logout_or_inf(b)),
                    extra={"ip_a": ip_a, "ip_b": ip_b,
                           "region_a": a["Source Region"],
                           "region_b": b["Source Region"]},
                ))
    return findings


def rule_R02_simul_region(by_user):
    findings = []
    for user, sess in by_user.items():
        for a, b in overlap_pairs_per_user(sess):
            ra, rb = a["Source Region"], b["Source Region"]
            if ra and rb and ra != rb:
                findings.append(_make_finding(
                    "R02", user,
                    "Concurrent sessions with different Source Region: "
                    "{0} and {1}.".format(ra, rb),
                    [a["_id"], b["_id"]],
                    window_start=max(a["_login_dt"], b["_login_dt"]),
                    window_end=min(_logout_or_inf(a), _logout_or_inf(b)),
                    extra={"region_a": ra, "region_b": rb,
                           "ip_a": a["Public IP"], "ip_b": b["Public IP"]},
                ))
    return findings


def rule_R03_impossible_travel(by_user):
    findings = []
    speed_limit = THRESHOLDS["impossible_travel_kmh"]
    for user, sess in by_user.items():
        s = sorted(sess, key=lambda x: x["_login_dt"])
        for i in range(len(s) - 1):
            a, b = s[i], s[i + 1]
            ra, rb = a["Source Region"], b["Source Region"]
            if not (is_iso2_region(ra) and is_iso2_region(rb)):
                continue
            if ra == rb:
                continue
            ca = COUNTRY_CENTROIDS.get(ra)
            cb = COUNTRY_CENTROIDS.get(rb)
            if not ca or not cb:
                continue
            dist = haversine_km(ca, cb)
            delta = (b["_login_dt"] - a["_login_dt"]).total_seconds() / 3600.0
            if delta <= 0:
                continue
            speed = dist / delta
            if speed > speed_limit:
                findings.append(_make_finding(
                    "R03", user,
                    "Impossible travel between {0} and {1}: ~{2:.0f} km in "
                    "{3:.1f} h -> {4:.0f} km/h.".format(
                        ra, rb, dist, delta, speed),
                    [a["_id"], b["_id"]],
                    window_start=a["_login_dt"], window_end=b["_login_dt"],
                    extra={"region_a": ra, "region_b": rb,
                           "distance_km": round(dist, 1),
                           "delta_hours": round(delta, 2),
                           "speed_kmh": round(speed, 1)},
                ))
    return findings


def rule_R04_unusual_region(by_user):
    findings = []
    K = THRESHOLDS["user_baseline_top_k"]
    for user, sess in by_user.items():
        counts = Counter()
        for s in sess:
            if is_iso2_region(s["Source Region"]):
                counts[s["Source Region"]] += 1
        if not counts:
            continue
        top = {r for r, _ in counts.most_common(K)}
        flagged = []
        for s in sess:
            r = s["Source Region"]
            if is_iso2_region(r) and r not in top:
                flagged.append(s)
        if not flagged:
            continue
        # one finding per (user, region) so the dashboard can drill in
        per_region = defaultdict(list)
        for s in flagged:
            per_region[s["Source Region"]].append(s)
        for region, ss in per_region.items():
            ss.sort(key=lambda x: x["_login_dt"])
            findings.append(_make_finding(
                "R04", user,
                "{0} sessions from {1} (not in user's habitual top-{2}: {3}).".format(
                    len(ss), region, K, ", ".join(sorted(top)) or "-"),
                [s["_id"] for s in ss],
                window_start=ss[0]["_login_dt"],
                window_end=ss[-1]["_login_dt"],
                extra={"region": region, "count": len(ss),
                       "user_top_regions": sorted(top)},
            ))
    return findings


def rule_R05_multi_computer(by_user):
    findings = []
    minc = THRESHOLDS["multi_computer_min"]
    for user, sess in by_user.items():
        by_day = defaultdict(set)
        evidence_by_day = defaultdict(list)
        for s in sess:
            d = s["_login_dt"].date()
            if s["Computer"]:
                by_day[d].add(s["Computer"])
                evidence_by_day[d].append(s)
        for day, comps in by_day.items():
            if len(comps) >= minc:
                ev = evidence_by_day[day]
                ev.sort(key=lambda x: x["_login_dt"])
                findings.append(_make_finding(
                    "R05", user,
                    "{0} distinct computers on {1}: {2}.".format(
                        len(comps), day.isoformat(), ", ".join(sorted(comps))),
                    [s["_id"] for s in ev],
                    window_start=ev[0]["_login_dt"],
                    window_end=ev[-1]["_login_dt"],
                    extra={"date": day.isoformat(),
                           "computers": sorted(comps)},
                ))
    return findings


def rule_R06_first_seen_ip(by_user):
    findings = []
    for user, sess in by_user.items():
        s = sorted(sess, key=lambda x: x["_login_dt"])
        seen = set()
        for cur in s:
            ip = cur["Public IP"]
            if not ip:
                continue
            if seen and ip not in seen:
                findings.append(_make_finding(
                    "R06", user,
                    "First appearance of Public IP {0} for this user.".format(ip),
                    [cur["_id"]],
                    window_start=cur["_login_dt"],
                    window_end=cur["_login_dt"],
                    extra={"new_ip": ip, "region": cur["Source Region"]},
                ))
            seen.add(ip)
    return findings


def rule_R07_long_session(by_user):
    findings = []
    threshold = THRESHOLDS["long_session_seconds"]
    for user, sess in by_user.items():
        for s in sess:
            if s["_ongoing"] or s["_logout_dt"] is None:
                continue
            dur = (s["_logout_dt"] - s["_login_dt"]).total_seconds()
            if dur >= threshold:
                findings.append(_make_finding(
                    "R07", user,
                    "Session lasted {0:.1f} h.".format(dur / 3600),
                    [s["_id"]],
                    window_start=s["_login_dt"],
                    window_end=s["_logout_dt"],
                    extra={"duration_seconds": int(dur)},
                ))
    return findings


def _is_off_hour(d):
    h = d.hour
    start = THRESHOLDS["off_hours_start"]
    end = THRESHOLDS["off_hours_end"]
    return h >= start or h < end


def rule_R08_off_hours(by_user):
    findings = []
    minc = THRESHOLDS["off_hours_min_count"]
    for user, sess in by_user.items():
        off = [s for s in sess if _is_off_hour(s["_login_dt"])]
        if len(off) >= minc:
            off.sort(key=lambda x: x["_login_dt"])
            findings.append(_make_finding(
                "R08", user,
                "{0} logins outside working hours ({1:02d}:00-{2:02d}:00).".format(
                    len(off),
                    THRESHOLDS["off_hours_start"],
                    THRESHOLDS["off_hours_end"]),
                [s["_id"] for s in off[:50]],
                window_start=off[0]["_login_dt"],
                window_end=off[-1]["_login_dt"],
                extra={"count": len(off),
                       "total_sessions": len(sess)},
            ))
    return findings


def rule_R09_shared_computer(all_sessions):
    findings = []
    by_computer = defaultdict(set)
    sess_by_computer = defaultdict(list)
    for s in all_sessions:
        if s["Computer"] and s["User"]:
            by_computer[s["Computer"]].add(s["User"])
            sess_by_computer[s["Computer"]].append(s)
    for comp, users in by_computer.items():
        if len(users) >= 2:
            ss = sorted(sess_by_computer[comp], key=lambda x: x["_login_dt"])
            user_list = sorted(users)
            for u in user_list:
                ev = [s for s in ss if s["User"] == u]
                findings.append(_make_finding(
                    "R09", u,
                    "Computer {0!r} used by {1} distinct users: {2}.".format(
                        comp, len(users), ", ".join(user_list)),
                    [s["_id"] for s in ev[:30]],
                    window_start=ev[0]["_login_dt"] if ev else None,
                    window_end=ev[-1]["_login_dt"] if ev else None,
                    extra={"computer": comp, "users": user_list},
                ))
    return findings


def rule_R10_private_region(by_user):
    findings = []
    for user, sess in by_user.items():
        priv = [s for s in sess if is_private_region(s["Source Region"])]
        if not priv:
            continue
        per_range = defaultdict(list)
        for s in priv:
            per_range[s["Source Region"]].append(s)
        for rng, ss in per_range.items():
            ss.sort(key=lambda x: x["_login_dt"])
            findings.append(_make_finding(
                "R10", user,
                "{0} sessions with Source Region == {1!r} (geoip unresolved).".format(
                    len(ss), rng),
                [s["_id"] for s in ss[:50]],
                window_start=ss[0]["_login_dt"],
                window_end=ss[-1]["_login_dt"],
                extra={"private_range": rng, "count": len(ss)},
            ))
    return findings


def rule_R11_client_change(by_user):
    findings = []
    W = dt.timedelta(hours=24)
    for user, sess in by_user.items():
        s = sorted(sess, key=lambda x: x["_login_dt"])
        for i in range(len(s)):
            a = s[i]
            for j in range(i + 1, len(s)):
                b = s[j]
                if b["_login_dt"] - a["_login_dt"] > W:
                    break
                if (a["Client"] and b["Client"] and a["Client"] != b["Client"]
                        and a["Source Region"] != b["Source Region"]
                        and is_iso2_region(a["Source Region"])
                        and is_iso2_region(b["Source Region"])):
                    findings.append(_make_finding(
                        "R11", user,
                        "Client change {0!r} -> {1!r} with region change {2}->{3} within 24h.".format(
                            a["Client"], b["Client"],
                            a["Source Region"], b["Source Region"]),
                        [a["_id"], b["_id"]],
                        window_start=a["_login_dt"], window_end=b["_login_dt"],
                        extra={"client_a": a["Client"], "client_b": b["Client"],
                               "region_a": a["Source Region"],
                               "region_b": b["Source Region"]},
                    ))
                    break  # avoid combinatorial explosion per i
    return findings


def rule_R12_shared_public_ip(all_sessions):
    findings = []
    by_ip = defaultdict(list)
    for s in all_sessions:
        if s["Public IP"]:
            by_ip[s["Public IP"]].append(s)
    threshold = THRESHOLDS["shared_ip_user_threshold"]
    for ip, ss in by_ip.items():
        users = sorted({s["User"] for s in ss if s["User"]})
        if len(users) > threshold:
            ss.sort(key=lambda x: x["_login_dt"])
            for u in users:
                ev = [s for s in ss if s["User"] == u]
                findings.append(_make_finding(
                    "R12", u,
                    "Public IP {0} shared with {1} users: {2}.".format(
                        ip, len(users), ", ".join(users[:8])
                        + ("..." if len(users) > 8 else "")),
                    [s["_id"] for s in ev[:30]],
                    window_start=ev[0]["_login_dt"] if ev else None,
                    window_end=ev[-1]["_login_dt"] if ev else None,
                    extra={"public_ip": ip, "user_count": len(users),
                           "users": users[:50]},
                ))
    return findings


def rule_R13_lifetime_max(by_user):
    findings = []
    threshold = THRESHOLDS["lifetime_max_seconds"]
    for user, sess in by_user.items():
        for s in sess:
            life = s["Lifetime (S)"]
            if not life:
                continue
            try:
                v = int(life)
            except ValueError:
                continue
            if v > threshold:
                findings.append(_make_finding(
                    "R13", user,
                    "Lifetime of {0:.1f} h exceeds maximum policy ({1:.0f} h).".format(
                        v / 3600, threshold / 3600),
                    [s["_id"]],
                    window_start=s["_login_dt"],
                    window_end=s["_logout_dt"] or s["_login_dt"],
                    extra={"lifetime_seconds": v},
                ))
    return findings


def rule_R14_corrupt(all_sessions, parse_errors):
    findings = []
    by_user = defaultdict(list)
    for s in all_sessions:
        if s.get("_corrupt"):
            by_user[s["User"]].append(s)
    for user, ss in by_user.items():
        ss.sort(key=lambda x: x["_login_dt"])
        findings.append(_make_finding(
            "R14", user,
            "{0} corrupt row(s): Logout < Login or unparseable.".format(len(ss)),
            [s["_id"] for s in ss[:50]],
            window_start=ss[0]["_login_dt"],
            window_end=ss[-1]["_login_dt"],
            extra={"count": len(ss)},
        ))
    if parse_errors:
        findings.append(_make_finding(
            "R14", "(global)",
            "{0} row(s) impossible to parse (see logs).".format(len(parse_errors)),
            [],
            extra={"count": len(parse_errors),
                   "samples": [e.get("reason") for e in parse_errors[:5]]},
        ))
    return findings


def rule_R15_multi_domain(all_sessions):
    findings = []
    by_user_domain = defaultdict(set)
    sess_by_user = defaultdict(list)
    for s in all_sessions:
        if s["User"]:
            by_user_domain[s["User"]].add(s["Domain"])
            sess_by_user[s["User"]].append(s)
    for user, ds in by_user_domain.items():
        if len(ds) > 1:
            ev = sorted(sess_by_user[user], key=lambda x: x["_login_dt"])
            findings.append(_make_finding(
                "R15", user,
                "Different Domains for the same user: {0}.".format(
                    ", ".join(sorted(ds))),
                [s["_id"] for s in ev[:30]],
                window_start=ev[0]["_login_dt"],
                window_end=ev[-1]["_login_dt"],
                extra={"domains": sorted(ds)},
            ))
    return findings


def rule_R16_bogon(all_sessions):
    findings = []
    by_user_ip = defaultdict(list)
    for s in all_sessions:
        ip = s["Public IP"]
        if ip and is_bogon_ip(ip):
            by_user_ip[(s["User"], ip)].append(s)
    for (user, ip), ss in by_user_ip.items():
        ss.sort(key=lambda x: x["_login_dt"])
        findings.append(_make_finding(
            "R16", user,
            "Non-routable / bogon Public IP: {0} ({1} sessions).".format(ip, len(ss)),
            [s["_id"] for s in ss[:30]],
            window_start=ss[0]["_login_dt"],
            window_end=ss[-1]["_login_dt"],
            extra={"public_ip": ip, "count": len(ss)},
        ))
    return findings


def rule_R17_beaconing(by_user):
    findings = []
    min_streak = THRESHOLDS["beacon_min_streak"]
    max_period = THRESHOLDS["beacon_max_period_seconds"]
    tol = THRESHOLDS["beacon_period_tolerance_pct"]
    for user, sess in by_user.items():
        by_uc = defaultdict(list)
        for s in sess:
            if s["Computer"]:
                by_uc[s["Computer"]].append(s)
        for computer, ss in by_uc.items():
            ss.sort(key=lambda x: x["_login_dt"])
            if len(ss) < min_streak + 1:
                continue
            deltas = []
            for i in range(1, len(ss)):
                d = (ss[i]["_login_dt"] - ss[i - 1]["_login_dt"]).total_seconds()
                deltas.append(d)
            if not deltas:
                continue
            try:
                med = statistics.median(deltas)
            except statistics.StatisticsError:
                continue
            if med <= 0 or med > max_period:
                continue
            tol_abs = med * tol
            streak = 0
            best = 0
            best_idx_end = 0
            for idx, d in enumerate(deltas):
                if abs(d - med) <= tol_abs:
                    streak += 1
                    if streak > best:
                        best = streak
                        best_idx_end = idx
                else:
                    streak = 0
            if best >= min_streak:
                start_idx = best_idx_end - best + 1
                ev = ss[start_idx:best_idx_end + 2]
                findings.append(_make_finding(
                    "R17", user,
                    "Beaconing on {0!r}: {1} reconnections every ~{2:.0f}s ({3} events).".format(
                        computer, best, med, best + 1),
                    [s["_id"] for s in ev],
                    window_start=ev[0]["_login_dt"],
                    window_end=ev[-1]["_login_dt"],
                    extra={"computer": computer,
                           "median_period_seconds": round(med, 1),
                           "streak_length": best},
                ))
    return findings


def rule_R18_new_user_outside_baseline(by_user, baseline_region):
    findings = []
    if not baseline_region:
        # No baseline known (empty dataset / no ISO-2 regions). Nothing to
        # compare against, so we skip silently.
        return findings
    cap = THRESHOLDS["first_seen_max_sessions"]
    for user, sess in by_user.items():
        if len(sess) > cap:
            continue
        s = sorted(sess, key=lambda x: x["_login_dt"])
        first = s[0]
        if (is_iso2_region(first["Source Region"])
                and first["Source Region"] != baseline_region):
            findings.append(_make_finding(
                "R18", user,
                "User with very few sessions in the dataset and first "
                "activity from {0} (!= baseline {1}).".format(
                    first["Source Region"], baseline_region),
                [s_["_id"] for s_ in s],
                window_start=s[0]["_login_dt"],
                window_end=s[-1]["_login_dt"],
                extra={"first_region": first["Source Region"],
                       "session_count": len(sess)},
            ))
    return findings


def rule_R19_login_burst(by_user):
    findings = []
    window = THRESHOLDS["burst_window_seconds"]
    minc = THRESHOLDS["burst_min_logins"]
    for user, sess in by_user.items():
        s = sorted(sess, key=lambda x: x["_login_dt"])
        n = len(s)
        if n < minc:
            continue
        # sliding window over login times
        i = 0
        emitted = set()  # avoid emitting overlapping bursts
        for j in range(n):
            while (s[j]["_login_dt"] - s[i]["_login_dt"]).total_seconds() > window:
                i += 1
            count = j - i + 1
            if count >= minc and i not in emitted:
                ev = s[i:j + 1]
                findings.append(_make_finding(
                    "R19", user,
                    "{0} logins within {1}s window (start {2}).".format(
                        count, window, ev[0]["_login_dt"].isoformat(" ")),
                    [e["_id"] for e in ev[:50]],
                    window_start=ev[0]["_login_dt"],
                    window_end=ev[-1]["_login_dt"],
                    extra={"count": count,
                           "window_seconds": window},
                ))
                emitted.add(i)
                # advance past this burst to avoid an emit per shifted index
                i = j + 1
    return findings


def rule_R20_tunnel_flap(by_user):
    findings = []
    window = THRESHOLDS["tunnel_flap_window_seconds"]
    min_switches = THRESHOLDS["tunnel_flap_min_switches"]
    for user, sess in by_user.items():
        by_comp = defaultdict(list)
        for s in sess:
            if s["Computer"] and s["Tunnel Type"]:
                by_comp[s["Computer"]].append(s)
        for comp, ss in by_comp.items():
            ss.sort(key=lambda x: x["_login_dt"])
            if len(ss) < min_switches + 1:
                continue
            # sliding window: count tunnel-type switches inside it
            i = 0
            emitted = False
            for j in range(1, len(ss)):
                while (ss[j]["_login_dt"] - ss[i]["_login_dt"]).total_seconds() > window:
                    i += 1
                switches = sum(
                    1 for k in range(i + 1, j + 1)
                    if ss[k]["Tunnel Type"] != ss[k - 1]["Tunnel Type"])
                if switches >= min_switches and not emitted:
                    ev = ss[i:j + 1]
                    tunnels = [e["Tunnel Type"] for e in ev]
                    findings.append(_make_finding(
                        "R20", user,
                        "Tunnel Type flapping on {0!r}: {1} switches in {2:.1f}h "
                        "({3}).".format(
                            comp, switches,
                            (ev[-1]["_login_dt"] - ev[0]["_login_dt"]).total_seconds() / 3600,
                            "->".join(tunnels[:8])
                            + ("..." if len(tunnels) > 8 else "")),
                        [e["_id"] for e in ev[:50]],
                        window_start=ev[0]["_login_dt"],
                        window_end=ev[-1]["_login_dt"],
                        extra={"computer": comp, "switches": switches,
                               "tunnels": tunnels},
                    ))
                    emitted = True
                    break
    return findings


def rule_R21_new_computer(by_user):
    findings = []
    min_history = THRESHOLDS["new_computer_min_history"]
    for user, sess in by_user.items():
        s = sorted(sess, key=lambda x: x["_login_dt"])
        seen = set()
        for idx, cur in enumerate(s):
            comp = cur["Computer"]
            if not comp:
                continue
            if comp not in seen and idx >= min_history:
                findings.append(_make_finding(
                    "R21", user,
                    "New Computer {0!r} after {1} prior session(s) on {2} other "
                    "Computer(s): {3}.".format(
                        comp, idx, len(seen),
                        ", ".join(sorted(seen)[:5])
                        + ("..." if len(seen) > 5 else "")),
                    [cur["_id"]],
                    window_start=cur["_login_dt"],
                    window_end=cur["_login_dt"],
                    extra={"new_computer": comp,
                           "prior_session_count": idx,
                           "prior_computers": sorted(seen)},
                ))
            seen.add(comp)
    return findings


def rule_R22_dormant_resurfacing(by_user):
    findings = []
    min_days = THRESHOLDS["dormant_min_days"]
    min_resurfacing = THRESHOLDS["dormant_min_resurfacing_sessions"]
    min_prior = THRESHOLDS["dormant_min_prior_sessions"]
    gap = dt.timedelta(days=min_days)
    for user, sess in by_user.items():
        s = sorted(sess, key=lambda x: x["_login_dt"])
        if len(s) < 2:
            continue
        for i in range(1, len(s)):
            if i < min_prior:
                continue
            delta = s[i]["_login_dt"] - s[i - 1]["_login_dt"]
            if delta >= gap:
                # collect resurfacing sessions: everything from i within 7 days
                horizon = s[i]["_login_dt"] + dt.timedelta(days=7)
                ev = [x for x in s[i:] if x["_login_dt"] <= horizon]
                if len(ev) < min_resurfacing:
                    continue
                findings.append(_make_finding(
                    "R22", user,
                    "User dormant for {0:.1f} days, then resurfaced "
                    "with {1} session(s) from {2}.".format(
                        delta.total_seconds() / 86400.0,
                        len(ev), ev[0]["Source Region"] or "unknown"),
                    [e["_id"] for e in ev[:30]],
                    window_start=s[i - 1]["_login_dt"],
                    window_end=ev[-1]["_login_dt"],
                    extra={"gap_days": round(delta.total_seconds() / 86400.0, 2),
                           "last_seen": s[i - 1]["_login_dt"].isoformat(" "),
                           "resurfacing_region": ev[0]["Source Region"],
                           "resurfacing_count": len(ev)},
                ))
                break  # one finding per user is enough
    return findings


def rule_R23_weekend_for_weekday_user(by_user):
    findings = []
    min_weekday = THRESHOLDS["weekday_only_min_weekday"]
    max_ratio = THRESHOLDS["weekday_only_max_weekend_ratio"]
    for user, sess in by_user.items():
        weekday = [s for s in sess if s["_login_dt"].weekday() < 5]
        weekend = [s for s in sess if s["_login_dt"].weekday() >= 5]
        if not weekend:
            continue
        if len(weekday) < min_weekday:
            continue
        ratio = len(weekend) / len(weekday)
        if ratio > max_ratio:
            continue
        weekend.sort(key=lambda x: x["_login_dt"])
        findings.append(_make_finding(
            "R23", user,
            "{0} weekend session(s) for a weekday-baselined user "
            "({1} weekday, weekend/weekday ratio {2:.2f}).".format(
                len(weekend), len(weekday), ratio),
            [s["_id"] for s in weekend[:30]],
            window_start=weekend[0]["_login_dt"],
            window_end=weekend[-1]["_login_dt"],
            extra={"weekend_count": len(weekend),
                   "weekday_count": len(weekday),
                   "ratio": round(ratio, 4)},
        ))
    return findings


def run_all_rules(sessions, parse_errors, baseline_region, logger):
    by_user = defaultdict(list)
    for s in sessions:
        if s["User"]:
            by_user[s["User"]].append(s)

    findings = []
    findings += rule_R01_simul_public_ip(by_user)
    findings += rule_R02_simul_region(by_user)
    findings += rule_R03_impossible_travel(by_user)
    findings += rule_R04_unusual_region(by_user)
    findings += rule_R05_multi_computer(by_user)
    findings += rule_R06_first_seen_ip(by_user)
    findings += rule_R07_long_session(by_user)
    findings += rule_R08_off_hours(by_user)
    findings += rule_R09_shared_computer(sessions)
    findings += rule_R10_private_region(by_user)
    findings += rule_R11_client_change(by_user)
    findings += rule_R12_shared_public_ip(sessions)
    findings += rule_R13_lifetime_max(by_user)
    findings += rule_R14_corrupt(sessions, parse_errors)
    findings += rule_R15_multi_domain(sessions)
    findings += rule_R16_bogon(sessions)
    findings += rule_R17_beaconing(by_user)
    findings += rule_R18_new_user_outside_baseline(by_user, baseline_region)
    findings += rule_R19_login_burst(by_user)
    findings += rule_R20_tunnel_flap(by_user)
    findings += rule_R21_new_computer(by_user)
    findings += rule_R22_dormant_resurfacing(by_user)
    findings += rule_R23_weekend_for_weekday_user(by_user)

    # Stable id per finding
    for i, f in enumerate(findings):
        h = hashlib.sha1(
            "|".join([f["rule_id"], f["user"], f["description"],
                      ",".join(f["evidence"][:5])]).encode()
        ).hexdigest()[:10]
        f["_id"] = "F{0:05d}-{1}".format(i, h)

    findings.sort(
        key=lambda f: (-SEVERITY_RANK[f["severity"]], f["user"], f["rule_id"]))
    logger.info("Generated %d findings across %d rules over %d sessions.",
                len(findings), len(RULE_CATALOG), len(sessions))
    return findings


# ============================================================
# CSV output
# ============================================================

# Cells starting with these characters can be interpreted as formulas /
# DDE payloads when the CSV is opened in Excel, LibreOffice, or Google
# Sheets. Prefixing with a single quote neutralizes the formula while
# keeping the cell visually identical.
_CSV_FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    s = "" if value is None else str(value)
    if s.startswith(_CSV_FORMULA_CHARS):
        return "'" + s
    return s


def write_consolidated_csv(path, sessions):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        # Re-key to a clean column set; underscore-prefixed fields are
        # internal except _id and _file which give traceability.
        cols = ["session_id", "Domain", "User", "Primary Username",
                "Computer", "Client", "Private IP", "Public IP",
                "Source Region", "Tunnel Type", "Login At", "Logout At",
                "Status", "Lifetime (S)", "source_file"]
        w.writerow(cols)
        for s in sessions:
            w.writerow([_csv_safe(v) for v in (
                s["_id"], s["Domain"], s["User"], s["Primary Username"],
                s["Computer"], s["Client"], s["Private IP"],
                s["Public IP"], s["Source Region"], s["Tunnel Type"],
                s["Login At"], s["Logout At"], s["Status"],
                s["Lifetime (S)"], s["_file"])])


# ============================================================
# Build payload for HTML
# ============================================================

def build_payload(sessions, findings, baseline_region):
    # Slim down sessions for the JSON payload — drop internals.
    sess_out = []
    for s in sessions:
        sess_out.append({
            "id": s["_id"],
            "domain": s["Domain"],
            "user": s["User"],
            "primary": s["Primary Username"],
            "computer": s["Computer"],
            "client": s["Client"],
            "priv_ip": s["Private IP"],
            "pub_ip": s["Public IP"],
            "region": s["Source Region"],
            "tunnel": s["Tunnel Type"],
            "login_at": s["Login At"],
            "logout_at": s["Logout At"],
            "status": s["Status"],
            "lifetime_s": s["Lifetime (S)"],
            "source_file": s["_file"],
            "off_hours": _is_off_hour(s["_login_dt"]),
            "weekday": s["_login_dt"].weekday(),
            "hour": s["_login_dt"].hour,
        })

    # Aggregates
    sev_counts = Counter(f["severity"] for f in findings)
    rule_counts = Counter(f["rule_id"] for f in findings)
    region_counts = Counter(s["region"] for s in sess_out)

    # Per-user summary
    users_summary = {}
    by_user = defaultdict(list)
    for s in sess_out:
        if s["user"]:
            by_user[s["user"]].append(s)
    findings_by_user = defaultdict(list)
    for f in findings:
        findings_by_user[f["user"]].append(f)
    for user, ss in by_user.items():
        regions = Counter(x["region"] for x in ss)
        users_summary[user] = {
            "session_count": len(ss),
            "computer_count": len({x["computer"] for x in ss if x["computer"]}),
            "ip_count": len({x["pub_ip"] for x in ss if x["pub_ip"]}),
            "region_count": len({r for r in regions if r}),
            "regions": regions.most_common(10),
            "finding_count": len(findings_by_user.get(user, [])),
            "max_severity": max(
                (SEVERITY_RANK[f["severity"]]
                 for f in findings_by_user.get(user, [])),
                default=-1),
        }

    if sess_out:
        date_min = min(s["login_at"] for s in sess_out)
        date_max = max(s["login_at"] for s in sess_out)
    else:
        date_min = date_max = ""

    # Heatmap day-of-week × hour-of-day
    heatmap = [[0] * 24 for _ in range(7)]
    for s in sess_out:
        heatmap[s["weekday"]][s["hour"]] += 1

    return {
        "meta": {
            "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
            "session_count": len(sess_out),
            "finding_count": len(findings),
            "user_count": len(users_summary),
            "baseline_region": baseline_region,
            "date_min": date_min,
            "date_max": date_max,
            "thresholds": THRESHOLDS,
            "severity_levels": SEVERITY_LEVELS,
        },
        "rules": {rid: {"name": name, "default_severity": sev}
                  for rid, (name, sev) in RULE_CATALOG.items()},
        "severity_counts": dict(sev_counts),
        "rule_counts": dict(rule_counts),
        "region_counts": dict(region_counts),
        "heatmap": heatmap,
        "users": users_summary,
        "findings": findings,
        "sessions": sess_out,
    }


# ============================================================
# HTML generator
# ============================================================

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GlobalProtect — Anomaly Dashboard</title>
<style>
:root {
    --bg: #0b0e14;
    --panel: #131722;
    --panel-2: #1a1f2e;
    --border: #2a3142;
    --text: #d4d8e0;
    --text-dim: #8a92a3;
    --accent: #4ea1ff;
    --accent-2: #7c5cff;
    --info: #4ea1ff;
    --data-quality: #888;
    --low: #6acf8c;
    --medium: #f0c674;
    --high: #ff8c4a;
    --critical: #ff4d6d;
}
* { box-sizing: border-box; }
html, body {
    margin: 0; padding: 0; height: 100%; background: var(--bg);
    color: var(--text); font-family: -apple-system, BlinkMacSystemFont,
    "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 13px;
    line-height: 1.45;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
button {
    background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
    padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 12px;
}
button:hover { border-color: var(--accent); }
input, select {
    background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
    padding: 5px 8px; border-radius: 4px; font-size: 12px;
}
input:focus, select:focus { outline: none; border-color: var(--accent); }
code { background: var(--panel-2); padding: 1px 5px; border-radius: 3px; font-size: 12px; }
.app { display: flex; min-height: 100vh; }
.sidebar {
    width: 240px; background: var(--panel); border-right: 1px solid var(--border);
    padding: 16px 0; position: sticky; top: 0; height: 100vh; overflow-y: auto;
    flex-shrink: 0;
}
.sidebar h1 {
    font-size: 14px; margin: 0 16px 4px; color: var(--accent);
    letter-spacing: 0.04em;
}
.sidebar .subtitle { font-size: 11px; color: var(--text-dim); margin: 0 16px 16px; }
.nav { list-style: none; padding: 0; margin: 0; }
.nav li a {
    display: flex; justify-content: space-between; align-items: center;
    padding: 7px 16px; color: var(--text); border-left: 3px solid transparent;
}
.nav li a:hover { background: var(--panel-2); text-decoration: none; }
.nav li a.active { background: var(--panel-2); border-left-color: var(--accent); color: #fff; }
.nav-section { font-size: 10px; text-transform: uppercase; color: var(--text-dim);
    padding: 14px 16px 4px; letter-spacing: 0.06em; }
.badge { background: var(--panel-2); padding: 1px 7px; border-radius: 10px;
    font-size: 11px; color: var(--text-dim); }
.main { flex: 1; padding: 20px 28px; overflow-x: auto; min-width: 0; }
.breadcrumb { color: var(--text-dim); font-size: 12px; margin-bottom: 6px; }
.breadcrumb a { color: var(--text-dim); }
h2 { font-size: 18px; font-weight: 600; margin: 0 0 16px; color: #fff; }
h3 { font-size: 14px; font-weight: 600; margin: 18px 0 8px; color: #fff; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px; margin-bottom: 20px; }
.kpi {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px 16px;
}
.kpi .label { font-size: 11px; color: var(--text-dim); text-transform: uppercase;
    letter-spacing: 0.05em; }
.kpi .value { font-size: 22px; font-weight: 700; color: #fff; margin-top: 4px; }
.kpi .sub { font-size: 11px; color: var(--text-dim); margin-top: 2px; }
.cards { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 1100px) { .cards { grid-template-columns: 1fr; } }
.card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 14px 16px;
}
.sev-pill { display: inline-block; padding: 1px 8px; border-radius: 10px;
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.04em; }
.sev-info { background: rgba(78,161,255,0.18); color: #6cb8ff; }
.sev-data-quality { background: rgba(136,136,136,0.18); color: #aaa; }
.sev-low { background: rgba(106,207,140,0.18); color: #6acf8c; }
.sev-medium { background: rgba(240,198,116,0.18); color: #f0c674; }
.sev-high { background: rgba(255,140,74,0.2); color: #ff8c4a; }
.sev-critical { background: rgba(255,77,109,0.22); color: #ff5c7a; font-weight: 700; }
.tag { display: inline-block; padding: 1px 7px; border-radius: 3px;
    background: var(--panel-2); font-size: 11px; color: var(--text-dim); margin: 1px; }
.toolbar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px;
    align-items: center; }
.toolbar .grow { flex: 1; min-width: 200px; }
.tbl-wrap {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    overflow: hidden;
}
.tbl-header, .tbl-row {
    display: grid; align-items: center; padding: 8px 12px;
    border-bottom: 1px solid var(--border); gap: 8px;
}
.tbl-header { background: var(--panel-2); font-size: 11px;
    text-transform: uppercase; color: var(--text-dim); letter-spacing: 0.04em;
    position: sticky; top: 0; z-index: 1; }
.tbl-row:hover { background: var(--panel-2); }
.tbl-row { font-size: 12px; }
.tbl-row .cell { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tbl-row.empty { color: var(--text-dim); font-style: italic; padding: 14px; }
.virtual { position: relative; height: 600px; overflow-y: auto; }
.virtual-spacer { position: relative; }
.virtual-row { position: absolute; left: 0; right: 0; }
.heatmap { display: grid; grid-template-columns: 40px repeat(24, 1fr); gap: 2px;
    margin: 4px 0; }
.heatmap .lbl { font-size: 10px; color: var(--text-dim); display: flex;
    align-items: center; justify-content: center; }
.heatmap .cell { aspect-ratio: 1; border-radius: 2px; min-height: 14px; }
.bar { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; }
.bar .name { width: 130px; font-size: 12px; overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap; }
.bar .track { flex: 1; height: 14px; background: var(--panel-2); border-radius: 2px;
    overflow: hidden; }
.bar .fill { height: 100%; background: var(--accent); }
.bar .num { font-size: 11px; color: var(--text-dim); width: 50px;
    text-align: right; font-variant-numeric: tabular-nums; }
/* Wide variant: full label on its own line above the bar (used by long
   labels like rule names so they don't get clipped). */
.bar.bar-wide { flex-wrap: wrap; row-gap: 2px; margin-bottom: 8px; }
.bar.bar-wide .name { width: 100%; min-width: 0; white-space: normal;
    overflow: visible; text-overflow: clip; line-height: 1.3; }
.bar.bar-wide .track { flex: 1; }
.rule-group-head { margin: 12px 0 4px 0; display: flex; align-items: center; }
.timeline {
    position: relative; height: 60px; background: var(--panel-2); border-radius: 6px;
    margin: 6px 0;
}
.timeline .seg {
    position: absolute; top: 14px; bottom: 4px; min-width: 2px;
    border-radius: 2px; opacity: 0.8;
}
.timeline .tl-finding {
    position: absolute; top: 0; width: 0; height: 0;
    border-left: 4px solid transparent; border-right: 4px solid transparent;
    border-top: 7px solid var(--medium);
    transform: translateX(-4px); cursor: help; z-index: 2;
}
.tl-axis { position: relative; height: 18px; margin: 0 0 2px 0;
    color: var(--text-dim); font-size: 10px;
    font-variant-numeric: tabular-nums; }
.tl-axis .tl-axis-tick { position: absolute; top: 0; bottom: 0;
    width: 1px; background: var(--border); }
.tl-axis .tl-axis-lbl { position: absolute; top: 2px; transform: translateX(-50%);
    white-space: nowrap; }
.tl-row { display: grid; grid-template-columns: 160px 1fr; gap: 10px;
    align-items: center; margin: 4px 0; }
.tl-row .tl-name { font-size: 12px; overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap; }
.tl-row .tl-name a { color: var(--accent); text-decoration: none; }
.tl-row .tl-name .badge { margin-left: 6px; }
.tl-row .timeline { height: 32px; margin: 2px 0; }
.tl-row .timeline .seg { top: 6px; bottom: 6px; }
.tl-row .timeline .tl-finding { border-top-width: 6px; }
.legend { font-size: 11px; color: var(--text-dim); display: flex; gap: 12px;
    flex-wrap: wrap; }
.legend .dot { display: inline-block; width: 10px; height: 10px;
    border-radius: 2px; margin-right: 4px; vertical-align: middle; }
.muted { color: var(--text-dim); }
.fail-banner { background: #4a1f2a; color: #ffb3c0; padding: 16px; border-radius: 8px;
    border: 1px solid #ff4d6d; margin: 30px; }
.kbd { font-family: ui-monospace, monospace; font-size: 11px; }
.evidence-list { font-family: ui-monospace, monospace; font-size: 11px;
    color: var(--text-dim); }
.region-flag { font-weight: 700; color: var(--text); }
</style>
</head>
<body>
<div id="app">
    <div style="padding: 40px; text-align: center; color: var(--text-dim);">
        Loading data...
    </div>
</div>
<script id="payload" type="application/octet-stream">__PAYLOAD__</script>
<script>
"use strict";

// ============================================================
// Boot: decompress gzip+base64 payload
// ============================================================
async function loadPayload() {
    const node = document.getElementById('payload');
    const b64 = (node.textContent || '').trim();
    if (!b64) throw new Error('payload empty');
    const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    if (typeof DecompressionStream === 'undefined') {
        throw new Error(
            'Your browser does not support DecompressionStream. ' +
            'Use Chrome 80+, Edge 80+, Safari 16.4+, or Firefox 113+.');
    }
    const ds = new DecompressionStream('gzip');
    const stream = new Blob([bin]).stream().pipeThrough(ds);
    const text = await new Response(stream).text();
    return JSON.parse(text);
}

// ============================================================
// State + util
// ============================================================
const state = { data: null, route: '#/' };

function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    // Note: there is intentionally no `html:` escape hatch here — every
    // user-controlled string must flow through createTextNode (children
    // path below) so the dashboard can never be tricked into evaluating
    // payload-derived HTML. Add a separate clearly-named helper if raw
    // HTML insertion is ever genuinely needed.
    if (attrs) for (const k of Object.keys(attrs)) {
        const v = attrs[k];
        if (k === 'class') e.className = v;
        else if (k.startsWith('on') && typeof v === 'function')
            e.addEventListener(k.slice(2).toLowerCase(), v);
        else if (v !== null && v !== undefined) e.setAttribute(k, v);
    }
    for (const c of children) {
        if (c === null || c === undefined || c === false) continue;
        if (Array.isArray(c)) for (const cc of c) {
            if (cc !== null && cc !== undefined && cc !== false)
                e.appendChild(typeof cc === 'string' ? document.createTextNode(cc) : cc);
        } else if (typeof c === 'string' || typeof c === 'number')
            e.appendChild(document.createTextNode(String(c)));
        else e.appendChild(c);
    }
    return e;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function fmtNum(n) { return n.toLocaleString('en-US'); }
function escapeRegex(s) { return s.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&'); }

function sevPill(s) {
    return el('span', { class: 'sev-pill sev-' + s }, s);
}

function severityFromMax(rank) {
    if (rank < 0) return null;
    return state.data.meta.severity_levels[rank];
}

// ============================================================
// Routing
// ============================================================
function parseHash() {
    let h = window.location.hash || '#/';
    if (!h.startsWith('#/')) h = '#/' + h.slice(1);
    const [path, query] = h.slice(2).split('?');
    const segs = path.split('/').filter(Boolean).map(decodeURIComponent);
    const params = new URLSearchParams(query || '');
    return { segs, params };
}

function hashFor(segs, params) {
    const path = segs.map(encodeURIComponent).join('/');
    let q = '';
    if (params) {
        const u = params instanceof URLSearchParams ? params : new URLSearchParams(params);
        const s = u.toString();
        if (s) q = '?' + s;
    }
    return '#/' + path + q;
}

function navigateTo(segs, params) {
    window.location.hash = hashFor(segs, params);
}

function linkTo(label, segs, params, attrs) {
    return el('a', Object.assign({ href: hashFor(segs, params) }, attrs || {}), label);
}

// ============================================================
// Virtual scrolling table
// ============================================================
function virtualTable(rows, columns, opts) {
    opts = opts || {};
    const rowHeight = opts.rowHeight || 32;
    const height = opts.height || 600;
    const onRowClick = opts.onRowClick;

    const wrap = el('div', { class: 'tbl-wrap' });

    // Header
    const headerCols = columns.map(c => `${c.width || '1fr'}`).join(' ');
    const header = el('div', { class: 'tbl-header' });
    header.style.gridTemplateColumns = headerCols;
    columns.forEach(c => header.appendChild(el('div', { class: 'cell' }, c.label)));
    wrap.appendChild(header);

    if (rows.length === 0) {
        wrap.appendChild(el('div', { class: 'tbl-row empty' }, 'No results.'));
        return wrap;
    }

    const virtual = el('div', { class: 'virtual' });
    virtual.style.height = height + 'px';
    const spacer = el('div', { class: 'virtual-spacer' });
    spacer.style.height = (rows.length * rowHeight) + 'px';
    virtual.appendChild(spacer);

    function render() {
        const top = virtual.scrollTop;
        const start = Math.max(0, Math.floor(top / rowHeight) - 5);
        const end = Math.min(rows.length,
            Math.ceil((top + virtual.clientHeight) / rowHeight) + 5);
        clear(spacer);
        for (let i = start; i < end; i++) {
            const r = rows[i];
            const row = el('div', { class: 'tbl-row virtual-row' });
            row.style.gridTemplateColumns = headerCols;
            row.style.top = (i * rowHeight) + 'px';
            row.style.height = rowHeight + 'px';
            columns.forEach(c => {
                const v = c.render ? c.render(r) : (r[c.key] || '');
                const cell = el('div', { class: 'cell' });
                if (v instanceof Node) cell.appendChild(v);
                else cell.appendChild(document.createTextNode(String(v)));
                row.appendChild(cell);
            });
            if (onRowClick) {
                row.style.cursor = 'pointer';
                row.addEventListener('click', () => onRowClick(r));
            }
            spacer.appendChild(row);
        }
    }

    let raf = null;
    virtual.addEventListener('scroll', () => {
        if (raf) return;
        raf = requestAnimationFrame(() => { raf = null; render(); });
    });
    setTimeout(render, 0);
    wrap.appendChild(virtual);
    return wrap;
}

// ============================================================
// Helpers / lookups
// ============================================================
function findingsForUser(user) {
    return state.data.findings.filter(f => f.user === user);
}
function sessionsForUser(user) {
    return state.data.sessions.filter(s => s.user === user);
}
function sessionsForComputer(user, computer) {
    return state.data.sessions.filter(s => s.user === user && s.computer === computer);
}
function sessionById(id) {
    return state.data.sessions.find(s => s.id === id);
}
function findingById(id) {
    return state.data.findings.find(f => f._id === id);
}

// ============================================================
// Views
// ============================================================
function viewOverview() {
    const m = state.data.meta;
    const sevCounts = state.data.severity_counts;
    const ruleCounts = state.data.rule_counts;
    const out = el('div');
    out.appendChild(el('h2', null, 'Overview'));
    out.appendChild(el('div', { class: 'breadcrumb' },
        `Generated ${m.generated_at} · Data ${m.date_min} -> ${m.date_max} · Baseline ${m.baseline_region}`));

    // KPIs
    const kpis = el('div', { class: 'kpis' });
    kpis.appendChild(kpi('Sessions', fmtNum(m.session_count)));
    kpis.appendChild(kpi('Users', fmtNum(m.user_count)));
    kpis.appendChild(kpi('Total findings', fmtNum(m.finding_count)));
    state.data.meta.severity_levels.slice().reverse().forEach(sev => {
        const n = sevCounts[sev] || 0;
        if (n > 0) kpis.appendChild(kpi(sev, fmtNum(n), null, sev));
    });
    out.appendChild(kpis);

    // Findings by rule
    const cards = el('div', { class: 'cards' });

    const ruleCard = el('div', { class: 'card' });
    const ruleHeader = el('div',
        { style: 'display:flex; align-items:baseline; justify-content:space-between;' },
        el('h3', { style: 'margin:0;' }, 'Findings by rule'),
        linkTo('view all rules ->', ['rules']));
    ruleCard.appendChild(ruleHeader);
    // All rules (including zero-count), grouped by severity (high -> info)
    // and bar-colored by severity. Empty bars communicate 'rule is wired but
    // didn't fire on this dataset' rather than hiding the rule entirely.
    const allRuleEntries = Object.entries(state.data.rules).map(([rid, info]) => ({
        rid, name: info.name, severity: info.default_severity,
        count: ruleCounts[rid] || 0,
    }));
    const maxRule = Math.max(...allRuleEntries.map(r => r.count), 1);
    const grouped = {};
    allRuleEntries.forEach(r => {
        (grouped[r.severity] = grouped[r.severity] || []).push(r);
    });
    state.data.meta.severity_levels.slice().reverse().forEach(sev => {
        const rules = grouped[sev];
        if (!rules) return;
        rules.sort((a, b) => b.count - a.count
            || a.rid.localeCompare(b.rid, 'en'));
        const head = el('div', { class: 'rule-group-head' },
            el('span', { class: 'sev-pill sev-' + sev }, sev),
            el('span', { class: 'muted',
                style: 'margin-left:8px; font-size:11px;' },
                `${rules.length} rule(s)`));
        ruleCard.appendChild(head);
        rules.forEach(r => {
            ruleCard.appendChild(barRow(
                `${r.rid} · ${r.name}`, r.count, maxRule,
                () => navigateTo(['findings'], { rule: r.rid }),
                { fillColor: `var(--${r.severity})`,
                  dim: r.count === 0, wide: true }));
        });
    });
    cards.appendChild(ruleCard);

    // Top users
    const userCard = el('div', { class: 'card' });
    userCard.appendChild(el('h3', null, 'Top users by findings'));
    const topUsers = Object.entries(state.data.users)
        .map(([u, info]) => [u, info.finding_count, info.max_severity])
        .filter(x => x[1] > 0)
        .sort((a, b) => b[2] - a[2] || b[1] - a[1])
        .slice(0, 12);
    const maxU = Math.max(...topUsers.map(t => t[1]), 1);
    topUsers.forEach(([u, n, sev]) => {
        const sevName = severityFromMax(sev) || '';
        const row = barRow(u, n, maxU, () => navigateTo(['user', u]));
        if (sevName) {
            row.querySelector('.fill').style.background =
                getComputedStyle(document.body).getPropertyValue('--' + sevName) ||
                'var(--accent)';
        }
        userCard.appendChild(row);
    });
    if (topUsers.length === 0)
        userCard.appendChild(el('div', { class: 'muted' }, 'No users with findings.'));
    cards.appendChild(userCard);
    out.appendChild(cards);

    // Heatmap day×hour
    out.appendChild(el('h3', null, 'Activity heatmap - day x local hour'));
    out.appendChild(buildHeatmap(state.data.heatmap));

    // Top regions
    const regCard = el('div', { class: 'card' });
    regCard.appendChild(el('h3', null, 'Sessions by Source Region'));
    const sortedRegs = Object.entries(state.data.region_counts)
        .filter(([k, _]) => k)
        .sort((a, b) => b[1] - a[1]);
    const maxR = Math.max(...sortedRegs.map(r => r[1]), 1);
    sortedRegs.slice(0, 30).forEach(([r, n]) => {
        regCard.appendChild(barRow(r, n, maxR));
    });
    out.appendChild(regCard);

    return out;
}

function kpi(label, value, sub, sevClass) {
    const e = el('div', { class: 'kpi' });
    e.appendChild(el('div', { class: 'label' }, label));
    const v = el('div', { class: 'value' }, value);
    if (sevClass) v.appendChild(el('span', { class: 'sev-pill sev-' + sevClass,
        style: 'margin-left: 8px;' }, sevClass));
    e.appendChild(v);
    if (sub) e.appendChild(el('div', { class: 'sub' }, sub));
    return e;
}

function barRow(label, value, max, onClick, opts) {
    opts = opts || {};
    const e = el('div', { class: 'bar' + (opts.wide ? ' bar-wide' : '') });
    const name = el('div', { class: 'name', title: opts.title || label }, label);
    if (onClick) { name.style.cursor = 'pointer'; name.style.color = 'var(--accent)';
        name.addEventListener('click', onClick); }
    const track = el('div', { class: 'track' });
    const fill = el('div', { class: 'fill' });
    fill.style.width = (max > 0 ? (100 * value / max) : 0) + '%';
    if (opts.fillColor) fill.style.background = opts.fillColor;
    if (opts.dim) { e.style.opacity = '0.55'; }
    track.appendChild(fill);
    e.appendChild(name);
    e.appendChild(track);
    e.appendChild(el('div', { class: 'num' }, fmtNum(value)));
    return e;
}

function buildHeatmap(grid) {
    const dayLabels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    let max = 1;
    for (const row of grid) for (const v of row) if (v > max) max = v;
    const wrap = el('div');
    const hour = el('div', { class: 'heatmap' });
    hour.appendChild(el('div'));
    for (let h = 0; h < 24; h++)
        hour.appendChild(el('div', { class: 'lbl' }, h.toString().padStart(2, '0')));
    wrap.appendChild(hour);
    grid.forEach((row, di) => {
        const r = el('div', { class: 'heatmap' });
        r.appendChild(el('div', { class: 'lbl' }, dayLabels[di]));
        row.forEach(v => {
            const intensity = v === 0 ? 0 : 0.18 + 0.82 * (v / max);
            const c = el('div', { class: 'cell',
                title: `${v} session(s)` });
            c.style.background = `rgba(78,161,255,${intensity})`;
            r.appendChild(c);
        });
        wrap.appendChild(r);
    });
    return wrap;
}

// ----- Findings list view -----
function viewFindings(params) {
    const out = el('div');
    out.appendChild(el('h2', null, 'Findings'));

    const filterRule = params.get('rule') || '';
    const filterSev = params.get('sev') || '';
    const filterUser = params.get('user') || '';
    const filterText = params.get('q') || '';

    const toolbar = el('div', { class: 'toolbar' });
    const ruleSel = el('select', null, el('option', { value: '' }, '- All rules -'));
    Object.entries(state.data.rules).forEach(([rid, info]) => {
        const o = el('option', { value: rid }, `${rid} · ${info.name}`);
        if (rid === filterRule) o.selected = true;
        ruleSel.appendChild(o);
    });
    ruleSel.addEventListener('change', () => updateFilter('rule', ruleSel.value));

    const sevSel = el('select', null, el('option', { value: '' }, '- All severities -'));
    state.data.meta.severity_levels.slice().reverse().forEach(s => {
        const o = el('option', { value: s }, s);
        if (s === filterSev) o.selected = true;
        sevSel.appendChild(o);
    });
    sevSel.addEventListener('change', () => updateFilter('sev', sevSel.value));

    const search = el('input', { type: 'search', placeholder: 'Search (user, rule, description)...',
        value: filterText, class: 'grow' });
    let to = null;
    search.addEventListener('input', () => {
        if (to) clearTimeout(to);
        to = setTimeout(() => updateFilter('q', search.value), 200);
    });

    toolbar.appendChild(ruleSel);
    toolbar.appendChild(sevSel);
    toolbar.appendChild(search);
    out.appendChild(toolbar);

    let rows = state.data.findings;
    if (filterRule) rows = rows.filter(f => f.rule_id === filterRule);
    if (filterSev) rows = rows.filter(f => f.severity === filterSev);
    if (filterUser) rows = rows.filter(f => f.user === filterUser);
    if (filterText) {
        const re = new RegExp(escapeRegex(filterText), 'i');
        rows = rows.filter(f =>
            re.test(f.user) || re.test(f.rule_id) || re.test(f.rule_name)
            || re.test(f.description));
    }
    out.appendChild(el('div', { class: 'breadcrumb' },
        `${fmtNum(rows.length)} finding(s)`));

    out.appendChild(virtualTable(rows, [
        { label: 'Sev.', width: '90px',
          render: f => sevPill(f.severity) },
        { label: 'Rule', width: '80px',
          render: f => linkTo(f.rule_id, ['findings'], { rule: f.rule_id }) },
        { label: 'User', width: '120px',
          render: f => linkTo(f.user, ['user', f.user]) },
        { label: 'Description', width: '1.5fr',
          render: f => f.description },
        { label: 'Window', width: '230px',
          render: f => `${f.window_start} -> ${f.window_end || '...'}` },
        { label: '#', width: '40px',
          render: f => String(f.evidence.length) },
    ], { onRowClick: f => navigateTo(['finding', f._id]) }));

    return out;
}

function updateFilter(key, value) {
    const { segs, params } = parseHash();
    if (value) params.set(key, value); else params.delete(key);
    navigateTo(segs.length ? segs : ['findings'], params);
}

// ----- Single finding -----
function viewFinding(id) {
    const f = findingById(id);
    const out = el('div');
    if (!f) {
        out.appendChild(el('h2', null, 'Finding not found'));
        return out;
    }
    out.appendChild(el('div', { class: 'breadcrumb' },
        linkTo('Findings', ['findings']), ' / ', f._id));
    out.appendChild(el('h2', null, `${f.rule_id} - ${f.rule_name}`));
    const meta = el('div', { class: 'kpis' });
    meta.appendChild(kpi('Severity', '', null, f.severity));
    meta.appendChild(kpi('User', f.user));
    meta.appendChild(kpi('Evidence', String(f.evidence.length) + ' session(s)'));
    if (f.window_start) meta.appendChild(kpi('Window', f.window_start, '-> ' + (f.window_end || '...')));
    out.appendChild(meta);

    out.appendChild(el('div', { class: 'card' }, el('div', null, f.description),
        Object.keys(f.extra || {}).length
            ? el('pre', { class: 'evidence-list',
                style: 'margin-top:10px; white-space:pre-wrap;' },
                JSON.stringify(f.extra, null, 2))
            : null));

    out.appendChild(el('h3', null, 'Evidence sessions'));
    const ev = f.evidence.map(sessionById).filter(Boolean);
    out.appendChild(sessionsTable(ev));
    return out;
}

// ----- Users list -----
function viewUsers(params) {
    const out = el('div');
    out.appendChild(el('h2', null, 'Users'));
    const filterText = params.get('q') || '';
    const minSev = params.get('sev') || '';

    const tb = el('div', { class: 'toolbar' });
    const search = el('input', { type: 'search', placeholder: 'Search user...',
        value: filterText, class: 'grow' });
    let to = null;
    search.addEventListener('input', () => {
        if (to) clearTimeout(to);
        to = setTimeout(() => updateFilter('q', search.value), 200);
    });
    const sevSel = el('select', null, el('option', { value: '' }, '- Any severity -'));
    state.data.meta.severity_levels.slice().reverse().forEach(s => {
        const o = el('option', { value: s }, '>= ' + s);
        if (s === minSev) o.selected = true;
        sevSel.appendChild(o);
    });
    sevSel.addEventListener('change', () => updateFilter('sev', sevSel.value));
    tb.appendChild(search);
    tb.appendChild(sevSel);
    out.appendChild(tb);

    const users = Object.entries(state.data.users).map(([u, info]) => ({
        user: u, ...info,
        max_sev_name: severityFromMax(info.max_severity) || '',
    }));
    let rows = users;
    if (filterText) {
        const re = new RegExp(escapeRegex(filterText), 'i');
        rows = rows.filter(u => re.test(u.user));
    }
    if (minSev) {
        const minR = state.data.meta.severity_levels.indexOf(minSev);
        rows = rows.filter(u => u.max_severity >= minR);
    }
    rows.sort((a, b) => b.max_severity - a.max_severity
        || b.finding_count - a.finding_count
        || a.user.localeCompare(b.user, 'en'));

    out.appendChild(el('div', { class: 'breadcrumb' },
        `${fmtNum(rows.length)} user(s)`));

    out.appendChild(virtualTable(rows, [
        { label: 'User', width: '160px',
          render: u => linkTo(u.user, ['user', u.user]) },
        { label: 'Sessions', width: '90px', render: u => fmtNum(u.session_count) },
        { label: 'Computers', width: '90px', render: u => fmtNum(u.computer_count) },
        { label: 'IPs', width: '70px', render: u => fmtNum(u.ip_count) },
        { label: 'Regions', width: '90px', render: u => fmtNum(u.region_count) },
        { label: 'Findings', width: '90px', render: u => fmtNum(u.finding_count) },
        { label: 'Max sev', width: '110px',
          render: u => u.max_sev_name ? sevPill(u.max_sev_name) : '-' },
        { label: 'Top regions', width: '1fr',
          render: u => u.regions.map(([r, n]) => `${r}(${n})`).join(' ') },
    ], { onRowClick: u => navigateTo(['user', u.user]) }));

    return out;
}

// ----- Single user -----
function viewUser(name) {
    const out = el('div');
    out.appendChild(el('div', { class: 'breadcrumb' },
        linkTo('Users', ['users']), ' / ', name));
    out.appendChild(el('h2', null, `User: ${name}`));

    const info = state.data.users[name];
    const sessions = sessionsForUser(name);
    const findings = findingsForUser(name);

    if (!info) {
        out.appendChild(el('div', { class: 'card' }, 'User not found in the dataset.'));
        return out;
    }

    const k = el('div', { class: 'kpis' });
    k.appendChild(kpi('Sessions', fmtNum(info.session_count)));
    k.appendChild(kpi('Computers', fmtNum(info.computer_count)));
    k.appendChild(kpi('Public IPs', fmtNum(info.ip_count)));
    k.appendChild(kpi('Regions', fmtNum(info.region_count)));
    k.appendChild(kpi('Findings', fmtNum(info.finding_count),
        null, severityFromMax(info.max_severity) || undefined));
    out.appendChild(k);

    // Computers list with link to drill down
    out.appendChild(el('h3', null, 'Computers'));
    const computers = {};
    sessions.forEach(s => {
        if (!s.computer) return;
        if (!computers[s.computer])
            computers[s.computer] = { count: 0, regions: new Set(), ips: new Set(), client: s.client };
        computers[s.computer].count++;
        if (s.region) computers[s.computer].regions.add(s.region);
        if (s.pub_ip) computers[s.computer].ips.add(s.pub_ip);
    });
    const compRows = Object.entries(computers).map(([c, d]) => ({
        computer: c, count: d.count,
        regions: [...d.regions].join(' '),
        ips: [...d.ips].join(' '),
        client: d.client,
    })).sort((a, b) => b.count - a.count);
    out.appendChild(virtualTable(compRows, [
        { label: 'Computer', width: '180px',
          render: r => linkTo(r.computer, ['user', name, 'computer', r.computer]) },
        { label: 'Sessions', width: '90px', render: r => fmtNum(r.count) },
        { label: 'Regions', width: '120px', render: r => r.regions || '-' },
        { label: 'IPs', width: '1fr', render: r => r.ips || '-' },
        { label: 'Client', width: '180px', render: r => r.client || '-' },
    ], { height: Math.min(400, compRows.length * 32 + 50) }));

    out.appendChild(el('h3', null, `Findings (${findings.length})`));
    if (findings.length === 0) {
        out.appendChild(el('div', { class: 'card muted' }, 'No findings for this user.'));
    } else {
        out.appendChild(virtualTable(findings, [
            { label: 'Sev.', width: '90px', render: f => sevPill(f.severity) },
            { label: 'Rule', width: '80px',
              render: f => linkTo(f.rule_id, ['findings'], { rule: f.rule_id }) },
            { label: 'Description', width: '1.5fr', render: f => f.description },
            { label: 'Window', width: '230px',
              render: f => `${f.window_start} -> ${f.window_end || '...'}` },
        ], { onRowClick: f => navigateTo(['finding', f._id]),
             height: Math.min(400, findings.length * 32 + 50) }));
    }

    // Timeline (visual) of sessions in user's range, with finding markers
    out.appendChild(el('h3', null, 'Session timeline'));
    out.appendChild(buildUserTimeline(sessions, { findings }));

    out.appendChild(el('h3', null, `Sessions (${sessions.length})`));
    out.appendChild(sessionsTable(sessions));
    return out;
}

// Locale-independent date formatter for axis ticks: 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM' for sub-day spans.
function fmtTick(ms, spanMs) {
    const d = new Date(ms);
    const pad = n => String(n).padStart(2, '0');
    const ymd = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    if (spanMs <= 2 * 86400 * 1000)
        return `${ymd} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
    return ymd;
}

// Standalone time axis (5 evenly-spaced labels). Used as a shared header in the
// global timelines view, and inside buildUserTimeline.
function buildTimeAxis(min, max) {
    const span = max - min;
    const axis = el('div', { class: 'tl-axis' });
    const N = 5;
    for (let i = 0; i < N; i++) {
        const frac = i / (N - 1);
        const ms = min + span * frac;
        const tick = el('div', { class: 'tl-axis-tick' });
        tick.style.left = (100 * frac) + '%';
        const lbl = el('div', { class: 'tl-axis-lbl' }, fmtTick(ms, span));
        if (i === 0) { lbl.style.transform = 'none'; lbl.style.left = '0'; }
        else if (i === N - 1) { lbl.style.transform = 'none'; lbl.style.right = '0';
            lbl.style.left = 'auto'; }
        else lbl.style.left = (100 * frac) + '%';
        axis.appendChild(tick);
        axis.appendChild(lbl);
    }
    return axis;
}

const _REGION_PALETTE = ['#4ea1ff', '#7c5cff', '#6acf8c', '#f0c674',
    '#ff8c4a', '#ff4d6d', '#3ec9c9', '#e0aaff', '#a3d977', '#d97aa3'];

// Build a region-color map; either provided, or freshly created.
function makeRegionPalette() {
    const map = new Map();
    return {
        colorFor(region) {
            if (!map.has(region))
                map.set(region, _REGION_PALETTE[map.size % _REGION_PALETTE.length]);
            return map.get(region);
        },
        entries() { return [...map.entries()]; },
    };
}

// Render a timeline.
//   sessions: array of session rows (must have login_at, logout_at, region, pub_ip).
//   opts.findings: optional array of findings to overlay as markers.
//   opts.min, opts.max: optional shared time bounds (ms). Auto-computed if absent.
//   opts.showAxis: render date axis above the bar (default true).
//   opts.showLegend: render region color legend (default true).
//   opts.palette: shared region palette (so multiple rows align colors).
function buildUserTimeline(sessions, opts) {
    opts = opts || {};
    const wrap = el('div');
    if (sessions.length === 0 && !(opts.findings && opts.findings.length))
        return el('div', { class: 'muted' }, 'No sessions.');
    const parse = s => s ? Date.parse(s.replace(' ', 'T')) : null;
    let min = opts.min, max = opts.max;
    if (min === undefined || max === undefined) {
        min = Infinity; max = -Infinity;
        sessions.forEach(s => {
            const a = parse(s.login_at);
            const b = parse(s.logout_at) || a + 60000;
            if (a !== null && a < min) min = a;
            if (b !== null && b > max) max = b;
        });
        if (opts.findings) opts.findings.forEach(f => {
            const a = parse(f.window_start);
            const b = parse(f.window_end) || a;
            if (a !== null && a < min) min = a;
            if (b !== null && b > max) max = b;
        });
    }
    if (!isFinite(min) || !isFinite(max) || max <= min) max = (min || Date.now()) + 60000;

    const showAxis = opts.showAxis !== false;
    const showLegend = opts.showLegend !== false;
    const palette = opts.palette || makeRegionPalette();
    const span = max - min;
    const pos = ms => 100 * (ms - min) / span;

    if (showAxis) wrap.appendChild(buildTimeAxis(min, max));

    const tl = el('div', { class: 'timeline' });
    sessions.forEach(s => {
        const a = parse(s.login_at);
        if (a === null) return;
        const b = parse(s.logout_at) || max;
        const left = pos(a);
        const right = pos(b);
        const seg = el('div', { class: 'seg',
            title: `${s.login_at} -> ${s.logout_at || 'ongoing'} · ${s.region || '-'} · ${s.pub_ip || '-'}` });
        seg.style.left = left + '%';
        seg.style.width = Math.max(0.2, right - left) + '%';
        seg.style.background = palette.colorFor(s.region || '-');
        tl.appendChild(seg);
    });

    if (opts.findings && opts.findings.length) {
        opts.findings.forEach(f => {
            const a = parse(f.window_start);
            if (a === null || a < min || a > max) return;
            const mark = el('div', { class: 'tl-finding',
                title: `[${f.severity}] ${f.rule_id} - ${f.rule_name}: ${f.description}` });
            mark.style.left = pos(a) + '%';
            mark.style.borderTopColor = `var(--${f.severity})`;
            mark.addEventListener('click', e => {
                e.stopPropagation();
                navigateTo(['finding', f._id]);
            });
            mark.style.cursor = 'pointer';
            tl.appendChild(mark);
        });
    }

    wrap.appendChild(tl);

    if (showLegend) {
        const legend = el('div', { class: 'legend' });
        palette.entries().forEach(([r, c]) => {
            const dot = el('span', { class: 'dot' });
            dot.style.background = c;
            legend.appendChild(el('span', null, dot, r || '-'));
        });
        if (opts.findings && opts.findings.length) {
            const sevDot = el('span', { class: 'dot',
                style: 'background: var(--medium); width: 0; height: 0; '
                    + 'border-left: 5px solid transparent; border-right: 5px solid transparent; '
                    + 'border-top: 7px solid var(--medium); border-radius: 0;' });
            legend.appendChild(el('span', null, sevDot, 'finding'));
        }
        wrap.appendChild(legend);
    }
    return wrap;
}

// ----- Computer drill-down -----
function viewComputer(user, computer) {
    const out = el('div');
    out.appendChild(el('div', { class: 'breadcrumb' },
        linkTo('Users', ['users']), ' / ',
        linkTo(user, ['user', user]), ' / ', computer));
    out.appendChild(el('h2', null, `${user} @ ${computer}`));
    const sess = sessionsForComputer(user, computer);
    const k = el('div', { class: 'kpis' });
    k.appendChild(kpi('Sessions', fmtNum(sess.length)));
    k.appendChild(kpi('Regions', fmtNum(new Set(sess.map(s => s.region)).size)));
    k.appendChild(kpi('IPs', fmtNum(new Set(sess.map(s => s.pub_ip)).size)));
    out.appendChild(k);
    // Limit findings to those whose evidence touches this computer's sessions.
    const sessIds = new Set(sess.map(s => s.id));
    const compFindings = findingsForUser(user).filter(
        f => f.evidence.some(id => sessIds.has(id)));
    out.appendChild(buildUserTimeline(sess, { findings: compFindings }));
    out.appendChild(sessionsTable(sess));
    return out;
}

// ----- Global comparison timelines -----
function viewTimelines(params) {
    const out = el('div');
    out.appendChild(el('h2', null, 'Timelines'));

    const minSev = params.get('sev') || '';
    const requestedN = parseInt(params.get('n') || '20', 10);
    const N = (Number.isFinite(requestedN) && requestedN > 0)
        ? Math.min(requestedN, 200) : 20;

    // Toolbar: severity filter + N selector
    const tb = el('div', { class: 'toolbar' });
    const sevSel = el('select', null,
        el('option', { value: '' }, '- Any severity -'));
    state.data.meta.severity_levels.slice().reverse().forEach(s => {
        const o = el('option', { value: s }, '>= ' + s);
        if (s === minSev) o.selected = true;
        sevSel.appendChild(o);
    });
    sevSel.addEventListener('change', () => updateFilter('sev', sevSel.value));

    const nSel = el('select');
    [10, 20, 50, 100, 200].forEach(v => {
        const o = el('option', { value: String(v) }, 'Top ' + v);
        if (v === N) o.selected = true;
        nSel.appendChild(o);
    });
    nSel.addEventListener('change', () => updateFilter('n', nSel.value));
    tb.appendChild(sevSel);
    tb.appendChild(nSel);
    out.appendChild(tb);

    // Pick users: prefer those with findings, ordered by max severity then count.
    const minR = minSev
        ? state.data.meta.severity_levels.indexOf(minSev) : -1;
    const candidates = Object.entries(state.data.users)
        .map(([u, info]) => ({ user: u, ...info }))
        .filter(u => u.finding_count > 0
            && (minR < 0 || u.max_severity >= minR));
    candidates.sort((a, b) => b.max_severity - a.max_severity
        || b.finding_count - a.finding_count
        || a.user.localeCompare(b.user, 'en'));
    const users = candidates.slice(0, N);

    out.appendChild(el('div', { class: 'breadcrumb' },
        `${fmtNum(users.length)} user(s) shown out of ${fmtNum(candidates.length)} flagged`
        + (minSev ? ` (>= ${minSev})` : '')));

    if (users.length === 0) {
        out.appendChild(el('div', { class: 'card muted' },
            'No flagged users match the current filter.'));
        return out;
    }

    // Compute global min/max across selected users' sessions + findings, so all
    // rows share one time axis.
    const parse = s => s ? Date.parse(s.replace(' ', 'T')) : null;
    let gMin = Infinity, gMax = -Infinity;
    const perUser = users.map(u => {
        const ss = sessionsForUser(u.user);
        const fs = findingsForUser(u.user);
        ss.forEach(s => {
            const a = parse(s.login_at);
            const b = parse(s.logout_at) || a + 60000;
            if (a !== null && a < gMin) gMin = a;
            if (b !== null && b > gMax) gMax = b;
        });
        fs.forEach(f => {
            const a = parse(f.window_start);
            const b = parse(f.window_end) || a;
            if (a !== null && a < gMin) gMin = a;
            if (b !== null && b > gMax) gMax = b;
        });
        return { u, sessions: ss, findings: fs };
    });
    if (!isFinite(gMin) || !isFinite(gMax) || gMax <= gMin) gMax = gMin + 60000;

    // Shared region palette so colors are consistent across all rows.
    const palette = makeRegionPalette();

    // Header axis row (single axis above all rows)
    const headerWrap = el('div', { class: 'card' });
    const header = el('div', { class: 'tl-row' });
    header.appendChild(el('div', { class: 'tl-name muted' }, 'User'));
    header.appendChild(buildTimeAxis(gMin, gMax));
    headerWrap.appendChild(header);

    // Per-user rows
    perUser.forEach(({ u, sessions, findings }) => {
        const row = el('div', { class: 'tl-row' });
        const sevName = severityFromMax(u.max_severity) || '';
        const name = el('div', { class: 'tl-name', title: u.user });
        name.appendChild(linkTo(u.user, ['user', u.user]));
        if (sevName)
            name.appendChild(el('span',
                { class: 'badge sev-pill sev-' + sevName },
                String(u.finding_count)));
        else
            name.appendChild(el('span', { class: 'badge' },
                String(u.finding_count)));
        row.appendChild(name);
        row.appendChild(buildUserTimeline(sessions, {
            findings, min: gMin, max: gMax,
            showAxis: false, showLegend: false, palette,
        }));
        headerWrap.appendChild(row);
    });
    out.appendChild(headerWrap);

    // Global region legend
    const legend = el('div', { class: 'legend', style: 'margin-top: 10px;' });
    palette.entries().forEach(([r, c]) => {
        const dot = el('span', { class: 'dot' });
        dot.style.background = c;
        legend.appendChild(el('span', null, dot, r || '-'));
    });
    out.appendChild(legend);
    return out;
}

// ----- Sessions list -----
function viewSessions(params) {
    const out = el('div');
    out.appendChild(el('h2', null, 'Sessions'));
    const filterText = params.get('q') || '';
    const filterRegion = params.get('region') || '';
    const filterStatus = params.get('status') || '';
    const offHoursOnly = params.get('off') === '1';

    const tb = el('div', { class: 'toolbar' });
    const search = el('input', { type: 'search',
        placeholder: 'Search (user, computer, IP, region)...',
        value: filterText, class: 'grow' });
    let to = null;
    search.addEventListener('input', () => {
        if (to) clearTimeout(to);
        to = setTimeout(() => updateFilter('q', search.value), 200);
    });
    const regSel = el('select', null,
        el('option', { value: '' }, '- All regions -'));
    Object.keys(state.data.region_counts).sort().forEach(r => {
        if (!r) return;
        const o = el('option', { value: r }, r);
        if (r === filterRegion) o.selected = true;
        regSel.appendChild(o);
    });
    regSel.addEventListener('change', () => updateFilter('region', regSel.value));
    const statusSel = el('select', null,
        el('option', { value: '' }, '- Status -'),
        el('option', { value: 'closed' }, 'closed'),
        el('option', { value: 'ongoing' }, 'ongoing'));
    statusSel.value = filterStatus;
    statusSel.addEventListener('change', () => updateFilter('status', statusSel.value));
    const offCb = el('label', { style: 'font-size:12px; color:var(--text-dim);' },
        Object.assign(el('input', { type: 'checkbox' }), {}));
    const offInput = offCb.querySelector('input');
    offInput.checked = offHoursOnly;
    offInput.addEventListener('change',
        () => updateFilter('off', offInput.checked ? '1' : ''));
    offCb.appendChild(document.createTextNode(' off-hours'));
    tb.appendChild(search); tb.appendChild(regSel);
    tb.appendChild(statusSel); tb.appendChild(offCb);
    out.appendChild(tb);

    let rows = state.data.sessions;
    if (filterRegion) rows = rows.filter(s => s.region === filterRegion);
    if (filterStatus) rows = rows.filter(s => s.status === filterStatus);
    if (offHoursOnly) rows = rows.filter(s => s.off_hours);
    if (filterText) {
        const re = new RegExp(escapeRegex(filterText), 'i');
        rows = rows.filter(s =>
            re.test(s.user) || re.test(s.computer) ||
            re.test(s.pub_ip) || re.test(s.region) || re.test(s.client));
    }
    out.appendChild(el('div', { class: 'breadcrumb' },
        `${fmtNum(rows.length)} session(s)`));
    out.appendChild(sessionsTable(rows));
    return out;
}

function sessionsTable(rows) {
    return virtualTable(rows, [
        { label: 'Status', width: '70px',
          render: s => s.status === 'ongoing'
            ? el('span', { class: 'sev-pill sev-medium' }, 'ongoing')
            : el('span', { class: 'tag' }, 'closed') },
        { label: 'User', width: '110px',
          render: s => linkTo(s.user, ['user', s.user]) },
        { label: 'Computer', width: '160px',
          render: s => linkTo(s.computer, ['user', s.user, 'computer', s.computer]) },
        { label: 'Region', width: '70px',
          render: s => el('span', { class: 'region-flag' }, s.region || '-') },
        { label: 'Public IP', width: '120px', render: s => s.pub_ip || '-' },
        { label: 'Login', width: '160px',
          render: s => el('span', { class: s.off_hours ? 'sev-pill sev-low' : '' },
            s.login_at) },
        { label: 'Logout', width: '160px',
          render: s => s.logout_at || '...' },
        { label: 'Tunnel', width: '70px', render: s => s.tunnel || '' },
        { label: 'Client', width: '1fr',
          render: s => s.client || '-' },
    ]);
}

// ----- Rules catalog view -----
function viewRules(params) {
    const out = el('div');
    out.appendChild(el('h2', null, 'Rules'));

    const filterText = params.get('q') || '';
    const minSev = params.get('sev') || '';

    const tb = el('div', { class: 'toolbar' });
    const search = el('input', { type: 'search',
        placeholder: 'Search rule (id, name, severity)...',
        value: filterText, class: 'grow' });
    let to = null;
    search.addEventListener('input', () => {
        if (to) clearTimeout(to);
        to = setTimeout(() => updateFilter('q', search.value), 200);
    });
    const sevSel = el('select', null,
        el('option', { value: '' }, '- Any severity -'));
    state.data.meta.severity_levels.slice().reverse().forEach(s => {
        const o = el('option', { value: s }, '>= ' + s);
        if (s === minSev) o.selected = true;
        sevSel.appendChild(o);
    });
    sevSel.addEventListener('change', () => updateFilter('sev', sevSel.value));
    tb.appendChild(search);
    tb.appendChild(sevSel);
    out.appendChild(tb);

    const rows = Object.entries(state.data.rules).map(([rid, info]) => {
        const count = state.data.rule_counts[rid] || 0;
        return {
            rid, name: info.name, severity: info.default_severity,
            count, status: count > 0 ? 'fired' : 'idle',
            sev_rank: state.data.meta.severity_levels.indexOf(info.default_severity),
        };
    });

    let filtered = rows;
    if (minSev) {
        const minR = state.data.meta.severity_levels.indexOf(minSev);
        filtered = filtered.filter(r => r.sev_rank >= minR);
    }
    if (filterText) {
        const re = new RegExp(escapeRegex(filterText), 'i');
        filtered = filtered.filter(r =>
            re.test(r.rid) || re.test(r.name) || re.test(r.severity));
    }
    filtered.sort((a, b) => b.sev_rank - a.sev_rank
        || b.count - a.count
        || a.rid.localeCompare(b.rid, 'en'));

    out.appendChild(el('div', { class: 'breadcrumb' },
        `${fmtNum(filtered.length)} rule(s) shown out of ${fmtNum(rows.length)}`));

    out.appendChild(virtualTable(filtered, [
        { label: 'ID', width: '60px',
          render: r => linkTo(r.rid, ['findings'], { rule: r.rid }) },
        { label: 'Severity', width: '110px',
          render: r => sevPill(r.severity) },
        { label: 'Rule', width: '1.5fr', render: r => r.name },
        { label: 'Findings', width: '90px', render: r => fmtNum(r.count) },
        { label: 'Status', width: '90px',
          render: r => el('span',
            { class: r.count > 0 ? 'tag' : 'muted',
              style: 'font-size:11px;' },
            r.status) },
    ], { onRowClick: r => navigateTo(['findings'], { rule: r.rid }),
         height: Math.min(700, filtered.length * 32 + 50) }));
    return out;
}

// ----- Regions view -----
function viewRegions() {
    const out = el('div');
    out.appendChild(el('h2', null, 'Regions'));
    const rows = Object.entries(state.data.region_counts)
        .filter(([k, _]) => k)
        .map(([k, v]) => ({ region: k, count: v,
            kind: /^[A-Z]{2}$/.test(k) ? 'iso2'
                : /^\d/.test(k) ? 'private' : 'other' }))
        .sort((a, b) => b.count - a.count);
    out.appendChild(virtualTable(rows, [
        { label: 'Region', width: '160px',
          render: r => linkTo(r.region, ['sessions'], { region: r.region }) },
        { label: 'Type', width: '120px', render: r => r.kind },
        { label: 'Sessions', width: '120px', render: r => fmtNum(r.count) },
    ], { height: Math.min(600, rows.length * 32 + 50) }));
    return out;
}

// ----- Sidebar -----
function buildSidebar() {
    const m = state.data.meta;
    const sevs = state.data.severity_counts;
    const side = el('aside', { class: 'sidebar' });
    side.appendChild(el('h1', null, 'GP Anomaly Dashboard'));
    side.appendChild(el('div', { class: 'subtitle' },
        `${fmtNum(m.session_count)} sessions · ${fmtNum(m.finding_count)} findings`));
    const nav = el('ul', { class: 'nav' });
    nav.appendChild(navItem('Overview', ['']));
    nav.appendChild(navSection('Findings'));
    nav.appendChild(navItem('All', ['findings'], m.finding_count));
    state.data.meta.severity_levels.slice().reverse().forEach(sev => {
        const n = sevs[sev] || 0;
        if (n > 0)
            nav.appendChild(navItem(sev, ['findings'], n, { sev: sev }));
    });
    nav.appendChild(navSection('Rules'));
    nav.appendChild(navItem('All rules', ['rules'],
        Object.keys(state.data.rules).length));
    nav.appendChild(navSection('Data'));
    nav.appendChild(navItem('Users', ['users'], m.user_count));
    nav.appendChild(navItem('Sessions', ['sessions'], m.session_count));
    nav.appendChild(navItem('Regions', ['regions'],
        Object.keys(state.data.region_counts).filter(k => k).length));
    nav.appendChild(navItem('Timelines', ['timelines']));
    side.appendChild(nav);
    return side;
}

function navSection(label) {
    return el('li', null, el('div', { class: 'nav-section' }, label));
}

function navItem(label, segs, count, params) {
    const target = hashFor(segs.length ? segs : [], params);
    const cur = window.location.hash || '#/';
    const isActive = (cur === target) || (cur === '#/' && target === '#/');
    return el('li', null,
        el('a', { href: target, class: isActive ? 'active' : '' },
            el('span', null, label),
            count !== undefined ? el('span', { class: 'badge' }, fmtNum(count)) : null));
}

// ============================================================
// Render
// ============================================================
function render() {
    const app = document.getElementById('app');
    clear(app);
    const { segs, params } = parseHash();
    const root = el('div', { class: 'app' });
    root.appendChild(buildSidebar());

    let main;
    try {
        if (segs.length === 0) main = viewOverview();
        else if (segs[0] === 'findings' && segs.length === 1) main = viewFindings(params);
        else if (segs[0] === 'finding' && segs.length === 2) main = viewFinding(segs[1]);
        else if (segs[0] === 'users') main = viewUsers(params);
        else if (segs[0] === 'user' && segs.length === 2) main = viewUser(segs[1]);
        else if (segs[0] === 'user' && segs.length === 4 && segs[2] === 'computer')
            main = viewComputer(segs[1], segs[3]);
        else if (segs[0] === 'sessions') main = viewSessions(params);
        else if (segs[0] === 'regions') main = viewRegions();
        else if (segs[0] === 'rules') main = viewRules(params);
        else if (segs[0] === 'timelines') main = viewTimelines(params);
        else main = el('div', null, el('h2', null, 'Not found'),
            linkTo('<- back to overview', ['']));
    } catch (err) {
        main = el('div', null, el('h2', null, 'Error rendering view'),
            el('pre', null, err.stack || err.message));
        console.error(err);
    }
    const wrap = el('main', { class: 'main' }, main);
    root.appendChild(wrap);
    app.appendChild(root);
}

window.addEventListener('hashchange', render);

(async function main() {
    try {
        state.data = await loadPayload();
    } catch (e) {
        const app = document.getElementById('app');
        clear(app);
        app.appendChild(el('div', { class: 'fail-banner' },
            el('strong', null, 'Could not load data.'),
            el('br'),
            String(e && e.message || e)));
        return;
    }
    render();
})();
</script>
</body>
</html>
"""


def render_html(payload, out_path):
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    gz = gzip.compress(raw, compresslevel=9)
    b64 = base64.b64encode(gz).decode("ascii")
    html_text = HTML_TEMPLATE.replace("__PAYLOAD__", b64)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html_text)


def archive_existing(path, logger=None):
    """Rename an existing output file to include its mtime stamp.

    Insert a 'YYYYMMDDTHHMMSSZ' UTC segment between stem and extension,
    e.g. 'summary.html' -> 'summary.20260427T123012Z.html'. UTC keeps the
    stamp unambiguous when archives are shared across timezones (relevant
    for incident-response forensics). No-op if the file does not exist.
    Returns the new path on success, or None.

    The target name is claimed atomically with O_CREAT|O_EXCL, so two
    concurrent runs in the same directory cannot silently overwrite each
    other's archives even when their mtime stamps collide.
    """
    try:
        mtime_secs = os.path.getmtime(path)
    except FileNotFoundError:
        return None
    mtime = dt.datetime.utcfromtimestamp(mtime_secs)
    stem, ext = os.path.splitext(path)
    stamp = mtime.strftime("%Y%m%dT%H%M%SZ")

    # Atomically claim a unique archive name. Each iteration tries to
    # create the file with O_CREAT|O_EXCL: that operation is atomic on
    # POSIX and Windows, so only one concurrent caller can ever succeed
    # for a given name. If the name is taken, append a counter and
    # retry. The cap of 1000 prevents an infinite loop if the directory
    # somehow already contains every variant.
    counter = 0
    target = None
    while counter < 1000:
        candidate = ("{0}.{1}{2}".format(stem, stamp, ext) if counter == 0
                     else "{0}.{1}_{2}{3}".format(stem, stamp, counter, ext))
        try:
            fd = os.open(candidate,
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            counter += 1
            continue
        os.close(fd)
        target = candidate
        break
    if target is None:
        raise RuntimeError(
            "Could not find a unique archive name for {0!r}".format(path))

    # Replace the placeholder with the real source. os.replace is atomic
    # on POSIX and on Windows when source and target share a volume.
    os.replace(path, target)
    if logger:
        logger.info("Archived %s -> %s.", path, target)
    return target


# ============================================================
# CLI / main
# ============================================================

def setup_logger(verbose):
    logger = logging.getLogger("gpanalyze")
    logger.handlers.clear()
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s",
                                     datefmt="%H:%M:%S"))
    logger.addHandler(h)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    return logger


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Consolidate GlobalProtect CSV exports and "
                    "produce an interactive anomaly dashboard.")
    p.add_argument("--input-dir", default=".",
                   help="Directory containing the CSV exports (default: cwd).")
    p.add_argument("--output-dir", default=None,
                   help="Where to write outputs (default: same as --input-dir).")
    p.add_argument("--anchor-date", type=parse_anchor_arg, default=None,
                   help="Override anchor date for year inference (YYYY-MM-DD). "
                        "Defaults to per-file detection from filename, then today.")
    p.add_argument("--baseline-region", default=DEFAULT_BASELINE_REGION,
                   help="Baseline ISO-2 region considered normal. "
                        "If omitted, auto-detected as the most common ISO-2 "
                        "region in the dataset.")
    p.add_argument("--no-html", action="store_true", help="Skip HTML output.")
    p.add_argument("--no-csv", action="store_true",
                   help="Skip consolidated CSV output.")
    p.add_argument("--no-archive", action="store_true",
                   help="Overwrite existing outputs instead of archiving them "
                        "with a timestamp suffix.")
    p.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS,
                   help="Abort if input contains more than this many session "
                        "rows (default: {0}). Pass 0 to disable.".format(
                            DEFAULT_MAX_ROWS))
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logger = setup_logger(args.verbose)
    out_dir = args.output_dir or args.input_dir

    sessions, errors = load_csvs(args.input_dir, args.anchor_date, logger,
                                  max_rows=args.max_rows or None)
    logger.info("Loaded %d session(s), %d parse error(s).", len(sessions), len(errors))

    baseline_region = args.baseline_region
    if baseline_region:
        logger.info("Baseline region (explicit): %s.", baseline_region)
    else:
        baseline_region = detect_baseline_region(sessions)
        if baseline_region:
            logger.info("Baseline region (auto-detected): %s.", baseline_region)
        else:
            logger.warning("No ISO-2 baseline region could be detected; "
                           "R18 will be skipped.")

    findings = run_all_rules(sessions, errors, baseline_region, logger)

    if not args.no_csv:
        path = os.path.join(out_dir, CONSOLIDATED_CSV)
        if not args.no_archive:
            archive_existing(path, logger)
        write_consolidated_csv(path, sessions)
        logger.info("Wrote %s (%d rows).", path, len(sessions))

    if not args.no_html:
        payload = build_payload(sessions, findings, baseline_region)
        path = os.path.join(out_dir, SUMMARY_HTML)
        if not args.no_archive:
            archive_existing(path, logger)
        render_html(payload, path)
        logger.info("Wrote %s (%.1f KB).", path,
                    os.path.getsize(path) / 1024)

    sev_summary = Counter(f["severity"] for f in findings)
    parts = ["{0}={1}".format(s, sev_summary.get(s, 0)) for s in
             reversed(SEVERITY_LEVELS) if sev_summary.get(s)]
    logger.info("Done. Findings by severity: %s",
                ", ".join(parts) if parts else "(none)")


if __name__ == "__main__":
    main()
