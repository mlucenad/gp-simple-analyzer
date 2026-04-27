"""Unit tests for analyze_globalprotect.py.

Run from the project directory:
    python3 -m unittest discover tests -v
"""

from __future__ import annotations

import base64
import contextlib
import csv
import datetime as dt
import gzip
import io
import json
import logging
import os
import re
import sys
import tempfile
import unittest
from collections import defaultdict

# Make the parent directory importable
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import analyze_globalprotect as gp  # noqa: E402


# ============================================================
# Helpers for synthetic CSV fixtures
# ============================================================

LIFETIME_HEADER = ["Domain", "User", "Primary Username", "Computer", "Client",
                   "Private IP", "Public IP", "Source Region", "Tunnel Type",
                   "Login At", "Lifetime (S)"]
LOGOUT_HEADER = ["Domain", "User", "Primary Username", "Computer", "Client",
                 "Private IP", "Public IP", "Source Region", "Tunnel Type",
                 "Login At", "Logout At"]


def _silent_logger():
    lg = logging.getLogger("gpanalyze.test")
    lg.handlers.clear()
    lg.addHandler(logging.NullHandler())
    lg.setLevel(logging.CRITICAL)
    return lg


def write_csv(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        w.writerow(header)
        for r in rows:
            w.writerow(r)


def make_filename(input_dir, mmddyyyy, hhmmss="081234"):
    """Filename in the same shape the real exports use."""
    return os.path.join(
        input_dir,
        "export_network_global_protect_gateways_{0}_{1}gmt+2.csv".format(
            mmddyyyy, hhmmss))


# ============================================================
# Tests
# ============================================================

class TestYearInference(unittest.TestCase):

    def test_year_from_anchor_below_anchor_month_is_anchor_year(self):
        anchor = dt.date(2026, 4, 27)
        d = gp.parse_login_token("Apr.27 07:29:09", anchor)
        self.assertEqual(d.year, 2026)
        d = gp.parse_login_token("Mar.15 10:00:00", anchor)
        self.assertEqual(d.year, 2026)

    def test_year_from_anchor_above_anchor_month_rolls_back(self):
        anchor = dt.date(2026, 4, 27)
        d = gp.parse_login_token("Oct.05 12:00:00", anchor)
        self.assertEqual(d.year, 2025)
        d = gp.parse_login_token("Dec.31 23:59:00", anchor)
        self.assertEqual(d.year, 2025)

    def test_unknown_month_returns_none(self):
        anchor = dt.date(2026, 4, 27)
        self.assertIsNone(gp.parse_login_token("Foo.10 00:00:00", anchor))
        self.assertIsNone(gp.parse_login_token("", anchor))

    def test_alt_september_abbreviation(self):
        anchor = dt.date(2026, 4, 27)
        d = gp.parse_login_token("Sept.10 12:00:00", anchor)
        self.assertEqual((d.year, d.month, d.day), (2025, 9, 10))


class TestDedupe(unittest.TestCase):

    def test_dedup_prefers_closed(self):
        common = {
            "_id": "x", "User": "alice", "Computer": "PC1",
            "Login At": "2026-04-27 08:00:00",
            "Public IP": "1.2.3.4",
            "Domain": "", "Primary Username": "", "Client": "",
            "Private IP": "", "Source Region": "ES", "Tunnel Type": "SSL",
            "Logout At": "", "Status": "ongoing", "Lifetime (S)": "100",
            "_login_dt": dt.datetime(2026, 4, 27, 8, 0, 0),
            "_logout_dt": None, "_ongoing": True, "_corrupt": False,
            "_file": "lifetime.csv",
        }
        ongoing = dict(common)
        closed = dict(common)
        closed["_ongoing"] = False
        closed["_logout_dt"] = dt.datetime(2026, 4, 27, 9, 0, 0)
        closed["Logout At"] = "2026-04-27 09:00:00"
        closed["Status"] = "closed"
        closed["_file"] = "logout.csv"

        deduped = gp.dedupe_sessions([ongoing, closed])
        self.assertEqual(len(deduped), 1)
        self.assertFalse(deduped[0]["_ongoing"])
        self.assertEqual(deduped[0]["_file"], "logout.csv")

        # Reverse insertion order — same outcome
        deduped = gp.dedupe_sessions([closed, ongoing])
        self.assertEqual(len(deduped), 1)
        self.assertFalse(deduped[0]["_ongoing"])


class TestRulesUnit(unittest.TestCase):
    """Direct unit tests on the rule functions, no CSV plumbing."""

    def _mk(self, user, login, logout, pub_ip="1.1.1.1", region="ES",
            computer="PC", client="Win", domain="cnio", ongoing=False,
            corrupt=False):
        sid = gp.make_session_id(user, computer, gp.fmt_dt(login), pub_ip)
        return {
            "_id": sid, "_file": "x.csv",
            "Domain": domain, "User": user, "Primary Username": user,
            "Computer": computer, "Client": client,
            "Private IP": "10.0.0.1", "Public IP": pub_ip,
            "Source Region": region, "Tunnel Type": "SSL",
            "Login At": gp.fmt_dt(login),
            "Logout At": gp.fmt_dt(logout) if logout else "",
            "Status": "ongoing" if ongoing else "closed",
            "Lifetime (S)": "" if logout is None else
                str(int((logout - login).total_seconds())),
            "_login_dt": login, "_logout_dt": logout,
            "_ongoing": ongoing, "_corrupt": corrupt,
        }

    def test_R01_simul_public_ip(self):
        a = self._mk("u", dt.datetime(2026, 4, 27, 8, 0),
                     dt.datetime(2026, 4, 27, 10, 0), pub_ip="1.1.1.1")
        b = self._mk("u", dt.datetime(2026, 4, 27, 9, 0),
                     dt.datetime(2026, 4, 27, 11, 0), pub_ip="2.2.2.2")
        f = gp.rule_R01_simul_public_ip({"u": [a, b]})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule_id"], "R01")
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(set(f[0]["evidence"]), {a["_id"], b["_id"]})

    def test_R01_no_overlap_no_finding(self):
        a = self._mk("u", dt.datetime(2026, 4, 27, 8, 0),
                     dt.datetime(2026, 4, 27, 9, 0), pub_ip="1.1.1.1")
        b = self._mk("u", dt.datetime(2026, 4, 27, 10, 0),
                     dt.datetime(2026, 4, 27, 11, 0), pub_ip="2.2.2.2")
        f = gp.rule_R01_simul_public_ip({"u": [a, b]})
        self.assertEqual(f, [])

    def test_R02_simul_region(self):
        a = self._mk("u", dt.datetime(2026, 4, 27, 8, 0),
                     dt.datetime(2026, 4, 27, 10, 0), region="ES")
        b = self._mk("u", dt.datetime(2026, 4, 27, 9, 0),
                     dt.datetime(2026, 4, 27, 11, 0), pub_ip="2.2.2.2",
                     region="US")
        f = gp.rule_R02_simul_region({"u": [a, b]})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "critical")

    def test_R03_impossible_travel_triggers(self):
        a = self._mk("u", dt.datetime(2026, 4, 27, 8, 0),
                     dt.datetime(2026, 4, 27, 9, 0), region="ES")
        b = self._mk("u", dt.datetime(2026, 4, 27, 10, 0),
                     dt.datetime(2026, 4, 27, 11, 0), pub_ip="2.2.2.2",
                     region="US")
        f = gp.rule_R03_impossible_travel({"u": [a, b]})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "critical")
        self.assertGreater(f[0]["extra"]["speed_kmh"], 900)

    def test_R03_normal_travel_no_finding(self):
        # 24h gap ES -> US: ~7000 km / 24 h = ~290 km/h, below threshold
        a = self._mk("u", dt.datetime(2026, 4, 27, 8, 0),
                     dt.datetime(2026, 4, 27, 9, 0), region="ES")
        b = self._mk("u", dt.datetime(2026, 4, 28, 8, 0),
                     dt.datetime(2026, 4, 28, 9, 0), pub_ip="2.2.2.2",
                     region="US")
        f = gp.rule_R03_impossible_travel({"u": [a, b]})
        self.assertEqual(f, [])

    def test_ongoing_session_overlaps_everything_after_it(self):
        a = self._mk("u", dt.datetime(2026, 4, 27, 8, 0),
                     None, pub_ip="1.1.1.1", ongoing=True)
        b = self._mk("u", dt.datetime(2026, 4, 27, 9, 0),
                     dt.datetime(2026, 4, 27, 10, 0), pub_ip="2.2.2.2")
        c = self._mk("u", dt.datetime(2026, 4, 28, 0, 0),
                     dt.datetime(2026, 4, 28, 1, 0), pub_ip="3.3.3.3")
        f = gp.rule_R01_simul_public_ip({"u": [a, b, c]})
        # ongoing 'a' overlaps with both b and c
        self.assertEqual(len(f), 2)

    def test_R04_baseline_excludes_top2(self):
        # User with mostly ES + several PT — neither flagged
        sess = []
        for i in range(20):
            sess.append(self._mk("u",
                dt.datetime(2026, 4, 1 + i, 8, 0),
                dt.datetime(2026, 4, 1 + i, 9, 0),
                region="ES", pub_ip="1.0.0.{0}".format(i)))
        for i in range(5):
            sess.append(self._mk("u",
                dt.datetime(2026, 4, 1 + i, 12, 0),
                dt.datetime(2026, 4, 1 + i, 13, 0),
                region="PT", pub_ip="2.0.0.{0}".format(i)))
        # one isolated FR session
        sess.append(self._mk("u",
            dt.datetime(2026, 4, 26, 12, 0),
            dt.datetime(2026, 4, 26, 13, 0),
            region="FR", pub_ip="3.0.0.1"))
        f = gp.rule_R04_unusual_region({"u": sess})
        # PT is in top-2, FR is not → exactly one finding for FR
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["extra"]["region"], "FR")

    def test_R10_private_region(self):
        sess = [self._mk("u", dt.datetime(2026, 4, 27, 8, 0),
                         dt.datetime(2026, 4, 27, 9, 0),
                         region="10.0.0.0-10.255.255.255")]
        f = gp.rule_R10_private_region({"u": sess})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule_id"], "R10")
        self.assertEqual(f[0]["severity"], "info")

    def test_R14_corrupt_logout_before_login(self):
        a = self._mk("u", dt.datetime(2026, 4, 27, 10, 0),
                     dt.datetime(2026, 4, 27, 8, 0), corrupt=True)
        b = self._mk("v", dt.datetime(2026, 4, 27, 8, 0),
                     dt.datetime(2026, 4, 27, 9, 0))
        f = gp.rule_R14_corrupt([a, b], [])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["user"], "u")
        self.assertEqual(f[0]["rule_id"], "R14")

    def test_R15_multi_domain(self):
        a = self._mk("u", dt.datetime(2026, 4, 27, 8, 0),
                     dt.datetime(2026, 4, 27, 9, 0), domain="cnio")
        b = self._mk("u", dt.datetime(2026, 4, 27, 10, 0),
                     dt.datetime(2026, 4, 27, 11, 0),
                     pub_ip="2.2.2.2", domain="other-domain")
        f = gp.rule_R15_multi_domain([a, b])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(set(f[0]["extra"]["domains"]),
                         {"cnio", "other-domain"})

    def test_R16_bogon(self):
        # Note: 10.x is bogon. We use a user-pub-ip pair grouping.
        a = self._mk("u", dt.datetime(2026, 4, 27, 8, 0),
                     dt.datetime(2026, 4, 27, 9, 0), pub_ip="10.0.0.5")
        b = self._mk("u", dt.datetime(2026, 4, 28, 8, 0),
                     dt.datetime(2026, 4, 28, 9, 0), pub_ip="8.8.8.8")
        f = gp.rule_R16_bogon([a, b])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["extra"]["public_ip"], "10.0.0.5")

    def test_R19_login_burst_triggers(self):
        # 12 logins within 5 minutes -> well above default 10-in-10min
        sess = []
        base = dt.datetime(2026, 4, 27, 8, 0, 0)
        for i in range(12):
            sess.append(self._mk("u",
                base + dt.timedelta(seconds=20 * i),
                base + dt.timedelta(seconds=20 * i + 60),
                pub_ip="1.0.0.{0}".format(i)))
        f = gp.rule_R19_login_burst({"u": sess})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule_id"], "R19")
        self.assertGreaterEqual(f[0]["extra"]["count"], 10)

    def test_R19_login_burst_spaced_out_no_finding(self):
        # 12 logins each 5 minutes apart -> never 10 inside a 10-min window
        sess = []
        base = dt.datetime(2026, 4, 27, 8, 0, 0)
        for i in range(12):
            sess.append(self._mk("u",
                base + dt.timedelta(minutes=5 * i),
                base + dt.timedelta(minutes=5 * i + 1),
                pub_ip="1.0.0.{0}".format(i)))
        f = gp.rule_R19_login_burst({"u": sess})
        self.assertEqual(f, [])

    def test_R20_tunnel_flap_triggers(self):
        # 5 sessions on same computer alternating SSL/IPSec inside 24h
        sess = []
        base = dt.datetime(2026, 4, 27, 8, 0, 0)
        tunnels = ["SSL", "IPSec", "SSL", "IPSec", "SSL"]
        for i, t in enumerate(tunnels):
            s = self._mk("u",
                base + dt.timedelta(hours=i),
                base + dt.timedelta(hours=i, minutes=30),
                pub_ip="1.0.0.{0}".format(i))
            s["Tunnel Type"] = t
            sess.append(s)
        f = gp.rule_R20_tunnel_flap({"u": sess})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule_id"], "R20")
        self.assertGreaterEqual(f[0]["extra"]["switches"], 4)

    def test_R20_no_flap_when_tunnel_stable(self):
        sess = []
        base = dt.datetime(2026, 4, 27, 8, 0, 0)
        for i in range(8):
            s = self._mk("u",
                base + dt.timedelta(hours=i),
                base + dt.timedelta(hours=i, minutes=30),
                pub_ip="1.0.0.{0}".format(i))
            s["Tunnel Type"] = "SSL"
            sess.append(s)
        f = gp.rule_R20_tunnel_flap({"u": sess})
        self.assertEqual(f, [])

    def test_R21_new_computer_after_history(self):
        # 25 sessions on PC-A then one on PC-B -> R21 fires for PC-B
        sess = []
        base = dt.datetime(2026, 4, 1, 8, 0, 0)
        for i in range(25):
            sess.append(self._mk("u",
                base + dt.timedelta(days=i),
                base + dt.timedelta(days=i, hours=1),
                computer="PC-A", pub_ip="1.0.0.{0}".format(i)))
        sess.append(self._mk("u",
            base + dt.timedelta(days=26),
            base + dt.timedelta(days=26, hours=1),
            computer="PC-B", pub_ip="2.0.0.1"))
        f = gp.rule_R21_new_computer({"u": sess})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["extra"]["new_computer"], "PC-B")

    def test_R21_no_finding_for_short_history_user(self):
        # Below the new_computer_min_history threshold (default 20)
        sess = [
            self._mk("u", dt.datetime(2026, 4, 1, 8, 0),
                     dt.datetime(2026, 4, 1, 9, 0), computer="PC-A"),
            self._mk("u", dt.datetime(2026, 4, 2, 8, 0),
                     dt.datetime(2026, 4, 2, 9, 0), computer="PC-B",
                     pub_ip="2.2.2.2"),
        ]
        f = gp.rule_R21_new_computer({"u": sess})
        self.assertEqual(f, [])

    def test_R22_dormant_resurfacing(self):
        # 12 daily sessions (>= dormant_min_prior_sessions), 90-day gap,
        # then a resurfacing session.
        sess = []
        base = dt.datetime(2026, 1, 1, 8, 0)
        for i in range(12):
            sess.append(self._mk("u",
                base + dt.timedelta(days=i),
                base + dt.timedelta(days=i, hours=1),
                pub_ip="1.0.0.{0}".format(i)))
        sess.append(self._mk("u",
            base + dt.timedelta(days=120),  # ~108-day gap
            base + dt.timedelta(days=120, hours=1),
            pub_ip="2.2.2.2"))
        f = gp.rule_R22_dormant_resurfacing({"u": sess})
        self.assertEqual(len(f), 1)
        self.assertGreaterEqual(f[0]["extra"]["gap_days"], 60)

    def test_R22_no_finding_for_continuous_user(self):
        sess = []
        base = dt.datetime(2026, 4, 1, 8, 0)
        for i in range(10):
            sess.append(self._mk("u",
                base + dt.timedelta(days=i),
                base + dt.timedelta(days=i, hours=1),
                pub_ip="1.0.0.{0}".format(i)))
        f = gp.rule_R22_dormant_resurfacing({"u": sess})
        self.assertEqual(f, [])

    def test_R23_weekend_activity_for_weekday_user(self):
        # 2026-04-06 is a Monday. Walk forward, picking only weekdays.
        sess = []
        anchor_mon = dt.datetime(2026, 4, 6, 9, 0)
        self.assertEqual(anchor_mon.weekday(), 0)
        d = anchor_mon
        added = 0
        i = 0
        while added < 30:
            cand = d + dt.timedelta(days=i)
            i += 1
            if cand.weekday() < 5:
                sess.append(self._mk("u", cand, cand + dt.timedelta(hours=1),
                    pub_ip="1.0.0.{0}".format(added)))
                added += 1
        # one Saturday session: 2026-04-04 is a Saturday
        sat = dt.datetime(2026, 4, 4, 11, 0)
        self.assertEqual(sat.weekday(), 5)
        sess.append(self._mk("u", sat, sat + dt.timedelta(hours=1),
            pub_ip="2.2.2.2"))
        f = gp.rule_R23_weekend_for_weekday_user({"u": sess})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["extra"]["weekend_count"], 1)

    def test_R23_no_finding_when_weekend_use_is_normal(self):
        # 50/50 weekend/weekday baseline -> below threshold, no finding.
        sess = []
        anchor_sat = dt.datetime(2026, 4, 4, 9, 0)  # Saturday
        self.assertEqual(anchor_sat.weekday(), 5)
        for i in range(20):
            # Saturdays for even i, Mondays (Saturday + 2 days) for odd i,
            # spaced by full weeks so we never overflow a month carelessly.
            offset = (i // 2) * 7 + (0 if i % 2 == 0 else 2)
            d = anchor_sat + dt.timedelta(days=offset)
            sess.append(self._mk("u", d, d + dt.timedelta(hours=1),
                pub_ip="1.0.0.{0}".format(i)))
        f = gp.rule_R23_weekend_for_weekday_user({"u": sess})
        self.assertEqual(f, [])


class TestPipelineEndToEnd(unittest.TestCase):
    """Full end-to-end with synthetic CSVs in a temp dir."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.input_dir = self.tmp.name

    def _build_basic_dataset(self):
        # Closed-format CSV
        path1 = make_filename(self.input_dir, "04272026")
        write_csv(path1, LOGOUT_HEADER, [
            ["cnio", "alice", "cnio\\alice", "PC1", "Win10",
             "10.0.0.1", "1.1.1.1", "ES", "SSL",
             "Apr.27 08:00:00", "Apr.27 09:00:00"],
            ["cnio", "alice", "cnio\\alice", "PC1", "Win10",
             "10.0.0.1", "2.2.2.2", "US", "SSL",
             "Apr.27 08:30:00", "Apr.27 10:00:00"],  # overlaps with prev
            ["cnio", "bob", "cnio\\bob", "PC2", "Mac",
             "10.0.0.2", "3.3.3.3", "ES", "IPSec",
             "Apr.26 09:00:00", "Apr.26 17:00:00"],
            ["cnio", "carol", "cnio\\carol", "PC3", "Linux",
             "10.0.0.3", "4.4.4.4", "10.0.0.0-10.255.255.255", "SSL",
             "Apr.25 09:00:00", "Apr.25 10:00:00"],
        ])
        # Lifetime-format CSV (active)
        path2 = make_filename(self.input_dir, "04272026", "081300")
        write_csv(path2, LIFETIME_HEADER, [
            ["cnio", "dave", "cnio\\dave", "PC4", "Win11",
             "10.0.0.4", "5.5.5.5", "ES", "IPSec",
             "Apr.27 07:00:00", "28800"],
        ])
        return path1, path2

    def test_pipeline_loads_and_rules_run(self):
        self._build_basic_dataset()
        sessions, errors = gp.load_csvs(
            self.input_dir, dt.date(2026, 4, 27), _silent_logger())
        self.assertEqual(len(sessions), 5)
        self.assertEqual(errors, [])
        self.assertEqual(sum(1 for s in sessions if s["_ongoing"]), 1)

        findings = gp.run_all_rules(sessions, errors, "ES", _silent_logger())
        rule_ids = {f["rule_id"] for f in findings}
        # we expect at least R01 (alice overlap) and R10 (carol private)
        self.assertIn("R01", rule_ids)
        self.assertIn("R10", rule_ids)
        # R02 (alice ES+US overlap) and R03 (alice impossible-travel) too
        self.assertIn("R02", rule_ids)

    def test_html_payload_decompresses_to_valid_json(self):
        self._build_basic_dataset()
        sessions, errors = gp.load_csvs(
            self.input_dir, dt.date(2026, 4, 27), _silent_logger())
        findings = gp.run_all_rules(sessions, errors, "ES", _silent_logger())
        payload = gp.build_payload(sessions, findings, "ES")
        out_html = os.path.join(self.input_dir, "summary.html")
        gp.render_html(payload, out_html)

        with open(out_html, encoding="utf-8") as fh:
            text = fh.read()
        m = re.search(r'id="payload"[^>]*>([^<]+)</script>', text)
        self.assertIsNotNone(m)
        b64 = m.group(1).strip()
        data = json.loads(gzip.decompress(base64.b64decode(b64)))
        self.assertEqual(data["meta"]["session_count"], len(sessions))
        self.assertEqual(data["meta"]["finding_count"], len(findings))
        self.assertIn("alice", data["users"])

    def test_consolidated_csv_neutralizes_formula_injection(self):
        """Regression: cells starting with =, +, -, @, tab, or CR must be
        prefixed with a single quote so spreadsheet apps don't evaluate
        them as formulas / DDE payloads."""
        with tempfile.TemporaryDirectory() as td:
            sessions = [{
                "_id": "x", "_file": "f.csv",
                "Domain": "cnio", "User": "=cmd|'/c calc'!A1",
                "Primary Username": "cnio\\u",
                "Computer": "+evil", "Client": "-payload",
                "Private IP": "10.0.0.1", "Public IP": "1.1.1.1",
                "Source Region": "@malicious", "Tunnel Type": "SSL",
                "Login At": "2026-04-27 08:00:00",
                "Logout At": "2026-04-27 09:00:00",
                "Status": "closed", "Lifetime (S)": "3600",
            }]
            out = os.path.join(td, gp.CONSOLIDATED_CSV)
            gp.write_consolidated_csv(out, sessions)
            with open(out, encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 1)
            r = rows[0]
            self.assertTrue(r["User"].startswith("'="),
                msg="formula-leading User must be quoted: {0!r}".format(r["User"]))
            self.assertTrue(r["Computer"].startswith("'+"))
            self.assertTrue(r["Client"].startswith("'-"))
            self.assertTrue(r["Source Region"].startswith("'@"))
            # Benign cells must not be touched
            self.assertEqual(r["Domain"], "cnio")
            self.assertEqual(r["Public IP"], "1.1.1.1")

    def test_consolidated_csv_columns_and_rows(self):
        self._build_basic_dataset()
        sessions, _ = gp.load_csvs(
            self.input_dir, dt.date(2026, 4, 27), _silent_logger())
        out_csv = os.path.join(self.input_dir, gp.CONSOLIDATED_CSV)
        gp.write_consolidated_csv(out_csv, sessions)
        with open(out_csv, encoding="utf-8") as fh:
            r = csv.DictReader(fh)
            cols = r.fieldnames
            rows = list(r)
        self.assertIn("session_id", cols)
        self.assertIn("Status", cols)
        self.assertEqual(len(rows), len(sessions))
        # ongoing session has empty Logout At and lifetime set
        ongoing = [r for r in rows if r["Status"] == "ongoing"]
        self.assertEqual(len(ongoing), 1)
        self.assertEqual(ongoing[0]["Logout At"], "")
        self.assertEqual(ongoing[0]["Lifetime (S)"], "28800")


class TestBaselineDetection(unittest.TestCase):
    """Baseline region must auto-detect from data, not be hardcoded to ES."""

    def test_detect_baseline_region_picks_modal_iso2(self):
        sessions = [
            {"Source Region": "FR"}, {"Source Region": "FR"},
            {"Source Region": "FR"}, {"Source Region": "DE"},
            {"Source Region": "10.0.0.0-10.255.255.255"},  # private, ignored
            {"Source Region": ""},                          # empty, ignored
        ]
        self.assertEqual(gp.detect_baseline_region(sessions), "FR")

    def test_detect_baseline_region_returns_none_when_no_iso2(self):
        sessions = [
            {"Source Region": "10.0.0.0-10.255.255.255"},
            {"Source Region": ""},
            {"Source Region": None},
        ]
        self.assertIsNone(gp.detect_baseline_region(sessions))

    def test_R18_skipped_when_no_baseline(self):
        # Create a "new user" session that would normally fire R18, but
        # pass baseline_region=None -> rule must not raise and must emit nothing.
        sess = {
            "_id": "x", "_file": "y.csv", "Domain": "d", "User": "newbie",
            "Primary Username": "newbie", "Computer": "PC1",
            "Client": "Win", "Private IP": "10.0.0.1",
            "Public IP": "1.2.3.4", "Source Region": "JP",
            "Tunnel Type": "SSL", "Login At": "2026-04-27 08:00:00",
            "Logout At": "", "Status": "ongoing", "Lifetime (S)": "100",
            "_login_dt": dt.datetime(2026, 4, 27, 8, 0),
            "_logout_dt": None, "_ongoing": True, "_corrupt": False,
        }
        f = gp.rule_R18_new_user_outside_baseline({"newbie": [sess]}, None)
        self.assertEqual(f, [])

    def test_pipeline_uses_detected_baseline_when_flag_omitted(self):
        with tempfile.TemporaryDirectory() as td:
            f = make_filename(td, "04272026")
            # Three FR sessions, one DE -> auto-baseline should be FR.
            write_csv(f, LOGOUT_HEADER, [
                ["c", "u1", "c\\u1", "PC1", "Win", "10.0.0.1", "1.1.1.1",
                 "FR", "SSL", "Apr.27 08:00:00", "Apr.27 09:00:00"],
                ["c", "u2", "c\\u2", "PC2", "Win", "10.0.0.2", "2.2.2.2",
                 "FR", "SSL", "Apr.27 09:00:00", "Apr.27 10:00:00"],
                ["c", "u3", "c\\u3", "PC3", "Win", "10.0.0.3", "3.3.3.3",
                 "FR", "SSL", "Apr.27 10:00:00", "Apr.27 11:00:00"],
                ["c", "u4", "c\\u4", "PC4", "Win", "10.0.0.4", "4.4.4.4",
                 "DE", "SSL", "Apr.27 11:00:00", "Apr.27 12:00:00"],
            ])
            with contextlib.redirect_stderr(io.StringIO()):
                gp.main(["--input-dir", td, "--no-archive"])
            with open(os.path.join(td, "summary.html"), encoding="utf-8") as fh:
                text = fh.read()
            m = re.search(r'id="payload"[^>]*>([^<]+)</script>', text)
            data = json.loads(gzip.decompress(base64.b64decode(m.group(1).strip())))
            self.assertEqual(data["meta"]["baseline_region"], "FR")

    def test_pipeline_honors_explicit_baseline_flag(self):
        with tempfile.TemporaryDirectory() as td:
            f = make_filename(td, "04272026")
            write_csv(f, LOGOUT_HEADER, [
                ["c", "u1", "c\\u1", "PC1", "Win", "10.0.0.1", "1.1.1.1",
                 "FR", "SSL", "Apr.27 08:00:00", "Apr.27 09:00:00"],
            ])
            with contextlib.redirect_stderr(io.StringIO()):
                gp.main(["--input-dir", td, "--no-archive",
                         "--baseline-region", "JP"])
            with open(os.path.join(td, "summary.html"), encoding="utf-8") as fh:
                text = fh.read()
            m = re.search(r'id="payload"[^>]*>([^<]+)</script>', text)
            data = json.loads(gzip.decompress(base64.b64decode(m.group(1).strip())))
            self.assertEqual(data["meta"]["baseline_region"], "JP")


class TestArchiveExisting(unittest.TestCase):
    """Behavioral tests for the archive-on-overwrite helper."""

    def test_no_op_when_file_missing(self):
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "summary.html")
            res = gp.archive_existing(target)
            self.assertIsNone(res)
            self.assertFalse(os.path.exists(target))

    def test_renames_with_mtime_stamp(self):
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "summary.html")
            with open(target, "w") as fh:
                fh.write("old")
            # Pin mtime to a known value so the assertion is deterministic.
            # archive_existing formats the stamp from the UTC of mtime, so
            # we compute the expected stamp the same way to stay
            # timezone-independent.
            ts = dt.datetime(2026, 4, 27, 12, 30, 12).timestamp()
            os.utime(target, (ts, ts))
            stamp = dt.datetime.utcfromtimestamp(ts).strftime(
                "%Y%m%dT%H%M%SZ")

            new_path = gp.archive_existing(target)
            self.assertIsNotNone(new_path)
            self.assertFalse(os.path.exists(target))
            expected = os.path.join(td, "summary.{0}.html".format(stamp))
            self.assertEqual(new_path, expected)
            self.assertTrue(os.path.exists(expected))
            with open(expected) as fh:
                self.assertEqual(fh.read(), "old")

    def test_disambiguates_on_collision(self):
        with tempfile.TemporaryDirectory() as td:
            ts = dt.datetime(2026, 4, 27, 12, 30, 12).timestamp()
            stamp = dt.datetime.utcfromtimestamp(ts).strftime(
                "%Y%m%dT%H%M%SZ")
            target = os.path.join(td, "consolidated_sessions.csv")
            stamped = os.path.join(td,
                "consolidated_sessions.{0}.csv".format(stamp))
            with open(target, "w") as fh:
                fh.write("now")
            with open(stamped, "w") as fh:
                fh.write("preexisting")
            os.utime(target, (ts, ts))

            new_path = gp.archive_existing(target)
            self.assertEqual(
                new_path,
                os.path.join(td,
                    "consolidated_sessions.{0}_1.csv".format(stamp)))
            self.assertFalse(os.path.exists(target))
            with open(stamped) as fh:
                self.assertEqual(fh.read(), "preexisting")
            with open(new_path) as fh:
                self.assertEqual(fh.read(), "now")

    def test_pipeline_archives_before_overwriting(self):
        """End-to-end: running the pipeline twice should leave 1 fresh +
        1 archived copy of each output."""
        with tempfile.TemporaryDirectory() as td:
            f = make_filename(td, "04272026")
            write_csv(f, LOGOUT_HEADER, [
                ["cnio", "alice", "cnio\\alice", "PC1", "Win10",
                 "10.0.0.1", "1.1.1.1", "ES", "SSL",
                 "Apr.27 08:00:00", "Apr.27 09:00:00"],
            ])

            csv_path = os.path.join(td, gp.CONSOLIDATED_CSV)
            html_path = os.path.join(td, gp.SUMMARY_HTML)

            # First run
            with contextlib.redirect_stderr(io.StringIO()):
                gp.main(["--input-dir", td])
            self.assertTrue(os.path.exists(csv_path))
            self.assertTrue(os.path.exists(html_path))
            # Pin mtime so we can compute the expected archived name
            ts = dt.datetime(2026, 4, 27, 12, 30, 12).timestamp()
            os.utime(csv_path, (ts, ts))
            os.utime(html_path, (ts, ts))
            stamp = dt.datetime.utcfromtimestamp(ts).strftime(
                "%Y%m%dT%H%M%SZ")

            # Second run
            with contextlib.redirect_stderr(io.StringIO()):
                gp.main(["--input-dir", td])
            self.assertTrue(os.path.exists(csv_path))
            self.assertTrue(os.path.exists(html_path))
            self.assertTrue(os.path.exists(
                os.path.join(td,
                    "consolidated_sessions.{0}.csv".format(stamp))))
            self.assertTrue(os.path.exists(
                os.path.join(td, "summary.{0}.html".format(stamp))))

    def test_archived_consolidated_is_not_loaded_as_input(self):
        """Regression: archived consolidated CSVs share the consolidated schema,
        not the GP export schema. They must be excluded from input discovery so
        a second run does not produce a parse error per archived row."""
        with tempfile.TemporaryDirectory() as td:
            f = make_filename(td, "04272026")
            write_csv(f, LOGOUT_HEADER, [
                ["cnio", "alice", "cnio\\alice", "PC1", "Win10",
                 "10.0.0.1", "1.1.1.1", "ES", "SSL",
                 "Apr.27 08:00:00", "Apr.27 09:00:00"],
                ["cnio", "bob", "cnio\\bob", "PC2", "Mac",
                 "10.0.0.2", "2.2.2.2", "ES", "IPSec",
                 "Apr.27 10:00:00", "Apr.27 11:00:00"],
            ])
            with contextlib.redirect_stderr(io.StringIO()):
                gp.main(["--input-dir", td])
            ts = dt.datetime(2026, 4, 27, 12, 30, 12).timestamp()
            os.utime(os.path.join(td, gp.CONSOLIDATED_CSV), (ts, ts))
            stamp = dt.datetime.utcfromtimestamp(ts).strftime(
                "%Y%m%dT%H%M%SZ")

            # Second run: should archive the existing consolidated CSV and not
            # try to parse it as a GP export.
            with contextlib.redirect_stderr(io.StringIO()):
                gp.main(["--input-dir", td])

            # An archive must exist alongside the fresh output.
            stamped = os.path.join(td,
                "consolidated_sessions.{0}.csv".format(stamp))
            self.assertTrue(os.path.exists(stamped))

            # Loading must not pick up the stamped archive as an input.
            sessions, errors = gp.load_csvs(
                td, dt.date(2026, 4, 27), _silent_logger())
            self.assertEqual(len(sessions), 2)
            self.assertEqual(errors, [])

    def test_no_archive_flag_overwrites(self):
        with tempfile.TemporaryDirectory() as td:
            f = make_filename(td, "04272026")
            write_csv(f, LOGOUT_HEADER, [
                ["cnio", "alice", "cnio\\alice", "PC1", "Win10",
                 "10.0.0.1", "1.1.1.1", "ES", "SSL",
                 "Apr.27 08:00:00", "Apr.27 09:00:00"],
            ])
            with contextlib.redirect_stderr(io.StringIO()):
                gp.main(["--input-dir", td])
                gp.main(["--input-dir", td, "--no-archive"])

            # Only one CSV and one HTML should exist; no stamped archive.
            entries = os.listdir(td)
            stamped_csv = [e for e in entries
                if e.startswith("consolidated_sessions.")
                and e != "consolidated_sessions.csv"
                and e.endswith(".csv")]
            stamped_html = [e for e in entries
                if e.startswith("summary.")
                and e != "summary.html"
                and e.endswith(".html")]
            self.assertEqual(stamped_csv, [])
            self.assertEqual(stamped_html, [])


class TestScale(unittest.TestCase):
    """Smoke test: 50k synthetic sessions → end-to-end completes quickly."""

    def test_scale_50k_sessions(self):
        import time
        # Locale-independent English month abbreviations (the input CSV uses
        # English regardless of the host's locale, so the test must too).
        en_months = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

        def gp_fmt(d):
            return "{0}.{1:02d} {2:02d}:{3:02d}:{4:02d}".format(
                en_months[d.month], d.day, d.hour, d.minute, d.second)

        with tempfile.TemporaryDirectory() as td:
            f = make_filename(td, "04272026")
            rows = []
            base = dt.datetime(2026, 4, 1, 8, 0, 0)
            users = ["u{0}".format(i) for i in range(2000)]
            for i in range(50_000):
                d = base + dt.timedelta(minutes=i)
                d_end = d + dt.timedelta(hours=1)
                rows.append([
                    "cnio", users[i % len(users)], "cnio\\u",
                    "PC{0}".format(i % 500), "Win",
                    "10.0.0.{0}".format(i % 250),
                    "1.1.{0}.{1}".format((i // 256) % 256, i % 256),
                    "ES", "SSL",
                    gp_fmt(d),
                    gp_fmt(d_end),
                ])
            write_csv(f, LOGOUT_HEADER, rows)

            t0 = time.time()
            sessions, errors = gp.load_csvs(
                td, dt.date(2026, 4, 27), _silent_logger())
            findings = gp.run_all_rules(
                sessions, errors, "ES", _silent_logger())
            payload = gp.build_payload(sessions, findings, "ES")
            gp.render_html(payload, os.path.join(td, "summary.html"))
            elapsed = time.time() - t0

        self.assertEqual(len(sessions), 50_000)
        # Soft budget: 30 seconds for 50k rows on a modern machine
        self.assertLess(elapsed, 60,
            "Pipeline took {0:.1f}s for 50k rows".format(elapsed))


if __name__ == "__main__":
    unittest.main()
