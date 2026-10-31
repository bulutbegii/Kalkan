import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from kalkan.models import Action, ActionResult, Plan, Risk
from kalkan import report


def _sample_plan():
    p = Plan(objective="web taraması", target="https://biri.com.tr")
    p.actions = [
        Action(tool="wafw00f", capability="waf_detect", target="https://biri.com.tr", risk=Risk.PASSIVE),
        Action(tool="nmap", capability="port_scan", target="https://biri.com.tr", risk=Risk.ACTIVE,
               args={"top_ports": 100}, technique="T1595"),
    ]
    p.notes = ["örnek not"]
    return p


def _sample_results(plan):
    return [
        ActionResult(action=plan.actions[0], status="ok", duration_s=1.2,
                     parsed={"detected": ["Cloudflare"], "count": 1}),
        ActionResult(action=plan.actions[1], status="ok", duration_s=6.4,
                     parsed={"open_ports": [80, 443], "findings": []}),
    ]


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_slug(self):
        self.assertEqual(report._slug("https://biri.com.tr:8443/x"), "biri.com.tr_8443_x")
        self.assertEqual(report._slug("10.0.0.5"), "10.0.0.5")

    def test_write_report_creates_dated_file(self):
        plan = _sample_plan()
        results = _sample_results(plan)
        when = datetime(2026, 10, 31, 15, 20, 33)
        path = report.write_report(plan, results, summary="kısa özet", scope="scope.json",
                                   out_dir=self.tmp.name, when=when)
        self.assertTrue(path.exists())
        self.assertEqual(path.name, "biri.com.tr_20261031-152033.md")
        md = path.read_text(encoding="utf-8")
        self.assertIn("# Kalkan Tarama Raporu", md)
        self.assertIn("https://biri.com.tr", md)
        self.assertIn("wafw00f.waf_detect", md)
        self.assertIn("Açık portlar: 80, 443", md)
        self.assertIn("WAF/CDN: Cloudflare", md)
        self.assertIn("kısa özet", md)
        self.assertIn("örnek not", md)

    def test_target_in_filename_historical(self):
        plan = _sample_plan()
        r = _sample_results(plan)
        p1 = report.write_report(plan, r, out_dir=self.tmp.name, when=datetime(2026, 1, 1, 1, 1, 1))
        p2 = report.write_report(plan, r, out_dir=self.tmp.name, when=datetime(2026, 1, 2, 2, 2, 2))
        self.assertNotEqual(p1.name, p2.name)
        self.assertEqual(len(list(Path(self.tmp.name).glob("*.md"))), 2)


if __name__ == "__main__":
    unittest.main()
