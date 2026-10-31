import tempfile
import unittest
from pathlib import Path

from kalkan.feeds.events import FeedEvent, JsonlSink
from kalkan.feeds.scheduler import FeedConfig, FeedDaemon
from kalkan.knowledge.vuln import CveRecord, VulnStore


class TestJsonlSink(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "events.jsonl"
        self.sink = JsonlSink(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_emit_and_tail_roundtrip(self):
        self.sink.emit(FeedEvent(kind="cve.new", source="nvd", id="CVE-1", title="x"))
        self.sink.emit(FeedEvent(kind="cve.kev", source="kev", id="CVE-2", tier="critical"))
        events = self.sink.tail(limit=10)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1].id, "CVE-2")
        self.assertEqual(events[-1].kind, "cve.kev")

    def test_follow_yields_appended(self):
        self.sink.emit(FeedEvent(kind="cve.new", source="nvd", id="CVE-10"))
        self.sink.emit(FeedEvent(kind="cve.new", source="nvd", id="CVE-11"))
        got = []
        for ev in self.sink.follow(from_start=True):
            got.append(ev.id)
            if len(got) == 2:
                break
        self.assertEqual(got, ["CVE-10", "CVE-11"])

    def test_event_json_roundtrip(self):
        ev = FeedEvent(kind="feed.sync", source="nvd", data={"a": 1})
        back = FeedEvent.from_json(ev.to_json())
        self.assertEqual(back.kind, "feed.sync")
        self.assertEqual(back.data["a"], 1)


class _FakeStore(VulnStore):
    """Agdan bagimsiz store: sync() onceden yuklenmis kayitlari dondurur."""

    def __init__(self, home, records):
        super().__init__(home)
        for r in records:
            self.cves[r.id] = r
        self._fake_new = [r.id for r in records]

    def sync(self, **kwargs):
        return {
            "fetched": len(self._fake_new),
            "added": len(self._fake_new),
            "new": list(self._fake_new),
            "total": len(self.cves),
            "kev": sum(1 for r in self.cves.values() if r.kev),
            "synced_at": "2026-01-01T00:00:00+00:00",
        }


class TestFeedDaemon(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        records = [
            CveRecord(id="CVE-2024-1000", description="SQL injection", cwe=("CWE-89",),
                      base_score=9.8, severity="critical", kev=True, kev_added="2024-05-01"),
            CveRecord(id="CVE-2024-1001", description="RCE in parser", cwe=("CWE-94",),
                      base_score=9.1, severity="critical"),
            CveRecord(id="CVE-2024-1002", description="minor info leak", cwe=("CWE-200",),
                      base_score=3.1, severity="low"),
        ]
        self.store = _FakeStore(self.home / "vuln", records)
        self.sink = JsonlSink(self.home / "feeds" / "events.jsonl")
        self.daemon = FeedDaemon(
            config=FeedConfig(critical_score=40.0),
            home=self.home / "feeds",
            sink=self.sink,
            store=self.store,
        )
        self.daemon.sync_knowledge = lambda domain: []  # type: ignore[assignment]

    def tearDown(self):
        self.tmp.cleanup()

    def test_sync_vuln_emits_kind_per_tier(self):
        events = self.daemon.sync_vuln()
        kinds = {e.id: e.kind for e in events if e.id}
        self.assertEqual(kinds["CVE-2024-1000"], "cve.kev")
        self.assertEqual(kinds["CVE-2024-1001"], "cve.critical")
        self.assertEqual(kinds["CVE-2024-1002"], "cve.new")
        self.assertTrue(any(e.kind == "feed.sync" for e in events))

    def test_sync_vuln_attaches_bridge(self):
        events = self.daemon.sync_vuln()
        kev = next(e for e in events if e.id == "CVE-2024-1000")
        self.assertIn("attack", kev.data)
        self.assertIn("T1190", kev.data["attack"]["runnable"])

    def test_run_once_writes_state_and_pid_cleared(self):
        res = self.daemon.run(once=True, write_pid=True)
        self.assertEqual(res["cycles"], 1)
        self.assertFalse(self.daemon.pid_path.exists())
        st = self.daemon.status()
        self.assertIn("vuln_synced", st)
        self.assertEqual(st["store"]["cve_count"], 3)

    def test_max_events_per_cycle(self):
        self.daemon.config.max_events_per_cycle = 1
        events = self.daemon.sync_vuln()
        cve_events = [e for e in events if e.kind.startswith("cve.")]
        self.assertEqual(len(cve_events), 1)


class TestSuggestMsfSqli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        recs = [
            CveRecord(id="CVE-2017-0144", description="SMB RCE EternalBlue",
                      cwe=("CWE-20",), base_score=9.3, severity="critical",
                      kev=True, product="windows", vendor="microsoft"),
            CveRecord(id="CVE-2024-9001", description="SQL injection in shop",
                      cwe=("CWE-89",), base_score=8.8, severity="high", product="shop"),
        ]
        self.store = _FakeStore(Path(self.tmp.name) / "vuln", recs)

    def tearDown(self):
        self.tmp.cleanup()

    def test_msf_candidate_from_feed(self):
        from kalkan.feeds import suggest
        sugg = suggest.suggest_for_text("windows smb", store=self.store, min_score=0.0)
        cands = suggest.msf_candidates(sugg)
        self.assertTrue(cands)
        self.assertEqual(cands[0].msf_module, "exploit/windows/smb/ms17_010_eternalblue")

    def test_sqli_candidate_from_feed(self):
        from kalkan.feeds import suggest
        sugg = suggest.suggest_for_text("shop injection", store=self.store, min_score=0.0)
        sqli = suggest.sqli_candidates(sugg)
        self.assertTrue(any(s.cve == "CVE-2024-9001" for s in sqli))


class TestChatShim(unittest.TestCase):
    def test_shim_has_build_plan_attrs(self):
        from kalkan.cli import _chat_shim
        base = {"from_feed": True, "feed_min_score": 55.0, "max_risk": "active",
                "endpoint": "http://x", "model": "m", "arg": ["verify=1"]}
        ns = _chat_shim(base, "example.com port tara")
        for attr in ("text", "from_feed", "feed_min_score", "max_risk",
                     "module", "payload", "mode", "endpoint", "model", "arg"):
            self.assertTrue(hasattr(ns, attr), f"eksik alan: {attr}")
        self.assertEqual(ns.text, "example.com port tara")
        self.assertEqual(ns.arg, ["verify=1"])
        self.assertIsNone(ns.module)


class TestDefaultCommand(unittest.TestCase):
    def _inj(self, argv):
        from kalkan.cli import _inject_default_command
        return _inject_default_command(argv)

    def test_empty_becomes_home(self):
        self.assertEqual(self._inj([]), ["home"])

    def test_bare_global_flag_becomes_home(self):
        self.assertEqual(self._inj(["--scope", "s.json"]), ["--scope", "s.json", "home"])

    def test_flags_without_command_become_chat(self):
        self.assertEqual(self._inj(["--target", "x"]), ["chat", "--target", "x"])

    def test_known_command_untouched(self):
        self.assertEqual(self._inj(["plan", "--target", "x"]), ["plan", "--target", "x"])
        self.assertEqual(self._inj(["--scope", "s", "run"]), ["--scope", "s", "run"])

    def test_help_untouched(self):
        self.assertEqual(self._inj(["--help"]), ["--help"])
        self.assertEqual(self._inj(["-h"]), ["-h"])


class TestNucleiCveId(unittest.TestCase):
    def _cmd(self, args):
        from kalkan.adapters.nuclei import NucleiAdapter
        from kalkan.models import Action, Risk
        action = Action(tool="nuclei", capability="web_template",
                        target="http://x", args=args, risk=Risk.ACTIVE)
        return NucleiAdapter().command(action)

    def test_cve_id_adds_id_flag_and_drops_tags(self):
        cmd = self._cmd({"cve_id": "CVE-2024-0001", "tags": "cve,exposure"})
        self.assertIn("-id", cmd)
        self.assertEqual(cmd[cmd.index("-id") + 1], "CVE-2024-0001")
        self.assertNotIn("-tags", cmd)

    def test_multiple_cve_ids_joined(self):
        cmd = self._cmd({"cve_id": ["CVE-2024-0001", "CVE-2024-0002"]})
        self.assertEqual(cmd[cmd.index("-id") + 1], "CVE-2024-0001,CVE-2024-0002")

    def test_no_cve_id_keeps_tags(self):
        cmd = self._cmd({"tags": "cve,exposure"})
        self.assertIn("-tags", cmd)
        self.assertNotIn("-id", cmd)


if __name__ == "__main__":
    unittest.main()
