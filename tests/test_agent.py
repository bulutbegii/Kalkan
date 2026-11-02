"""Otonom ajan dongusu testleri.

Ag/model gerektirmez: model yolu FakeRouter ile, arac calistirma dry-run ile
test edilir. Guvenlik degismezleri (yikici izin olmadan aday olmaz, kapsam/
politika kapilari) ve faz sirasi burada kilitlenir.
"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kalkan.adapters import load_default_registry
from kalkan.audit import AuditLog
from kalkan.models import ActionResult, Action, Risk
from kalkan.orchestrator.agent import AgentLoop, AgentState, build_catalog
from kalkan.orchestrator.router import Router
from kalkan.policy import Policy
from kalkan.scope import Scope, ScopeGuard


def guard(**overrides) -> ScopeGuard:
    base = dict(
        name="t", authorized_by="t", ticket="t",
        expires=datetime.now(timezone.utc) + timedelta(days=1),
        allow_cidrs=("10.0.0.0/24",), allow_domains=("example.com",),
        allow_ports=(), deny_cidrs=(), max_risk="destructive",
    )
    base.update(overrides)
    return ScopeGuard(Scope(**base))


class OfflineRouter(Router):
    """available()=False zorlar -> kural tabanli yola duser."""

    def available(self) -> bool:
        return False


class FakeRouter(Router):
    """Model yolunu agsiz test eder: verilen yetenekleri sirayla secer."""

    def __init__(self, picks):
        super().__init__(endpoint="http://127.0.0.1:1")
        self._picks = list(picks)
        self._i = 0

    def available(self) -> bool:
        return True

    def complete_json(self, system, user, schema, timeout=None):
        if self._i >= len(self._picks):
            return {"thought": "bitti", "capability": "", "done": True}
        cap = self._picks[self._i]
        self._i += 1
        return {"thought": f"sec {cap}", "capability": cap, "done": False}

    def summarize(self, prompt, timeout=None):
        return "MODEL ARA OZET"


class AgentTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = AuditLog(Path(self.tmp.name) / "audit.jsonl")
        self.registry = load_default_registry()
        self.events = []

    def tearDown(self):
        self.tmp.cleanup()

    def _loop(self, router, *, allow_destructive=False, max_steps=6, dry_run=True,
              summary_every=4):
        return AgentLoop(
            self.registry, guard(),
            Policy(allow_intrusive=True, allow_destructive=allow_destructive),
            self.audit, router,
            reporter=self.events.append, max_steps=max_steps, dry_run=dry_run,
            summary_every=summary_every,
        )


class TestCatalog(AgentTestBase):
    def test_risk_from_playbooks(self):
        cat = build_catalog(self.registry)
        self.assertIn("port_scan", cat)
        self.assertEqual(cat["passive_osint"].risk, Risk.PASSIVE)
        self.assertEqual(cat["port_scan"].risk, Risk.ACTIVE)
        self.assertEqual(cat["exploit_run"].risk, Risk.DESTRUCTIVE)
        self.assertEqual(cat["sqli_dump"].risk, Risk.DESTRUCTIVE)

    def test_tool_resolved_for_each_capability(self):
        cat = build_catalog(self.registry)
        names = self.registry.names()
        for cap in cat.values():
            self.assertIn(cap.tool, names)


class TestRuleLoop(AgentTestBase):
    def test_phase_order_and_autoapprove(self):
        loop = self._loop(OfflineRouter(), max_steps=4)
        state = loop.run("kesif", "example.com")
        self.assertEqual(state.steps, 4)
        acts = [e["action"] for e in self.events if e["kind"] == "act"]
        self.assertEqual(acts[0].capability, "passive_osint")
        self.assertTrue(all(r["result"].status == "dry-run"
                            for r in self.events if r["kind"] == "result"))
        caps = [a.capability for a in acts]
        self.assertEqual(len(caps), len(set(caps)))

    def test_done_event_when_exhausted(self):
        loop = self._loop(OfflineRouter(), max_steps=500)
        state = loop.run("kesif", "example.com")
        self.assertTrue(any(e["kind"] == "done" for e in self.events))
        self.assertLess(state.steps, 500)


class TestDecisionLog(AgentTestBase):
    _KEYS = {"step", "capability", "tool", "risk", "technique", "source",
             "thought", "status", "duration_s", "findings"}

    def test_decision_recorded_per_step(self):
        loop = self._loop(OfflineRouter(), max_steps=3)
        state = loop.run("kesif", "example.com")
        self.assertEqual(len(state.decisions), 3)
        for i, d in enumerate(state.decisions, 1):
            self.assertTrue(self._KEYS <= set(d))
            self.assertEqual(d["step"], i)
            self.assertEqual(d["source"], "rule")

    def test_decision_audit_events(self):
        loop = self._loop(OfflineRouter(), max_steps=2)
        loop.run("kesif", "example.com")
        ok, _ = self.audit.verify()
        self.assertTrue(ok)


class TestInterim(AgentTestBase):
    def test_interim_every_n_steps(self):
        loop = self._loop(OfflineRouter(), max_steps=4, summary_every=2)
        loop.run("kesif", "example.com")
        steps = [e["step"] for e in self.events if e["kind"] == "interim"]
        self.assertEqual(steps, [2, 4])

    def test_interim_text_mentions_next(self):
        loop = self._loop(OfflineRouter(), max_steps=2, summary_every=1)
        loop.run("kesif", "example.com")
        interim = [e for e in self.events if e["kind"] == "interim"]
        self.assertTrue(interim)
        self.assertIn("sırada", interim[0]["text"])


class TestSmartSummary(AgentTestBase):
    def test_model_interim_when_online(self):
        loop = self._loop(FakeRouter(["port_scan", "security_headers"]),
                          max_steps=2, summary_every=1)
        loop.run("kesif", "example.com")
        interim = [e for e in self.events if e["kind"] == "interim"]
        self.assertTrue(interim)
        self.assertEqual(interim[0]["source"], "model")
        self.assertEqual(interim[0]["text"], "MODEL ARA OZET")

    def test_deterministic_when_disabled(self):
        loop = AgentLoop(
            self.registry, guard(), Policy(allow_intrusive=True), self.audit,
            FakeRouter(["port_scan"]), reporter=self.events.append,
            max_steps=1, dry_run=True, summary_every=1, smart_summary=False,
        )
        loop.run("kesif", "example.com")
        interim = [e for e in self.events if e["kind"] == "interim"]
        self.assertEqual(interim[0]["source"], "kural")


class TestReportDecisionLog(unittest.TestCase):
    def test_decisions_section_in_md(self):
        from kalkan import report
        a = Action(tool="nmap", capability="port_scan", target="x",
                   risk=Risk.ACTIVE, technique="T1046")
        r = ActionResult(action=a, status="ok")
        decisions = [{"step": 1, "capability": "port_scan", "tool": "nmap",
                      "risk": "active", "technique": "T1046", "source": "llm",
                      "thought": "önce portları gör", "status": "ok",
                      "duration_s": 0.3, "findings": []}]
        md = report.render("x", "o", [a], [r], decisions=decisions)
        self.assertIn("## Ajan Karar Logu", md)
        self.assertIn("port_scan.nmap", md)
        self.assertIn("önce portları gör", md)
        self.assertIn("model", md)

    def test_pipe_in_thought_escaped(self):
        from kalkan import report
        a = Action(tool="nmap", capability="port_scan", target="x", risk=Risk.ACTIVE)
        decisions = [{"step": 1, "capability": "port_scan", "tool": "nmap",
                      "risk": "active", "technique": "", "source": "rule",
                      "thought": "a | b\nc", "status": "ok", "duration_s": 0.0,
                      "findings": []}]
        md = report.render("x", "o", [a], [], decisions=decisions)
        self.assertIn("a \\| b c", md)


class TestSafety(AgentTestBase):
    def test_destructive_excluded_without_flag(self):
        loop = self._loop(OfflineRouter(), allow_destructive=False)
        st = AgentState(objective="o", target="example.com")
        st.correlations = [{"cve": "CVE-2021-1", "score": 9.8, "kev": True,
                            "product": "x", "msf_module": "exploit/x"}]
        caps = {c.name for c in loop._candidates(st)}
        self.assertNotIn("exploit_run", caps)
        self.assertNotIn("sqli_dump", caps)
        self.assertIn("exploit_check", caps)

    def test_destructive_included_with_flag(self):
        loop = self._loop(OfflineRouter(), allow_destructive=True)
        st = AgentState(objective="o", target="example.com")
        st.correlations = [{"cve": "CVE-2021-1", "score": 9.8, "kev": True,
                            "product": "x", "msf_module": "exploit/x"}]
        caps = {c.name for c in loop._candidates(st)}
        self.assertIn("exploit_run", caps)

    def test_no_blind_exploit_without_correlation(self):
        loop = self._loop(OfflineRouter(), allow_destructive=True)
        st = AgentState(objective="o", target="example.com")
        caps = {c.name for c in loop._candidates(st)}
        self.assertNotIn("exploit_check", caps)
        self.assertNotIn("exploit_run", caps)
        self.assertNotIn("web_template", caps)


class TestExploitArgs(AgentTestBase):
    def test_msf_module_from_correlation(self):
        loop = self._loop(OfflineRouter())
        st = AgentState(objective="o", target="example.com")
        st.correlations = [{"cve": "CVE-1", "msf_module": "exploit/windows/smb/ms17_010"}]
        cap = loop.catalog["exploit_check"]
        args = loop._extra_args(st, cap)
        self.assertEqual(args.get("module"), "exploit/windows/smb/ms17_010")

    def test_cve_id_from_correlation_for_nuclei(self):
        loop = self._loop(OfflineRouter())
        st = AgentState(objective="o", target="example.com")
        st.correlations = [{"cve": "CVE-2021-23017"}, {"cve": "CVE-2022-1"}]
        cap = loop.catalog["web_template"]
        args = loop._extra_args(st, cap)
        self.assertIn("CVE-2021-23017", args.get("cve_id", ""))


class TestLlmPath(AgentTestBase):
    def test_model_choice_drives_loop(self):
        loop = self._loop(FakeRouter(["port_scan", "security_headers"]), max_steps=5)
        state = loop.run("kesif", "example.com")
        acts = [e["action"].capability for e in self.events if e["kind"] == "act"]
        self.assertEqual(acts[:2], ["port_scan", "security_headers"])
        self.assertTrue(any(e["kind"] == "done" for e in self.events))

    def test_invalid_model_choice_falls_back_to_rule(self):
        loop = self._loop(FakeRouter(["uydurma_yetenek"]), max_steps=1)
        state = loop.run("kesif", "example.com")
        self.assertEqual(state.steps, 1)
        acts = [e["action"].capability for e in self.events if e["kind"] == "act"]
        self.assertEqual(acts[0], "passive_osint")


if __name__ == "__main__":
    unittest.main()
