import unittest

from kalkan.adapters import load_default_registry
from kalkan.knowledge import mapping
from kalkan.models import Risk
from kalkan.orchestrator.planner import plan


class TestPlanner(unittest.TestCase):
    def setUp(self):
        self.registry = load_default_registry()

    def test_known_technique_produces_actions(self):
        p = plan("servis kesfi", "10.0.0.5", techniques=["T1046"], registry=self.registry)
        self.assertEqual(len(p.actions), 2)
        self.assertEqual(p.actions[0].tool, "nmap")
        self.assertTrue(all(a.technique == "T1046" for a in p.actions))

    def test_actions_sorted_by_risk(self):
        p = plan("ilk erisim", "10.0.0.5", techniques=["T1190"], registry=self.registry,
                 overrides={"module": "exploit/windows/smb/ms17_010_eternalblue"})
        risks = [int(a.risk) for a in p.actions]
        self.assertEqual(risks, sorted(risks))

    def test_msf_step_skipped_without_module(self):
        p = plan("ilk erisim", "10.0.0.5", techniques=["T1190"], registry=self.registry)
        tools = [a.tool for a in p.actions]
        self.assertNotIn("msf", tools)
        self.assertTrue(any("eksik: module" in n for n in p.notes))

    def test_msf_step_included_with_module(self):
        p = plan("ilk erisim", "10.0.0.5", techniques=["T1190"], registry=self.registry,
                 overrides={"module": "auxiliary/scanner/smb/smb_version"})
        self.assertIn("msf", [a.tool for a in p.actions])

    def test_unknown_technique_is_noted(self):
        p = plan("x", "10.0.0.5", techniques=["T9999"], registry=self.registry)
        self.assertEqual(p.actions, [])
        self.assertTrue(any("playbook yok" in n for n in p.notes))

    def test_risk_ceiling_filters(self):
        p = plan("ilk erisim", "10.0.0.5", techniques=["T1190"], registry=self.registry,
                 max_risk=Risk.ACTIVE,
                 overrides={"module": "auxiliary/scanner/smb/smb_version"})
        self.assertNotIn("msf", [a.tool for a in p.actions])

    def test_tactic_expansion(self):
        p = plan("kesif", "10.0.0.5", tactic="reconnaissance", registry=self.registry)
        self.assertGreater(len(p.actions), 0)

    def test_atlas_technique(self):
        p = plan("jailbreak testi", "http://localhost:11434", techniques=["AML.T0054"],
                 registry=self.registry)
        self.assertEqual(len(p.actions), 1)
        self.assertEqual(p.actions[0].capability, "llm_jailbreak_probe")

    def test_llmprobe_accepts_endpoint_and_model_overrides(self):
        p = plan(
            "jailbreak",
            "http://localhost:11434",
            techniques=["AML.T0054"],
            registry=self.registry,
            overrides={"endpoint": "http://127.0.0.1:11434", "model": "qwen3:4b"},
        )
        self.assertEqual(p.actions[0].args["model"], "qwen3:4b")
        self.assertEqual(p.actions[0].args["endpoint"], "http://127.0.0.1:11434")

    def test_deduplication(self):
        p = plan("kesif", "10.0.0.5", techniques=["T1595", "T1595.002"], registry=self.registry)
        keys = [a.key() for a in p.actions]
        self.assertEqual(len(keys), len(set(keys)))

    def test_every_playbook_step_has_known_tool(self):
        for playbook in mapping.all_playbooks():
            for step in playbook.steps:
                self.assertIn(step.tool, self.registry.names(), f"{playbook.technique}: {step.tool}")

    def test_every_playbook_capability_is_offered(self):
        for playbook in mapping.all_playbooks():
            for step in playbook.steps:
                adapter = self.registry.get(step.tool)
                self.assertTrue(
                    adapter.spec.supports(step.capability),
                    f"{playbook.technique}: {step.tool} '{step.capability}' yeteneğini sunmuyor",
                )


if __name__ == "__main__":
    unittest.main()
