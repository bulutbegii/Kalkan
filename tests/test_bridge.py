import unittest

from kalkan.knowledge import bridge
from kalkan.knowledge.vuln import CveRecord


class TestBridge(unittest.TestCase):
    def test_cwe_to_playbook_technique(self):
        links = bridge.resolve(cwe=["CWE-89"])
        self.assertTrue(links)
        top = links[0]
        self.assertEqual(top.technique, "T1190")
        self.assertTrue(top.has_playbook)
        self.assertEqual(top.framework, "attack")
        self.assertIn("cwe:CWE-89", top.source)

    def test_cwe_without_playbook_still_resolves(self):
        links = bridge.resolve(cwe=["CWE-269"])
        ids = [l.technique for l in links]
        self.assertIn("T1068", ids)
        t1068 = next(l for l in links if l.technique == "T1068")
        self.assertFalse(t1068.has_playbook)

    def test_keyword_fallback_when_no_cwe(self):
        links = bridge.resolve(cwe=[], description="Unauthenticated remote code execution in the API")
        self.assertTrue(any(l.technique == "T1190" for l in links))
        self.assertTrue(any(l.source == "keyword" for l in links))

    def test_cwe_preferred_over_keyword(self):
        links = bridge.resolve(cwe=["CWE-89"], description="privilege escalation")
        self.assertTrue(all(l.source.startswith("cwe:") or l.framework == "atlas" for l in links))

    def test_atlas_keyword_detection(self):
        links = bridge.resolve(cwe=["CWE-89"], description="allows prompt injection into the LLM")
        self.assertTrue(any(l.framework == "atlas" for l in links))

    def test_multi_candidate_memory_corruption(self):
        links = bridge.resolve(cwe=["CWE-787"])
        ids = {l.technique for l in links}
        self.assertTrue({"T1190", "T1203"} & ids)

    def test_cwe_476_does_not_crash(self):
        links = bridge.resolve(cwe=["CWE-476"])
        self.assertTrue(any(l.technique == "T1499" for l in links))

    def test_enrich_record(self):
        rec = CveRecord(
            id="CVE-2024-0001",
            description="SQL injection",
            cwe=("CWE-89",),
            base_score=9.8,
            severity="critical",
        )
        info = bridge.enrich(rec)
        self.assertIn("T1190", info["runnable"])
        self.assertEqual(info["top"]["technique"], "T1190")
        self.assertTrue(info["techniques"])

    def test_min_confidence_filter(self):
        high = bridge.resolve(cwe=["CWE-125"], min_confidence=0.9)
        self.assertEqual(high, [])


if __name__ == "__main__":
    unittest.main()
