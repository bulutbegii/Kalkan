"""Bilgi tabani yukleyicileri icin birim testler.

ATT&CK ve ATLAS STIX yukleyicileri sentetik bundle'lar ile test edilir;
ag erisimi gerektirmez. Gercek veriyi indirmek yerine kucuk ve
tekrarlanabilir senaryolar kullanilir.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from kalkan.knowledge.atlas import AtlasKnowledge
from kalkan.knowledge.attack import AttackKnowledge


def _bundle(objects: list[dict]) -> dict:
    return {"type": "bundle", "id": "bundle--00000000-0000-0000-0000-000000000000",
            "objects": objects}


ATTACK_PATTERN_PARENT = {
    "type": "attack-pattern",
    "id": "attack-pattern--11111111-1111-1111-1111-111111111111",
    "name": "Synthetic Prompt Injection",
    "description": "Sistem promptuna sahte talimat enjekte etme.",
    "external_references": [
        {"source_name": "mitre-atlas", "external_id": "AML.T9000",
         "url": "https://atlas.mitre.org/techniques/AML.T9000"}
    ],
    "kill_chain_phases": [
        {"kill_chain_name": "mitre-atlas", "phase_name": "execution"}
    ],
    "x_mitre_platforms": ["Enterprise"],
}

ATTACK_PATTERN_CHILD = {
    "type": "attack-pattern",
    "id": "attack-pattern--22222222-2222-2222-2222-222222222222",
    "name": "Synthetic Prompt Injection: Direct",
    "description": "Kullanici mesajina dogrudan sahte sistem talimati.",
    "external_references": [
        {"source_name": "mitre-atlas", "external_id": "AML.T9000.001",
         "url": "https://atlas.mitre.org/techniques/AML.T9000.001"}
    ],
    "kill_chain_phases": [
        {"kill_chain_name": "mitre-atlas", "phase_name": "execution"}
    ],
    "x_mitre_platforms": ["Enterprise"],
}

MITIGATION = {
    "type": "course-of-action",
    "id": "course-of-action--33333333-3333-3333-3333-333333333333",
    "name": "Prompt Injection Filtering",
    "description": "Girdi filtrelemesi ve talimat onceligi ayrimi.",
    "external_references": [
        {"source_name": "mitre-atlas", "external_id": "AML.M9000",
         "url": "https://atlas.mitre.org/mitigations/AML.M9000"}
    ],
}

CASE_STUDY = {
    "type": "campaign",
    "id": "campaign--44444444-4444-4444-4444-444444444444",
    "name": "Case Study: Demo Prompt Leak",
    "description": "Ornek olay calismasi.",
}

REL_SUBTECH = {
    "type": "relationship",
    "id": "relationship--55555555-5555-5555-5555-555555555555",
    "relationship_type": "subtechnique-of",
    "source_ref": ATTACK_PATTERN_CHILD["id"],
    "target_ref": ATTACK_PATTERN_PARENT["id"],
}

REL_MITIGATES = {
    "type": "relationship",
    "id": "relationship--66666666-6666-6666-6666-666666666666",
    "relationship_type": "mitigates",
    "source_ref": MITIGATION["id"],
    "target_ref": ATTACK_PATTERN_PARENT["id"],
}

REL_USES = {
    "type": "relationship",
    "id": "relationship--77777777-7777-7777-7777-777777777777",
    "relationship_type": "uses",
    "source_ref": CASE_STUDY["id"],
    "target_ref": ATTACK_PATTERN_PARENT["id"],
}


class TestAtlasKnowledge(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name)
        bundle = _bundle([
            ATTACK_PATTERN_PARENT, ATTACK_PATTERN_CHILD, MITIGATION,
            CASE_STUDY, REL_SUBTECH, REL_MITIGATES, REL_USES,
        ])
        (self.cache / "stix-atlas.json").write_text(
            json.dumps(bundle, ensure_ascii=False), encoding="utf-8"
        )
        self.knowledge = AtlasKnowledge(cache_dir=self.cache).load()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_available(self) -> None:
        self.assertTrue(self.knowledge.available)

    def test_technique_lookup(self) -> None:
        info = self.knowledge.technique("aml.t9000")
        self.assertIsNotNone(info)
        self.assertEqual(info["name"], "Synthetic Prompt Injection")
        self.assertEqual(info["tactics"], ["execution"])
        self.assertTrue(info["url"].endswith("AML.T9000"))

    def test_subtechnique_linked(self) -> None:
        parent = self.knowledge.technique("AML.T9000")
        self.assertIn("AML.T9000.001", parent.get("sub_techniques", []))
        child = self.knowledge.technique("AML.T9000.001")
        self.assertEqual(child["parent"], "AML.T9000")

    def test_search(self) -> None:
        hits = self.knowledge.search("prompt injection")
        names = [h["id"] for h in hits]
        self.assertIn("AML.T9000", names)
        self.assertIn("AML.T9000.001", names)

    def test_search_name_matches_first(self) -> None:
        hits = self.knowledge.search("prompt injection")
        self.assertEqual(hits[0]["id"], "AML.T9000")

    def test_by_tactic_and_tactics(self) -> None:
        execs = self.knowledge.by_tactic("execution")
        self.assertGreaterEqual(len(execs), 2)
        self.assertIn("execution", self.knowledge.tactics())

    def test_mitigations_for(self) -> None:
        mitig = self.knowledge.mitigations_for("AML.T9000")
        self.assertEqual(len(mitig), 1)
        self.assertEqual(mitig[0]["name"], "Prompt Injection Filtering")

    def test_cases_using(self) -> None:
        cases = self.knowledge.cases_using("AML.T9000")
        self.assertEqual(cases, ["Case Study: Demo Prompt Leak"])

    def test_statistics(self) -> None:
        stats = self.knowledge.statistics()
        self.assertEqual(stats["techniques"], 1)
        self.assertEqual(stats["sub_techniques"], 1)
        self.assertEqual(stats["case_studies"], 1)
        self.assertEqual(stats["mitigations"], 1)

    def test_len_counts_all_patterns(self) -> None:
        self.assertEqual(len(self.knowledge), 2)

    def test_missing_data_raises(self) -> None:
        missing_dir = self.cache / "missing"
        knowledge = AtlasKnowledge(cache_dir=missing_dir)
        with self.assertRaises(FileNotFoundError):
            knowledge.technique("AML.T9000")

    def test_in_seed_flag_matches_curated_table(self) -> None:
        self.assertFalse(self.knowledge.technique("AML.T9000")["in_seed"])


ATTACK_ENTERPRISE_PATTERN = {
    "type": "attack-pattern",
    "id": "attack-pattern--99999999-9999-9999-9999-999999999999",
    "name": "Synthetic Network Scan",
    "description": "Port ve servis taramasinin sentetik oyuncusu.",
    "external_references": [
        {"source_name": "mitre-attack", "external_id": "T9000",
         "url": "https://attack.mitre.org/techniques/T9000/"}
    ],
    "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}
    ],
    "x_mitre_platforms": ["Windows"],
    "x_mitre_detection": "Ag tarama impretlerlerine dikkat.",
}

ATTACK_OBJECT = {
    "type": "attack-pattern",
    "id": "attack-pattern--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "name": "Synthetic Network Share",
    "description": "Uzak paylasim mount fiilinin sentetik oyuncusu.",
    "external_references": [
        {"source_name": "mitre-attack", "external_id": "T9001",
         "url": "https://attack.mitre.org/techniques/T9001/"}
    ],
    "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}
    ],
    "x_mitre_platforms": ["Windows"],
    "x_mitre_detection": "",
}


class TestAttackKnowledge(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name)
        bundle = _bundle([ATTACK_ENTERPRISE_PATTERN, ATTACK_OBJECT])
        (self.cache / "enterprise-attack.json").write_text(
            json.dumps(bundle, ensure_ascii=False), encoding="utf-8"
        )
        self.knowledge = AttackKnowledge(
            domain="enterprise", cache_dir=self.cache
        ).load()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_technique_lookup(self) -> None:
        info = self.knowledge.technique("t9000")
        self.assertIsNotNone(info)
        self.assertEqual(info["name"], "Synthetic Network Scan")
        self.assertEqual(info["tactics"], ["discovery"])

    def test_search(self) -> None:
        hits = self.knowledge.search("scan")
        self.assertEqual(hits[0]["id"], "T9000")

    def test_by_tactic(self) -> None:
        self.assertEqual(len(self.knowledge.by_tactic("discovery")), 2)

    def test_tactics_listing(self) -> None:
        self.assertIn("discovery", self.knowledge.tactics())

    def test_no_cache_raises(self) -> None:
        knowledge = AttackKnowledge(domain="enterprise", cache_dir=self.cache / "away")
        with self.assertRaises(FileNotFoundError):
            knowledge.technique("T9000")


_GROUP = {
    "type": "intrusion-set", "id": "intrusion-set--b0b00000-0000-0000-0000-000000000001",
    "name": "Synthetic Bear", "aliases": ["Synthetic Bear", "SynthAPT"],
    "description": "Sentetik tehdit grubu.",
    "external_references": [{"source_name": "mitre-attack", "external_id": "G9000",
                             "url": "https://attack.mitre.org/groups/G9000"}],
}
_SOFTWARE = {
    "type": "malware", "id": "malware--50f70000-0000-0000-0000-000000000002",
    "name": "SynthRAT", "x_mitre_aliases": ["SynthRAT"],
    "description": "Sentetik zararli.", "x_mitre_platforms": ["Windows"],
    "external_references": [{"source_name": "mitre-attack", "external_id": "S9000",
                             "url": "https://attack.mitre.org/software/S9000"}],
}
_CAMPAIGN = {
    "type": "campaign", "id": "campaign--ca000000-0000-0000-0000-000000000003",
    "name": "Synthetic Op", "aliases": ["Synthetic Op"],
    "description": "Sentetik kampanya.",
    "first_seen": "2024-01-01T00:00:00Z", "last_seen": "2024-06-01T00:00:00Z",
    "external_references": [{"source_name": "mitre-attack", "external_id": "C9000",
                             "url": "https://attack.mitre.org/campaigns/C9000"}],
}
_DATA_SOURCE = {
    "type": "x-mitre-data-source", "id": "x-mitre-data-source--d5000000-0000-0000-0000-000000000004",
    "name": "Synthetic Logs", "x_mitre_platforms": ["Windows"],
    "description": "Sentetik veri kaynagi.",
    "external_references": [{"source_name": "mitre-attack", "external_id": "DS9000",
                             "url": "https://attack.mitre.org/datasources/DS9000"}],
}
_DATA_COMPONENT = {
    "type": "x-mitre-data-component", "id": "x-mitre-data-component--dc000000-0000-0000-0000-000000000005",
    "name": "Synthetic Log Creation",
    "x_mitre_data_source_ref": _DATA_SOURCE["id"],
}
_REL_GROUP_USES_TECH = {
    "type": "relationship", "id": "relationship--aa000000-0000-0000-0000-000000000006",
    "relationship_type": "uses", "source_ref": _GROUP["id"],
    "target_ref": ATTACK_ENTERPRISE_PATTERN["id"],
}
_REL_GROUP_USES_SW = {
    "type": "relationship", "id": "relationship--aa000000-0000-0000-0000-000000000007",
    "relationship_type": "uses", "source_ref": _GROUP["id"], "target_ref": _SOFTWARE["id"],
}
_REL_CAMP_ATTR = {
    "type": "relationship", "id": "relationship--aa000000-0000-0000-0000-000000000008",
    "relationship_type": "attributed-to", "source_ref": _CAMPAIGN["id"], "target_ref": _GROUP["id"],
}
_REL_CAMP_USES_TECH = {
    "type": "relationship", "id": "relationship--aa000000-0000-0000-0000-000000000009",
    "relationship_type": "uses", "source_ref": _CAMPAIGN["id"],
    "target_ref": ATTACK_ENTERPRISE_PATTERN["id"],
}
_REL_SW_USES_TECH = {
    "type": "relationship", "id": "relationship--aa000000-0000-0000-0000-00000000000a",
    "relationship_type": "uses", "source_ref": _SOFTWARE["id"],
    "target_ref": ATTACK_ENTERPRISE_PATTERN["id"],
}


class TestAttackFullDataset(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name)
        bundle = _bundle([
            ATTACK_ENTERPRISE_PATTERN, _GROUP, _SOFTWARE, _CAMPAIGN,
            _DATA_SOURCE, _DATA_COMPONENT, _REL_GROUP_USES_TECH, _REL_GROUP_USES_SW,
            _REL_CAMP_ATTR, _REL_CAMP_USES_TECH, _REL_SW_USES_TECH,
        ])
        (self.cache / "enterprise-attack.json").write_text(
            json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
        self.k = AttackKnowledge(domain="enterprise", cache_dir=self.cache).load()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_statistics_counts_all_kinds(self) -> None:
        st = self.k.statistics()
        self.assertEqual(st["groups"], 1)
        self.assertEqual(st["software"], 1)
        self.assertEqual(st["campaigns"], 1)
        self.assertEqual(st["data_sources"], 1)

    def test_group_links(self) -> None:
        g = self.k.group("G9000")
        self.assertIsNotNone(g)
        self.assertIn("T9000", g["techniques"])
        self.assertIn("S9000", g["software"])
        self.assertIn("SynthAPT", g["aliases"])

    def test_software_links(self) -> None:
        s = self.k.software("S9000")
        self.assertIn("G9000", s["groups"])
        self.assertIn("T9000", s["techniques"])

    def test_campaign_links(self) -> None:
        c = self.k.campaign("C9000")
        self.assertIn("G9000", c["groups"])
        self.assertIn("T9000", c["techniques"])

    def test_data_source_components(self) -> None:
        ds = self.k.data_source("DS9000")
        self.assertIn("Synthetic Log Creation", ds["components"])

    def test_lookup_routes_by_prefix(self) -> None:
        self.assertEqual(self.k.lookup("G9000")["kind"], "group")
        self.assertEqual(self.k.lookup("S9000")["kind"], "software")
        self.assertEqual(self.k.lookup("C9000")["kind"], "campaign")
        self.assertEqual(self.k.lookup("DS9000")["kind"], "data_source")
        self.assertEqual(self.k.lookup("T9000")["id"], "T9000")

    def test_search_all_name_first(self) -> None:
        hits = self.k.search_all("Synthetic Bear")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["id"], "G9000")


if __name__ == "__main__":
    unittest.main()
