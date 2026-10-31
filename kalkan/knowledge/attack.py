"""MITRE ATT&CK bilgi tabani (STIX 2.1) - TAM icerik.

Yerel onbellek kullanir; ag yoksa da calisir. `kalkan knowledge fetch`
ile enterprise-attack.json indirilir (~55 MB). mobile/ics ayrica indirilir.

Her teknik icin TAM icerik yuklenir:
  - aciklama (neyin nasil yapildigi), tespit (detection)
  - platformlar, veri kaynaklari, gerekli izinler, asilan savunmalar
  - alt-teknikler / ust teknik bagi
  - mitigasyonlar (course-of-action)
  - prosedur ornekleri (hangi grup/yazilim bu teknigi nasil kullanmis)
Ayrica taktikler (x-mitre-tactic) aciklamalariyla yuklenir.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
DEFAULT_URLS = {
    "enterprise": f"{BASE}/enterprise-attack/enterprise-attack.json",
    "mobile": f"{BASE}/mobile-attack/mobile-attack.json",
    "ics": f"{BASE}/ics-attack/ics-attack.json",
}

_ATTACK_SOURCES = ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
DEFAULT_CACHE = Path.home() / ".kalkan" / "attack"


class AttackKnowledge:
    def __init__(self, domain: str = "enterprise", cache_dir: str | Path | None = None):
        if domain not in DEFAULT_URLS:
            raise ValueError(f"bilinmeyen domain: {domain}")
        self.domain = domain
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE
        self._index: dict[str, dict[str, Any]] = {}
        self._objects: dict[str, dict[str, Any]] = {}
        self._stix_to_tid: dict[str, str] = {}
        self._mitigations: dict[str, dict[str, Any]] = {}
        self._tactics: dict[str, dict[str, Any]] = {}
        self._loaded = False

    @property
    def cache_path(self) -> Path:
        return self.cache_dir / f"{self.domain}-attack.json"

    @property
    def available(self) -> bool:
        return self.cache_path.exists()

    def fetch(self, force: bool = False, timeout: int = 180) -> Path:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if self.cache_path.exists() and not force:
            return self.cache_path
        url = DEFAULT_URLS[self.domain]
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
        self.cache_path.write_bytes(data)
        self._loaded = False
        return self.cache_path

    def load(self) -> "AttackKnowledge":
        if self._loaded:
            return self
        if not self.cache_path.exists():
            raise FileNotFoundError(
                f"ATT&CK verisi yok: {self.cache_path}\n"
                "  önce: kalkan knowledge fetch"
            )
        bundle = json.loads(self.cache_path.read_text(encoding="utf-8"))
        objects = bundle.get("objects", [])

        for obj in objects:
            sid = obj.get("id", "")
            if sid:
                self._objects[sid] = obj

        for obj in objects:
            kind = obj.get("type")
            if kind == "attack-pattern":
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue
                tid = self._external_id(obj)
                if not tid:
                    continue
                self._index[tid] = {
                    "id": tid,
                    "stix_id": obj.get("id", ""),
                    "name": obj.get("name", ""),
                    "description": (obj.get("description") or "").strip(),
                    "tactics": [
                        phase.get("phase_name", "")
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name", "").endswith("attack")
                    ],
                    "platforms": obj.get("x_mitre_platforms", []),
                    "detection": (obj.get("x_mitre_detection") or "").strip(),
                    "data_sources": obj.get("x_mitre_data_sources", []),
                    "permissions": obj.get("x_mitre_permissions_required", []),
                    "defenses_bypassed": obj.get("x_mitre_defense_bypassed", []),
                    "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                    "parent": tid.split(".")[0] if "." in tid else "",
                    "sub_techniques": [],
                    "mitigations": [],
                    "procedures": [],
                    "url": self._external_url(obj),
                }
                self._stix_to_tid[obj.get("id", "")] = tid

            elif kind == "course-of-action":
                m_ext, m_url = self._external_ref(obj)
                self._mitigations[obj.get("id", "")] = {
                    "id": m_ext or obj.get("id", ""),
                    "name": obj.get("name", ""),
                    "description": (obj.get("description") or "").strip(),
                    "url": m_url,
                }

            elif kind == "x-mitre-tactic":
                shortname = obj.get("x_mitre_shortname", "")
                if shortname:
                    self._tactics[shortname] = {
                        "shortname": shortname,
                        "name": obj.get("name", ""),
                        "description": (obj.get("description") or "").strip(),
                        "url": self._external_url(obj),
                    }

        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            rel = obj.get("relationship_type", "")
            source = obj.get("source_ref", "")
            target = obj.get("target_ref", "")
            if rel == "mitigates" and target in self._stix_to_tid:
                tid = self._stix_to_tid[target]
                mit = self._mitigations.get(source)
                if mit:
                    self._index[tid]["mitigations"].append({
                        "id": mit["id"], "name": mit["name"],
                        "description": mit["description"], "url": mit["url"],
                    })
            elif rel == "subtechnique-of" and target in self._stix_to_tid:
                child = self._stix_to_tid.get(source, "")
                parent = self._stix_to_tid.get(target, "")
                if parent in self._index and child:
                    self._index[parent]["sub_techniques"].append(child)
                if child in self._index and parent:
                    self._index[child]["parent"] = parent
            elif rel == "uses" and target in self._stix_to_tid:
                tid = self._stix_to_tid[target]
                src = self._objects.get(source, {})
                if src.get("type") in ("intrusion-set", "malware", "tool", "campaign"):
                    self._index[tid]["procedures"].append({
                        "source": src.get("name", ""),
                        "type": src.get("type", ""),
                        "description": (obj.get("description") or "").strip(),
                    })

        for info in self._index.values():
            info["mitigations"].sort(key=lambda m: m["name"])
            info["sub_techniques"].sort()
            info["procedures"].sort(key=lambda p: p["source"])
        self._loaded = True
        return self

    @staticmethod
    def _external_id(obj: dict[str, Any]) -> str:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in _ATTACK_SOURCES:
                return ref.get("external_id", "")
        return ""

    @staticmethod
    def _external_url(obj: dict[str, Any]) -> str:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in _ATTACK_SOURCES:
                return ref.get("url", "")
        return ""

    @classmethod
    def _external_ref(cls, obj: dict[str, Any]) -> tuple[str, str]:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in _ATTACK_SOURCES:
                return ref.get("external_id", ""), ref.get("url", "")
        return "", ""

    def technique(self, tid: str) -> dict[str, Any] | None:
        self.load()
        key = tid.strip().upper()
        if key in self._index:
            return self._index[key]
        for existing, info in self._index.items():
            if existing.startswith(key + "."):
                return info
        return None

    def search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        self.load()
        tokens = query.lower().split()
        phrase = " ".join(tokens)
        name_hits: list[dict[str, Any]] = []
        phrase_hits: list[dict[str, Any]] = []
        token_hits: list[dict[str, Any]] = []
        for info in self._index.values():
            if tokens and all(t in info["name"].lower() for t in tokens):
                name_hits.append(info)
            elif tokens and phrase in info["description"].lower():
                phrase_hits.append(info)
            elif tokens and all(t in f"{info['name']} {info['description']}".lower()
                                for t in tokens):
                token_hits.append(info)
        return (name_hits + phrase_hits + token_hits)[:limit]

    def by_tactic(self, tactic: str, limit: int = 500) -> list[dict[str, Any]]:
        self.load()
        t = tactic.strip().lower()
        return [i for i in self._index.values() if t in i["tactics"]][:limit]

    def tactics(self) -> list[str]:
        self.load()
        found = {t for info in self._index.values() for t in info["tactics"] if t}
        return sorted(found)

    def tactic_list(self) -> list[dict[str, Any]]:
        """Taktikleri (ad + aciklama) matris sirasiyla dondurur."""
        self.load()
        return [self._tactics[k] for k in sorted(self._tactics)]

    def mitigations_for(self, tid: str) -> list[dict[str, Any]]:
        info = self.technique(tid)
        return info["mitigations"] if info else []

    def procedures_for(self, tid: str) -> list[dict[str, Any]]:
        info = self.technique(tid)
        return info["procedures"] if info else []

    def statistics(self) -> dict[str, int]:
        self.load()
        full = sum(1 for i in self._index.values() if not i["is_subtechnique"])
        sub = sum(1 for i in self._index.values() if i["is_subtechnique"])
        procs = sum(len(i["procedures"]) for i in self._index.values())
        return {
            "tactics": len(self._tactics) or len(self.tactics()),
            "techniques": full,
            "sub_techniques": sub,
            "mitigations": len(self._mitigations),
            "procedures": procs,
        }

    def all(self) -> list[dict[str, Any]]:
        self.load()
        return list(self._index.values())

    def __len__(self) -> int:
        self.load()
        return len(self._index)
