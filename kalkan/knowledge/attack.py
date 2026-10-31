"""MITRE ATT&CK bilgi tabani (STIX 2.1).

Yerel onbellek kullanir; ag yoksa da calisir. `kalkan knowledge fetch`
ile enterprise-attack.json indirilir (~40 MB).
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

DEFAULT_CACHE = Path.home() / ".kalkan" / "attack"


class AttackKnowledge:
    def __init__(self, domain: str = "enterprise", cache_dir: str | Path | None = None):
        if domain not in DEFAULT_URLS:
            raise ValueError(f"bilinmeyen domain: {domain}")
        self.domain = domain
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE
        self._index: dict[str, dict[str, Any]] = {}
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
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
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
                "url": self._external_url(obj),
            }
        self._loaded = True
        return self

    @staticmethod
    def _external_id(obj: dict[str, Any]) -> str:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
                return ref.get("external_id", "")
        return ""

    @staticmethod
    def _external_url(obj: dict[str, Any]) -> str:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
                return ref.get("url", "")
        return ""

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
        q = query.lower()
        hits = [
            info
            for info in self._index.values()
            if q in info["name"].lower() or q in info["description"].lower()
        ]
        return hits[:limit]

    def by_tactic(self, tactic: str, limit: int = 100) -> list[dict[str, Any]]:
        self.load()
        t = tactic.strip().lower()
        return [i for i in self._index.values() if t in i["tactics"]][:limit]

    def tactics(self) -> list[str]:
        self.load()
        found = {t for info in self._index.values() for t in info["tactics"] if t}
        return sorted(found)

    def __len__(self) -> int:
        self.load()
        return len(self._index)
