"""MITRE ATLAS katalogu (AI/ML sistemlerine yonelik taktikler).

Burada araclarla *test edilebilir* cekirdek teknikler kuret edildi. Katalog bilincli olarak kucuk ve durust: hangi teknik
otomatik test edilebiliyor, hangisi manuel, acikca yaziyor.

Tam katalog (butun taktik/teknik/mitigation/case study) resmi STIX
dagitimindan `AtlasKnowledge` ile beslenir:
  kalkan knowledge fetch --domain atlas
  kalkan knowledge search --domain atlas -q "prompt injection"

`capabilities` dolu ise llmprobe o yetenekleri calistirir. Bos ise
`manual=True` olur ve `test_approach` alani elle nasil test edilecegini
anlatir. Bu ayrim, "kapsandi" demek ile "gercekten test ediliyor"
demek arasindaki farki korur.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AtlasTechnique:
    id: str
    name: str
    tactic: str
    summary: str
    capabilities: tuple[str, ...] = ()
    manual: bool = False
    test_approach: str = ""


ATLAS: dict[str, AtlasTechnique] = {
    "AML.T0040": AtlasTechnique(
        id="AML.T0040",
        name="ML Model Inference API Access",
        tactic="discovery",
        summary="Model cikarim uc noktasina yetkisiz/oturumsuz erisim denemesi.",
        capabilities=("llm_api_access_probe",),
        test_approach="Uc noktaya kimlik dogrulama olmadan istek at; 401/403 yerine 200 donuyorsa bulgu.",
    ),
    "AML.T0051": AtlasTechnique(
        id="AML.T0051",
        name="LLM Prompt Injection",
        tactic="execution",
        summary="Modelin baglamina sahte sistem talimati veya gizli komut enjekte etme.",
        capabilities=("llm_injection_probe", "llm_rag_injection"),
        test_approach="Belge/log/HTML icine gomulu talimatlarla ajanin davranisi degisiyor mu olc.",
    ),
    "AML.T0051.000": AtlasTechnique(
        id="AML.T0051.000",
        name="LLM Prompt Injection: Direct",
        tactic="execution",
        summary="Kullanicinin kendi mesajina sistem talimati taklidi eklemesi.",
        capabilities=("llm_injection_probe",),
        test_approach="Kullanici mesajinda '[SYSTEM]' taklidi ve talimatla reddetme orani olculur.",
    ),
    "AML.T0051.001": AtlasTechnique(
        id="AML.T0051.001",
        name="LLM Prompt Injection: Indirect",
        tactic="execution",
        summary="Getirilen belge, web sayfasi veya arac ciktisina gomulu talimat (RAG zehirlenmesi).",
        capabilities=("llm_rag_injection",),
        test_approach="Belge icine benzersiz isaret gom; yanitta isaret gorunuyorsa enjeksiyon uygulandi.",
    ),
    "AML.T0054": AtlasTechnique(
        id="AML.T0054",
        name="LLM Jailbreak",
        tactic="defense-evasion",
        summary="Guvenlik politikasini rol yapma/ceviri/cok adim teknikleriyle asma.",
        capabilities=("llm_jailbreak_probe",),
        test_approach="Reddetme oranini olc; reddetme olmadan zararsiz bir isaretci (canary) uretiliyorsa kirilgan.",
    ),
    "AML.T0050": AtlasTechnique(
        id="AML.T0050",
        name="Command and Scripting Interpreter",
        tactic="execution",
        summary="Ajanin arac/shell cagrisi uzerinden komut calistirmaya ikna edilmesi.",
        capabilities=("llm_agent_hijack",),
        test_approach="Ajanin arac cagrilarini allowlist ile sinirla; enjeksiyonla yeni arac cagrisi uretilebiliyor mu bak.",
    ),
    "AML.T0024": AtlasTechnique(
        id="AML.T0024",
        name="Exfiltration via ML Inference API",
        tactic="exfiltration",
        summary="Cikarim API'si uzerinden egitim verisi, baglam veya sistem bilgisi sizdirma.",
        capabilities=("llm_model_extraction", "llm_exfil_probe"),
        test_approach="Baglama canary ve sahte sirlar koy; yanitta gorunuyorsa sizinti var.",
    ),
    "AML.T0029": AtlasTechnique(
        id="AML.T0029",
        name="Denial of ML Service",
        tactic="impact",
        summary="Asiri uzun veya cok sayida istekle cikarim hizmetini tuketme.",
        capabilities=("llm_dos_probe",),
        test_approach="Uzun/oteklemeli isteklerde gecikme ve hata oranini olc; esik asilirsa kaynak tuketimi riski.",
    ),
    "AML.T0057": AtlasTechnique(
        id="AML.T0057",
        name="LLM Data Leakage",
        tactic="exfiltration",
        summary="Sistem promptu, anahtar veya baglamdaki hassas verinin disari sizmasi.",
        capabilities=("llm_leak_probe", "llm_exfil_probe"),
        test_approach="Sistem promptuna canary yerlestir; yanitta gorunuyorsa sizinti var.",
    ),
    "AML.T0010": AtlasTechnique(
        id="AML.T0010",
        name="ML Supply Chain Compromise",
        tactic="initial-access",
        summary="Model agirligi, kutuphane veya egitim verisi tedarik zincirinin bozulmasi.",
        manual=True,
        test_approach="Model hash'ini ve bagimliliklari dogrula (safetensors + imza + SBOM).",
    ),
    "AML.T0020": AtlasTechnique(
        id="AML.T0020",
        name="Poison Training Data",
        tactic="impact",
        summary="Egitim/ince ayar verisine arka kapi yerlestirme.",
        manual=True,
        test_approach="Tetikleyici tabanli davranis testi; veri kaynagi koken takibi.",
    ),
    "AML.T0043": AtlasTechnique(
        id="AML.T0043",
        name="Craft Adversarial Data",
        tactic="defense-evasion",
        summary="Modeli yaniltmak icin ozel hazirlanmis girdi uretme.",
        manual=True,
        test_approach="Girdi perturbasyonu ile siniflandirma kararliligi olc.",
    ),
}


def get(tid: str) -> AtlasTechnique | None:
    return ATLAS.get(tid.strip().upper())


def by_tactic(tactic: str) -> list[AtlasTechnique]:
    t = tactic.strip().lower()
    return [v for v in ATLAS.values() if v.tactic == t]


def automated() -> list[AtlasTechnique]:
    return [v for v in ATLAS.values() if v.capabilities]


def manual() -> list[AtlasTechnique]:
    return [v for v in ATLAS.values() if v.manual]


def tactics() -> list[str]:
    return sorted({v.tactic for v in ATLAS.values()})


def capabilities() -> list[str]:
    found: set[str] = set()
    for technique in ATLAS.values():
        found.update(technique.capabilities)
    return sorted(found)



STIX_URL = (
    "https://github.com/mitre-atlas/atlas-data/releases/"
    "latest/download/stix-atlas.json"
)
DEFAULT_STIX_CACHE = Path.home() / ".kalkan" / "atlas"


class AtlasKnowledge:
    """resmi ATLAS STIX dagitimini indirir ve tam katalogu sunar.

    Kuretlenmis `ATLAS` sozlugu (ustte) *test edilebilir cekirdek*
    olarak kalir; bu sinif onun icinde olmayan butun teknikleri,
    mitigation'lari ve case study'leri de listeler.
    """

    def __init__(self, cache_dir: str | Path | None = None):
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_STIX_CACHE
        self._objects: dict[str, dict[str, Any]] = {}
        self._index: dict[str, dict[str, Any]] = {}
        self._stix_to_tid: dict[str, str] = {}
        self._mitigations: dict[str, dict[str, Any]] = {}
        self._cases: list[dict[str, Any]] = []
        self._loaded = False

    @property
    def cache_path(self) -> Path:
        return self.cache_dir / "stix-atlas.json"

    @property
    def available(self) -> bool:
        return self.cache_path.exists()

    def fetch(self, force: bool = False, timeout: int = 180) -> Path:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if self.cache_path.exists() and not force:
            return self.cache_path
        req = urllib.request.Request(STIX_URL, headers={"User-Agent": "kalkan/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        self.cache_path.write_bytes(data)
        self._loaded = False
        return self.cache_path

    def load(self) -> "AtlasKnowledge":
        if self._loaded:
            return self
        if not self.cache_path.exists():
            raise FileNotFoundError(
                f"ATLAS verisi yok: {self.cache_path}\n"
                "  önce: kalkan knowledge fetch --domain atlas"
            )
        bundle = json.loads(self.cache_path.read_text(encoding="utf-8"))
        for obj in bundle.get("objects", []):
            stix_id = obj.get("id", "")
            if stix_id:
                self._objects[stix_id] = obj
            kind = obj.get("type")

            if kind == "attack-pattern":
                ext_id, url = self._external_ref(obj)
                if not ext_id:
                    continue
                info: dict[str, Any] = {
                    "id": ext_id,
                    "stix_id": stix_id,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description") or "").strip(),
                    "tactics": [
                        phase.get("phase_name", "")
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name", "") == "mitre-atlas"
                    ],
                    "platforms": obj.get("x_mitre_platforms", []),
                    "url": url,
                    "mitigations": [],
                    "cases": [],
                    "in_seed": ext_id in ATLAS,
                }
                self._index[ext_id] = info
                self._stix_to_tid[stix_id] = ext_id

            elif kind == "course-of-action":
                m_ext, m_url = self._external_ref(obj)
                self._mitigations[stix_id] = {
                    "id": m_ext or stix_id,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description") or "").strip(),
                    "url": m_url,
                }

            elif kind == "campaign":
                self._cases.append({
                    "stix_id": stix_id,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description") or "").strip(),
                })

        for obj in bundle.get("objects", []):
            if obj.get("type") != "relationship":
                continue
            rel = obj.get("relationship_type", "")
            source = obj.get("source_ref", "")
            target = obj.get("target_ref", "")
            if rel == "subtechnique-of" and target in self._stix_to_tid:
                child = self._stix_to_tid.get(source, "")
                parent = self._stix_to_tid.get(target, "")
                if parent in self._index:
                    self._index[parent].setdefault("sub_techniques", []).append(child)
                if child in self._index:
                    self._index[child]["parent"] = parent
            elif rel == "uses" and target in self._stix_to_tid:
                tid = self._stix_to_tid[target]
                case_name = self._object_name(source)
                if tid in self._index and case_name:
                    self._index[tid]["cases"].append({"name": case_name})
            elif rel == "mitigates" and target in self._stix_to_tid:
                tid = self._stix_to_tid[target]
                mitigation = self._mitigations.get(source)
                if tid in self._index and mitigation:
                    self._index[tid]["mitigations"].append({
                        "id": mitigation["id"],
                        "name": mitigation["name"],
                        "url": mitigation["url"],
                    })

        for info in self._index.values():
            info["cases"] = sorted({c["name"] for c in info["cases"]})
            info["mitigations"].sort(key=lambda m: m["name"])
        self._loaded = True
        return self

    @staticmethod
    def _external_ref(obj: dict[str, Any]) -> tuple[str, str]:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-atlas":
                return ref.get("external_id", ""), ref.get("url", "")
        return "", ""

    def _object_name(self, stix_id: str) -> str:
        obj = self._objects.get(stix_id, {})
        name = obj.get("name", "")
        kind = obj.get("type", "campaign")
        if kind != "campaign" and name:
            return f"{name} ({kind})"
        return name

    def technique(self, tid: str) -> dict[str, Any] | None:
        self.load()
        return self._index.get(tid.strip().upper())

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
            elif tokens and phrase in (info["description"] or "").lower():
                phrase_hits.append(info)
            elif tokens and all(t in f"{info['name']} {info['description'] or ''}".lower()
                                for t in tokens):
                token_hits.append(info)
        return (name_hits + phrase_hits + token_hits)[:limit]

    def by_tactic(self, tactic: str, limit: int = 100) -> list[dict[str, Any]]:
        self.load()
        t = tactic.strip().lower()
        return [i for i in self._index.values() if t in i["tactics"]][:limit]

    def tactics(self) -> list[str]:
        self.load()
        found = {t for info in self._index.values() for t in info["tactics"] if t}
        return sorted(found)

    def mitigations_for(self, tid: str) -> list[dict[str, Any]]:
        info = self.technique(tid)
        return info["mitigations"] if info else []

    def cases_using(self, tid: str) -> list[str]:
        info = self.technique(tid)
        return list(info["cases"]) if info else []

    def statistics(self) -> dict[str, int]:
        self.load()
        full = sum(1 for i in self._index.values() if i["id"].count(".") == 1)
        sub = sum(1 for i in self._index.values() if i["id"].count(".") == 2)
        return {
            "tactics": len(self.tactics()),
            "techniques": full,
            "sub_techniques": sub,
            "mitigations": len(self._mitigations),
            "case_studies": len(self._cases),
        }

    def __len__(self) -> int:
        self.load()
        return len(self._index)
