"""MITRE ATLAS katalogu (AI/ML sistemlerine yonelik taktikler).

ATLAS verisi YAML olarak dagitiliyor; burada araclarla *test edilebilir*
cekirdek teknikler kuret edildi. Katalog bilincli olarak kucuk ve
durust: hangi teknik otomatik test edilebiliyor, hangisi manuel,
acikca yaziyor.

`capabilities` dolu ise llmprobe o yetenekleri calistirir. Bos ise
`manual=True` olur ve `test_approach` alani elle nasil test edilecegini
anlatir. Bu ayrim, "kapsandi" demek ile "gercekten test ediliyor"
demek arasindaki farki korur.
"""

from __future__ import annotations

from dataclasses import dataclass


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
