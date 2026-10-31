"""CVE -> ATT&CK/ATLAS teknik koprusu.

Neden var: canli CVE akisindan dusen bir kayit tek basina "ne yapmaliyim"
sorusunu cevaplamaz. Bu modul CVE'nin CWE'sinden (ve gerekirse aciklama
anahtar kelimelerinden) bir ATT&CK/ATLAS teknik kimligine koprU kurar;
boylece `mapping.get(tid)` ile dogrudan bir playbook'a baglanir.

Tasarim ilkeleri:
  * Durust guven (confidence): her eslesme 0.0-1.0 bir guven ve gerekce
    tasir. Zayif eslesmeyi guclu gibi gostermeyiz.
  * Playbook oncelikli: mumkun oldugunda playbook'u OLAN tekniklere
    koprU kurariz (T1190, T1203, T1059.007 ...). Boylece akistan dusen
    CVE aninda calistirilabilir bir plana donusebilir (Scope/Policy
    kapisi arkasinda).
  * Stdlib-only, veri statik. Ag gerekmez.

Kaynak esleme CWE -> CAPEC -> ATT&CK zincirinin pratik bir ozetidir;
otorite degil, operasyonel bir baslangic noktasidir.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import atlas, mapping

CWE_TO_ATTACK: dict[str, tuple[tuple[str, float, str], ...]] = {
    "CWE-89": (("T1190", 0.9, "SQL enjeksiyonu ile acik uygulama somurusu"),),
    "CWE-79": (("T1190", 0.7, "XSS; istemci tarafi ama acik uygulama yuzeyinden"),),
    "CWE-78": (("T1190", 0.9, "OS komut enjeksiyonu"),),
    "CWE-77": (("T1190", 0.85, "komut enjeksiyonu"),),
    "CWE-94": (("T1190", 0.9, "kod enjeksiyonu"),),
    "CWE-95": (("T1190", 0.85, "eval tarzi kod enjeksiyonu"),),
    "CWE-74": (("T1190", 0.8, "genel enjeksiyon"),),
    "CWE-434": (("T1190", 0.9, "sinirsiz dosya yukleme -> webshell"),),
    "CWE-22": (("T1190", 0.8, "dizin gezinme ile acik uygulama somurusu"),),
    "CWE-23": (("T1190", 0.8, "goreli yol gezinme"),),
    "CWE-98": (("T1190", 0.85, "PHP uzak/yerel dosya dahil etme"),),
    "CWE-611": (("T1190", 0.8, "XXE ile acik uygulama somurusu"),),
    "CWE-918": (("T1190", 0.8, "SSRF"),),
    "CWE-502": (("T1190", 0.85, "guvensiz deserializasyon"),),
    "CWE-917": (("T1190", 0.85, "ifade dili enjeksiyonu (SSTI)"),),
    "CWE-90": (("T1190", 0.8, "LDAP enjeksiyonu"),),
    "CWE-91": (("T1190", 0.75, "XML enjeksiyonu"),),
    "CWE-1336": (("T1190", 0.85, "sablon enjeksiyonu"),),
    "CWE-287": (("T1190", 0.6, "hatali kimlik dogrulama"), ("T1078", 0.5, "gecerli hesap kotuye kullanimi")),
    "CWE-306": (("T1190", 0.7, "kritik islevde kimlik dogrulama eksik"),),
    "CWE-862": (("T1190", 0.6, "yetkilendirme eksik"),),
    "CWE-863": (("T1190", 0.6, "hatali yetkilendirme"),),
    "CWE-269": (("T1068", 0.7, "hatali ayricalik yonetimi -> yerel privesc"),),
    "CWE-250": (("T1068", 0.6, "gereksiz yuksek ayricaliklarla calisma"),),
    "CWE-798": (("T1078", 0.7, "gomulu kimlik bilgisi -> gecerli hesap"),),
    "CWE-521": (("T1110", 0.5, "zayif parola gereksinimi -> brute force"),),
    "CWE-384": (("T1190", 0.6, "oturum sabitleme"),),
    "CWE-787": (("T1190", 0.6, "out-of-bounds write (servis)"), ("T1203", 0.6, "istemci yurutme")),
    "CWE-125": (("T1190", 0.5, "out-of-bounds read"), ("T1203", 0.5, "istemci yurutme")),
    "CWE-416": (("T1203", 0.6, "use-after-free"), ("T1190", 0.5, "servis somurusu")),
    "CWE-120": (("T1190", 0.6, "klasik tampon tasmasi"), ("T1203", 0.5, "istemci yurutme")),
    "CWE-119": (("T1190", 0.5, "bellek sinir hatasi"), ("T1203", 0.5, "istemci yurutme")),
    "CWE-190": (("T1190", 0.5, "tamsayi tasmasi -> bellek bozulmasi"),),
    "CWE-476": (("T1499", 0.5, "null pointer -> hizmet reddi"),),
    "CWE-200": (("T1592", 0.6, "hassas bilgi ifsasi -> hedef bilgisi toplama"),),
    "CWE-209": (("T1592", 0.5, "hata mesajiyla bilgi sizmasi"),),
    "CWE-538": (("T1083", 0.5, "dosya/dizin ifsasi"),),
    "CWE-400": (("T1499", 0.7, "kontrolsuz kaynak tuketimi -> DoS"),),
    "CWE-770": (("T1499", 0.6, "kaynak sinirlamasi yok -> DoS"),),
}

KEYWORD_TO_ATTACK: tuple[tuple[tuple[str, ...], str, float, str], ...] = (
    (("sql injection", "sqli"), "T1190", 0.8, "aciklamada SQL enjeksiyonu"),
    (("remote code execution", "rce", "arbitrary code"), "T1190", 0.85, "aciklamada uzaktan kod yurutme"),
    (("command injection",), "T1190", 0.8, "aciklamada komut enjeksiyonu"),
    (("deserialization",), "T1190", 0.8, "aciklamada deserializasyon"),
    (("path traversal", "directory traversal"), "T1190", 0.75, "aciklamada dizin gezinme"),
    (("server-side request forgery", "ssrf"), "T1190", 0.75, "aciklamada SSRF"),
    (("cross-site scripting", "xss"), "T1190", 0.6, "aciklamada XSS"),
    (("privilege escalation", "elevation of privilege"), "T1068", 0.7, "aciklamada ayricalik yukseltme"),
    (("authentication bypass", "auth bypass"), "T1190", 0.7, "aciklamada kimlik dogrulama atlatma"),
    (("denial of service", "dos ", "crash"), "T1499", 0.6, "aciklamada hizmet reddi"),
    (("buffer overflow", "out-of-bounds", "use-after-free"), "T1190", 0.6, "aciklamada bellek bozulmasi"),
)

ATLAS_KEYWORDS: tuple[tuple[tuple[str, ...], str, float, str], ...] = (
    (("prompt injection",), "AML.T0051", 0.7, "aciklamada prompt injection"),
    (("jailbreak", "guardrail bypass"), "AML.T0054", 0.6, "aciklamada jailbreak"),
    (("model", "llm", "machine learning", "tensorflow", "pytorch", "onnx"),
     "AML.T0040", 0.4, "ML bileseni; ML servisine erisim adayi"),
    (("training data", "data poisoning"), "AML.T0020", 0.5, "aciklamada egitim verisi"),
)


CVE_TO_MSF: dict[str, tuple[str, str]] = {
    "CVE-2017-0144": ("exploit/windows/smb/ms17_010_eternalblue", "EternalBlue (MS17-010)"),
    "CVE-2017-0143": ("exploit/windows/smb/ms17_010_eternalblue", "MS17-010 ailesi"),
    "CVE-2017-0145": ("exploit/windows/smb/ms17_010_eternalblue", "MS17-010 ailesi"),
    "CVE-2020-1472": ("auxiliary/admin/dcerpc/cve_2020_1472_zerologon", "ZeroLogon"),
    "CVE-2020-0796": ("exploit/windows/smb/cve_2020_0796_smbghost", "SMBGhost"),
    "CVE-2019-0708": ("exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "BlueKeep (RDP)"),
    "CVE-2021-44228": ("exploit/multi/http/log4shell_header_injection", "Log4Shell"),
    "CVE-2021-34527": ("exploit/windows/dcerpc/cve_2021_1675_printnightmare", "PrintNightmare"),
    "CVE-2021-1675": ("exploit/windows/dcerpc/cve_2021_1675_printnightmare", "PrintNightmare"),
    "CVE-2014-6271": ("exploit/multi/http/apache_mod_cgi_bash_env_exec", "Shellshock"),
    "CVE-2017-5638": ("exploit/multi/http/struts2_content_type_ognl", "Apache Struts2 OGNL"),
    "CVE-2018-7600": ("exploit/unix/webapp/drupal_drupalgeddon2", "Drupalgeddon2"),
    "CVE-2019-19781": ("exploit/linux/http/citrix_dir_traversal_rce", "Citrix ADC"),
    "CVE-2021-26855": ("exploit/windows/http/exchange_proxylogon_rce", "ProxyLogon"),
    "CVE-2021-34473": ("exploit/windows/http/exchange_proxyshell_rce", "ProxyShell"),
    "CVE-2022-1388": ("exploit/linux/http/f5_bigip_icontrol_rce", "F5 BIG-IP iControl"),
}

SQLI_CWES = frozenset({"CWE-89", "CWE-564", "CWE-943"})


def msf_module(cve_id: str) -> tuple[str, str] | None:
    """CVE icin kurasyonlu MSF modulu (yol, not) veya None."""
    return CVE_TO_MSF.get(str(cve_id).strip().upper())


def is_sqli(cwe: list[str] | tuple[str, ...] | None = None, description: str = "") -> bool:
    """CVE SQL enjeksiyonu sinifinda mi? (sqlmap adimi icin ipucu)."""
    for raw in cwe or ():
        if str(raw).strip().upper() in SQLI_CWES:
            return True
    text = (description or "").lower()
    return "sql injection" in text or "sqli" in text


@dataclass(frozen=True)
class TechniqueLink:
    """Bir CVE ile bir ATT&CK/ATLAS teknigi arasinda koprU."""

    technique: str
    framework: str
    confidence: float
    rationale: str
    source: str
    has_playbook: bool = False
    playbook_name: str = ""
    playbook_tactic: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "framework": self.framework,
            "confidence": round(self.confidence, 2),
            "rationale": self.rationale,
            "source": self.source,
            "has_playbook": self.has_playbook,
            "playbook": self.playbook_name,
            "tactic": self.playbook_tactic,
        }


def _decorate(tid: str, framework: str, confidence: float, rationale: str, source: str) -> TechniqueLink:
    """Teknige playbook var mi diye bakip linki zenginlestir."""
    pb = mapping.get(tid)
    if pb is not None:
        return TechniqueLink(
            technique=tid, framework=pb.framework, confidence=confidence,
            rationale=rationale, source=source, has_playbook=True,
            playbook_name=pb.name, playbook_tactic=pb.tactic,
        )
    return TechniqueLink(
        technique=tid, framework=framework, confidence=confidence,
        rationale=rationale, source=source, has_playbook=False,
    )


def resolve(
    cwe: list[str] | tuple[str, ...] | None = None,
    description: str = "",
    min_confidence: float = 0.0,
) -> list[TechniqueLink]:
    """CWE listesi ve/veya aciklamadan teknik koprUleri uret.

    Oncelik: once CWE eslesmeleri (en guvenilir), CWE hic eslesmezse
    aciklama anahtar kelimeleri (son care). ATLAS ipuclari her zaman
    aciklamadan taranir (dusuk guven, bilgilendirici).
    """
    links: dict[str, TechniqueLink] = {}

    def _add(link: TechniqueLink) -> None:
        existing = links.get(link.technique)
        if existing is None or link.confidence > existing.confidence:
            links[link.technique] = link

    cwe_hit = False
    for raw in cwe or ():
        key = str(raw).strip().upper()
        for tid, conf, why in CWE_TO_ATTACK.get(key, ()):  # type: ignore[misc]
            cwe_hit = True
            _add(_decorate(tid, "attack", conf, why, f"cwe:{key}"))

    text = (description or "").lower()
    if not cwe_hit and text:
        for needles, tid, conf, why in KEYWORD_TO_ATTACK:
            if any(n in text for n in needles):
                _add(_decorate(tid, "attack", conf, why, "keyword"))

    if text:
        for needles, tid, conf, why in ATLAS_KEYWORDS:
            if any(n in text for n in needles):
                _add(_decorate(tid, "atlas", conf, why, "keyword"))

    out = [l for l in links.values() if l.confidence >= min_confidence]
    out.sort(key=lambda l: (l.has_playbook, l.confidence), reverse=True)
    return out


def resolve_record(record: Any, min_confidence: float = 0.0) -> list[TechniqueLink]:
    """CveRecord (knowledge.vuln) icin koprU cozumle."""
    return resolve(
        cwe=getattr(record, "cwe", ()) or (),
        description=getattr(record, "description", "") or "",
        min_confidence=min_confidence,
    )


def enrich(record: Any, min_confidence: float = 0.0) -> dict[str, Any]:
    """Olay/akis icin kompakt koprU ozeti.

    Playbook'u olan teknikler ayri listelenir; planner bunlari dogrudan
    tuketebilir (`runnable`).
    """
    links = resolve_record(record, min_confidence=min_confidence)
    runnable = [l.technique for l in links if l.has_playbook]
    cwe = getattr(record, "cwe", ()) or ()
    desc = getattr(record, "description", "") or ""
    module = msf_module(getattr(record, "id", ""))
    return {
        "techniques": [l.to_dict() for l in links],
        "runnable": runnable,
        "top": links[0].to_dict() if links else None,
        "msf_module": module[0] if module else "",
        "msf_note": module[1] if module else "",
        "sqli": is_sqli(cwe, desc),
    }
