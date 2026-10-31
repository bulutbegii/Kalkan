"""Tespit kurallari (Sigma uyumlu kayitlar).

Neden burada: bir playbook "hedefe ne yapacagini" anlatir; kural ise
"bunu loglarda nasil yakalarsin" sorusunu cevaplar. Ikisi ayni teknik
kimligiyle baglanir, boylece saldiri simulasyonu ile tespit ayni
tablodan okunur.

Kurallar Sigma'ya *benzer* ama bilincli olarak sade tutuldu: her kural
tek bir `selection` blogu ve tek bir `condition` icerir. Amac Sigma
motoru yazmak degil, savunma tarafina tasinabilir bir baslangic
noktasi vermek. `to_sigma()` cikti gercek Sigma araclarinda
(sigmac/pySigma) kullanilabilecek sekilde uretilir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LEVELS = ("informational", "low", "medium", "high", "critical")
LEVEL_ORDER = {name: index for index, name in enumerate(LEVELS)}


@dataclass(frozen=True)
class DetectionRule:
    id: str
    title: str
    level: str
    technique: str
    logsource: dict[str, str]
    description: str
    detection: dict[str, Any]
    condition: str = "selection"
    falsepositives: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @property
    def framework(self) -> str:
        return "atlas" if self.technique.upper().startswith("AML.") else "attack"

    @property
    def severity(self) -> int:
        return LEVEL_ORDER.get(self.level.lower(), 0)

    def to_sigma(self) -> dict[str, Any]:
        sigma: dict[str, Any] = {
            "title": self.title,
            "id": self.id,
            "status": "experimental",
            "description": self.description,
            "references": list(self.references),
            "author": "Kalkan",
            "date": "2026/10/31",
            "tags": list(self.tags) or [f"attack.{self.technique.lower()}"],
            "logsource": dict(self.logsource),
            "detection": {**self.detection, "condition": self.condition},
            "falsepositives": list(self.falsepositives) or ["Bilinmiyor"],
            "level": self.level,
        }
        return sigma

    def to_yaml(self) -> str:
        return _yaml(self.to_sigma())

    def matches(self, technique: str | None = None, logsource: str | None = None, level: str | None = None) -> bool:
        if technique and not self.technique.upper().startswith(technique.strip().upper()):
            return False
        if logsource:
            values = {str(v).lower() for v in self.logsource.values()}
            if logsource.strip().lower() not in values:
                return False
        if level and self.severity < LEVEL_ORDER.get(level.strip().lower(), 0):
            return False
        return True


def _r(
    rid: str,
    title: str,
    level: str,
    technique: str,
    logsource: dict[str, str],
    description: str,
    detection: dict[str, Any],
    condition: str = "selection",
    falsepositives: tuple[str, ...] = (),
    references: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
) -> DetectionRule:
    return DetectionRule(
        id=rid,
        title=title,
        level=level,
        technique=technique,
        logsource=logsource,
        description=description,
        detection=detection,
        condition=condition,
        falsepositives=falsepositives,
        references=references,
        tags=tags,
    )


_WEB = {"category": "webserver"}
_NET = {"category": "network"}
_LLM = {"category": "application", "product": "llm-gateway"}

_RULES: tuple[DetectionRule, ...] = (
    _r(
        "kalkan-recon-001",
        "Sirali Port Taramasi (SYN)",
        "medium",
        "T1046",
        _NET,
        "Tek kaynaktan cok sayida farkli porta kisa surede SYN denemesi.",
        {"selection": {"dst_port|count": {"gte": 100}, "initiated": True}},
        falsepositives=("Mesru zafiyet tarayicisi", "Yuk dengeleyici saglik kontrolu"),
        references=("https://attack.mitre.org/techniques/T1046/",),
        tags=("attack.discovery", "attack.t1046"),
    ),
    _r(
        "kalkan-recon-002",
        "Dizin/Dosya Kaba Kuvvet (404 Patlamasi)",
        "medium",
        "T1595.003",
        _WEB,
        "Ayni istemciden cok sayida 404 yaniti; gizli yol arayisi.",
        {
            "selection": {
                "cs-method": "GET",
                "sc-status": 404,
                "cs-uri-stem|contains": ("/admin", "/backup", "/.git", "/config", "/.env", "/wp-"),
            }
        },
        falsepositives=("Eski yer imleri", "Bozuk baglantilar"),
        references=("https://attack.mitre.org/techniques/T1595/003/",),
        tags=("attack.reconnaissance", "attack.t1595.003"),
    ),
    _r(
        "kalkan-recon-003",
        "Zafiyet Tarayici User-Agent",
        "low",
        "T1595.002",
        _WEB,
        "Bilinen tarayici imzalari (nuclei, nikto, sqlmap, ffuf) ile gelen istekler.",
        {"selection": {"cs-user-agent|contains": ("nuclei", "nikto", "sqlmap", "ffuf", "nmap", "masscan")}},
        falsepositives=("Ic zafiyet yonetimi taramasi",),
        references=("https://attack.mitre.org/techniques/T1595/002/",),
        tags=("attack.reconnaissance", "attack.t1595.002"),
    ),
    _r(
        "kalkan-recon-004",
        "Internet Tarayici Altyapisi Sorgusu",
        "informational",
        "T1596",
        {"category": "network", "product": "proxy"},
        "Shodan/Censys gibi tarama servislerinin bot IP'lerinden gelen erisimler.",
        {"selection": {"src_ip|contains": ("shodan", "censys", "binaryedge", "zoomeye")}},
        falsepositives=("Guvenlik arastirmasi", "Marka izleme"),
        references=("https://attack.mitre.org/techniques/T1596/",),
        tags=("attack.reconnaissance", "attack.t1596"),
    ),
    _r(
        "kalkan-web-001",
        "SQL Enjeksiyonu - UNION SELECT",
        "high",
        "T1190",
        _WEB,
        "Sorgu parametresinde UNION SELECT kalibi.",
        {"selection": {"cs-uri-query|contains": ("union select", "union all select", "information_schema")}},
        falsepositives=("Guvenlik testi", "Arama motoru botu"),
        references=("https://attack.mitre.org/techniques/T1190/", "https://owasp.org/Top10/A03_2021-Injection/"),
        tags=("attack.initial_access", "attack.t1190", "web.sqli"),
    ),
    _r(
        "kalkan-web-002",
        "SQL Enjeksiyonu - Zaman Tabanli",
        "high",
        "T1190",
        _WEB,
        "Parametrede SLEEP/BENCHMARK/pg_sleep gibi gecikme fonksiyonlari.",
        {"selection": {"cs-uri-query|contains": ("sleep(", "benchmark(", "pg_sleep(", "waitfor delay")}},
        falsepositives=("Mesru yavas sorgu testi",),
        references=("https://attack.mitre.org/techniques/T1190/",),
        tags=("attack.initial_access", "attack.t1190", "web.sqli"),
    ),
    _r(
        "kalkan-web-003",
        "Yansitilan XSS - Script Etiketi",
        "medium",
        "T1059.007",
        _WEB,
        "Yanitta kullanici girdisinin script baglaminda donmesi.",
        {"selection": {"cs-uri-query|contains": ("<script", "javascript:", "onerror=", "onload=", "svg/onload")}},
        falsepositives=("Zengin metin editoru", "Guvenlik tarayicisi"),
        references=("https://attack.mitre.org/techniques/T1059/007/",),
        tags=("attack.execution", "attack.t1059.007", "web.xss"),
    ),
    _r(
        "kalkan-web-004",
        "Dizin Atlama (Path Traversal)",
        "high",
        "T1083",
        _WEB,
        "Yol parametresinde ../ veya kodlanmis karsiliklari.",
        {"selection": {"cs-uri-stem|contains": ("../", "..%2f", "%2e%2e%2f", "..\\", "%252e%252e")}},
        falsepositives=("Dosya yoneticisi uygulamasi",),
        references=("https://attack.mitre.org/techniques/T1083/",),
        tags=("attack.discovery", "attack.t1083", "web.traversal"),
    ),
    _r(
        "kalkan-web-005",
        "Hassas Dosya Okuma Denemesi",
        "high",
        "T1005",
        _WEB,
        "passwd, .env, .git/config gibi hassas dosyalara erisim denemesi.",
        {"selection": {"cs-uri-stem|contains": ("/etc/passwd", "/.env", "/.git/config", "/web.config", "/.aws/credentials")}},
        falsepositives=("Yanlis yapilandirilmis uygulama",),
        references=("https://attack.mitre.org/techniques/T1005/",),
        tags=("attack.collection", "attack.t1005"),
    ),
    _r(
        "kalkan-web-006",
        "Isletim Sistemi Komut Enjeksiyonu",
        "critical",
        "T1059.004",
        _WEB,
        "Parametrede kabuk ayirici ve komut kalibi.",
        {"selection": {"cs-uri-query|contains": (";id", "|whoami", "&&id", "$(id)", "`id`", ";cat /etc/passwd")}},
        falsepositives=("Mesru entegrasyon testi",),
        references=("https://attack.mitre.org/techniques/T1059/004/",),
        tags=("attack.execution", "attack.t1059.004"),
    ),
    _r(
        "kalkan-web-007",
        "Sunucu Tarafi Sablon Enjeksiyonu",
        "high",
        "T1190",
        _WEB,
        "Sablon ifadesi ({{7*7}}, ${7*7}) parametre olarak gonderilmis.",
        {"selection": {"cs-uri-query|contains": ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}")}},
        falsepositives=("Sablon gelistirici",),
        references=("https://attack.mitre.org/techniques/T1190/",),
        tags=("attack.initial_access", "attack.t1190", "web.ssti"),
    ),
    _r(
        "kalkan-web-008",
        "Log4Shell JNDI Yuku",
        "critical",
        "T1190",
        _WEB,
        "Herhangi bir baslikta ${jndi:...} kalibi.",
        {"selection": {"cs-header|contains": ("${jndi:", "${lower:j", "${env:")}},
        falsepositives=("Guvenlik tarayicisi",),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2021-44228",),
        tags=("attack.initial_access", "attack.t1190", "cve.2021-44228"),
    ),
    _r(
        "kalkan-web-009",
        "Web Shell Yukleme",
        "high",
        "T1505.003",
        _WEB,
        "Yukleme dizininde calistirilabilir dosya olusturulmasi ve erisimi.",
        {
            "selection": {
                "cs-method": "POST",
                "cs-uri-stem|endswith": (".php", ".jsp", ".aspx", ".ashx"),
                "sc-status": 200,
            }
        },
        falsepositives=("Mesru dosya yukleme ozelligi",),
        references=("https://attack.mitre.org/techniques/T1505/003/",),
        tags=("attack.persistence", "attack.t1505.003"),
    ),
    _r(
        "kalkan-web-010",
        "Gevsek CORS Yapilandirmasi",
        "medium",
        "T1190",
        _WEB,
        "Origin yansitmasi ve credentials=true birlikte donuyor.",
        {
            "selection": {
                "cs-header|contains": "access-control-allow-origin",
                "sc-header|contains": ("access-control-allow-credentials: true", "*"),
            }
        },
        falsepositives=("Herkese acik API",),
        references=("https://owasp.org/www-project-web-security-testing-guide/",),
        tags=("attack.initial_access", "attack.t1190", "web.cors"),
    ),
    _r(
        "kalkan-web-011",
        "Eksik Guvenlik Basliklari",
        "low",
        "T1190",
        _WEB,
        "CSP/HSTS/X-Content-Type-Options basliklari yok.",
        {"selection": {"sc-header|contains": ("content-security-policy", "strict-transport-security")}, "condition": "selection"},
        falsepositives=("Ic uygulama", "Gelistirme ortami"),
        references=("https://owasp.org/www-project-secure-headers/",),
        tags=("attack.initial_access", "attack.t1190", "web.headers"),
    ),
    _r(
        "kalkan-web-012",
        "Tehlikeli HTTP Metodu",
        "medium",
        "T1190",
        _WEB,
        "PUT/DELETE/TRACE gibi yazma veya hata ayiklama metodlari kabul ediliyor.",
        {"selection": {"cs-method": ("PUT", "DELETE", "TRACE", "CONNECT")}},
        falsepositives=("WebDAV", "REST API"),
        references=("https://owasp.org/www-project-web-security-testing-guide/",),
        tags=("attack.initial_access", "attack.t1190"),
    ),
    _r(
        "kalkan-web-013",
        "Yapilandirma Dosyasi Sizintisi",
        "medium",
        "T1552.001",
        _WEB,
        ".git, .svn, .DS_Store veya yedek dosyalara basarili erisim (200).",
        {"selection": {"cs-uri-stem|contains": ("/.git/", "/.svn/", "/.DS_Store", ".bak", ".old", ".sql")}},
        falsepositives=("Bilincli olarak yayinlanan dosya",),
        references=("https://attack.mitre.org/techniques/T1552/001/",),
        tags=("attack.credential_access", "attack.t1552.001"),
    ),
    _r(
        "kalkan-web-014",
        "JWT Algoritma None / Zayif Dogrulama",
        "high",
        "T1550.001",
        _WEB,
        "Authorization basliginda alg=none veya dogrulanmamis token.",
        {"selection": {"cs-header|contains": ("eyJhbGciOiJub25lIiw", "alg\":\"none")}},
        falsepositives=("Gelistirme tokeni",),
        references=("https://attack.mitre.org/techniques/T1550/001/",),
        tags=("attack.defense_evasion", "attack.t1550.001", "web.jwt"),
    ),
    _r(
        "kalkan-web-015",
        "SSRF - Bulut Metadata Erisimi",
        "high",
        "T1552.005",
        _WEB,
        "Sunucu tarafinda 169.254.169.254 veya metadata.google.internal erisimi.",
        {"selection": {"cs-uri-query|contains": ("169.254.169.254", "metadata.google.internal", "100.100.100.200")}},
        falsepositives=("Bulut ajanı",),
        references=("https://attack.mitre.org/techniques/T1552/005/",),
        tags=("attack.credential_access", "attack.t1552.005", "web.ssrf"),
    ),
    _r(
        "kalkan-web-016",
        "Mass Assignment - Yetki Alani",
        "medium",
        "T1098",
        _WEB,
        "Istek govdesinde role/is_admin gibi korunmasi gereken alanlar.",
        {"selection": {"cs-body|contains": ("\"role\":", "\"is_admin\":", "\"isAdmin\":", "\"plan\":\"enterprise\"")}},
        falsepositives=("Yonetici paneli",),
        references=("https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",),
        tags=("attack.persistence", "attack.t1098", "web.mass_assignment"),
    ),
    _r(
        "kalkan-ai-001",
        "Dogrudan Prompt Enjeksiyonu",
        "high",
        "AML.T0051.000",
        _LLM,
        "Kullanici mesajinda sistem talimati taklidi veya onceki talimatlari yok sayma.",
        {"selection": {"request.body|contains": ("ignore all previous", "ignore previous instructions", "[system]", "you are now", "disregard prior")}},
        falsepositives=("Guvenlik testi", "Egitim icerigi"),
        references=("https://atlas.mitre.org/techniques/AML.T0051/",),
        tags=("atlas.execution", "atlas.aml.t0051.000"),
    ),
    _r(
        "kalkan-ai-002",
        "Dolayli Prompt Enjeksiyonu (RAG)",
        "high",
        "AML.T0051.001",
        _LLM,
        "Getirilen belge veya arac ciktisinda gomulu talimat.",
        {"selection": {"retrieval.document|contains": ("ignore the user", "assistant override", "note to the assistant", "hidden instruction")}},
        falsepositives=("Guvenlik dokumantasyonu",),
        references=("https://atlas.mitre.org/techniques/AML.T0051/",),
        tags=("atlas.execution", "atlas.aml.t0051.001"),
    ),
    _r(
        "kalkan-ai-003",
        "Jailbreak Kaliplari",
        "medium",
        "AML.T0054",
        _LLM,
        "DAN/rol yapma/ceviri ile politika asma denemesi.",
        {"selection": {"request.body|contains": ("do anything now", "dan mode", "no restrictions", "developer mode", "roleplay as")}},
        falsepositives=("Yaratici yazarlik",),
        references=("https://atlas.mitre.org/techniques/AML.T0054/",),
        tags=("atlas.defense_evasion", "atlas.aml.t0054"),
    ),
    _r(
        "kalkan-ai-004",
        "Sistem Promptu Sizdirma Denemesi",
        "medium",
        "AML.T0057",
        _LLM,
        "Sistem promptunu veya gizli isaretciyi isteme.",
        {"selection": {"request.body|contains": ("system prompt", "your instructions", "secret marker", "repeat everything above")}},
        falsepositives=("Gelistirici hata ayiklama",),
        references=("https://atlas.mitre.org/techniques/AML.T0057/",),
        tags=("atlas.exfiltration", "atlas.aml.t0057"),
    ),
    _r(
        "kalkan-ai-005",
        "Ajan Arac Cagrisi - Kabuk",
        "critical",
        "AML.T0050",
        _LLM,
        "Ajanin shell/exec/http_request gibi hassas araclari cagirmasi.",
        {"selection": {"event.action": "tool_call", "tool.name": ("shell", "exec", "bash", "cmd", "powershell", "http_request", "file_write")}},
        falsepositives=("Yetkili otomasyon",),
        references=("https://atlas.mitre.org/techniques/AML.T0050/",),
        tags=("atlas.execution", "atlas.aml.t0050"),
    ),
    _r(
        "kalkan-ai-006",
        "Yanitta Canary Isaretcisi",
        "high",
        "AML.T0057",
        _LLM,
        "Model yanitinda sistem promptuna gomulu canary degeri gorunuyor.",
        {"selection": {"response.body|contains": "KALKAN-CANARY"}},
        falsepositives=("Test ortami",),
        references=("https://atlas.mitre.org/techniques/AML.T0057/",),
        tags=("atlas.exfiltration", "atlas.aml.t0057"),
    ),
    _r(
        "kalkan-ai-007",
        "Kimlik Dogrulamasiz Model API'si",
        "high",
        "AML.T0040",
        {"category": "application", "product": "model-server"},
        "Model listesi/çıkarım uç noktası kimlik dogrulama olmadan 200 donuyor.",
        {"selection": {"event.action": "api_request", "url.path": ("/api/tags", "/v1/models"), "status": 200, "auth.present": False}},
        falsepositives=("Kasitli olarak acik yerel model",),
        references=("https://atlas.mitre.org/techniques/AML.T0040/",),
        tags=("atlas.discovery", "atlas.aml.t0040"),
    ),
    _r(
        "kalkan-ai-008",
        "Asiri Uzun Istek - Kaynak Tuketimi",
        "medium",
        "AML.T0029",
        _LLM,
        "Tek istekte cok yuksek token veya tekrarlayan uretim talebi.",
        {"selection": {"request.tokens": {"gte": 8000}, "request.body|contains": ("repeat", "10000", "until the token limit")}},
        falsepositives=("Uzun belge ozetleme",),
        references=("https://atlas.mitre.org/techniques/AML.T0029/",),
        tags=("atlas.impact", "atlas.aml.t0029"),
    ),
    _r(
        "kalkan-ai-009",
        "Model Yanitinda Sir Sizintisi",
        "high",
        "AML.T0024",
        _LLM,
        "Yanitta API anahtari, token veya ozel anahtar formati.",
        {"selection": {"response.body|contains": ("sk-", "AKIA", "ghp_", "xoxb-", "-----BEGIN", "postgres://", "mysql://")}},
        falsepositives=("Dokumantasyon ornegi",),
        references=("https://atlas.mitre.org/techniques/AML.T0024/",),
        tags=("atlas.exfiltration", "atlas.aml.t0024"),
    ),
    _r(
        "kalkan-ai-010",
        "Bilgi Tabanina Zehirli Belge Yukleme",
        "high",
        "AML.T0020",
        {"category": "application", "product": "rag-ingest"},
        "Dokuman yuklemesinde talimat benzeri icerik veya gizli isaret.",
        {"selection": {"event.action": "document_upload", "document.content|contains": ("ignore previous", "assistant override", "KALKAN-RAG", "[system]")}},
        falsepositives=("Guvenlik egitimi materyali",),
        references=("https://atlas.mitre.org/techniques/AML.T0020/",),
        tags=("atlas.impact", "atlas.aml.t0020"),
    ),
)

INDEX: dict[str, DetectionRule] = {r.id: r for r in _RULES}


def get(rule_id: str) -> DetectionRule | None:
    return INDEX.get(rule_id.strip())


def all_rules() -> tuple[DetectionRule, ...]:
    return _RULES


def by_technique(technique: str) -> list[DetectionRule]:
    return [r for r in _RULES if r.technique.upper().startswith(technique.strip().upper())]


def by_logsource(category: str) -> list[DetectionRule]:
    return [r for r in _RULES if category.strip().lower() in {str(v).lower() for v in r.logsource.values()}]


def by_level(level: str) -> list[DetectionRule]:
    floor = LEVEL_ORDER.get(level.strip().lower(), 0)
    return [r for r in _RULES if r.severity >= floor]


def for_playbook(technique: str) -> list[DetectionRule]:
    """Bir teknik icin dogrudan ve ust teknik uzerinden eslesen kurallar."""
    key = technique.strip().upper()
    exact = by_technique(key)
    if exact:
        return exact
    parent = key.rsplit(".", 1)[0]
    if parent != key:
        return by_technique(parent)
    return []


def search(text: str) -> list[DetectionRule]:
    needle = text.strip().lower()
    if not needle:
        return list(_RULES)
    hits: list[DetectionRule] = []
    for rule in _RULES:
        blob = " ".join(
            [
                rule.id,
                rule.title,
                rule.description,
                rule.technique,
                " ".join(rule.tags),
                " ".join(str(v) for v in rule.logsource.values()),
            ]
        ).lower()
        if needle in blob:
            hits.append(rule)
    return hits


def stats() -> dict[str, Any]:
    levels: dict[str, int] = {}
    frameworks: dict[str, int] = {}
    for rule in _RULES:
        levels[rule.level] = levels.get(rule.level, 0) + 1
        frameworks[rule.framework] = frameworks.get(rule.framework, 0) + 1
    return {
        "count": len(_RULES),
        "by_level": dict(sorted(levels.items(), key=lambda kv: LEVEL_ORDER.get(kv[0], 0))),
        "by_framework": frameworks,
        "techniques": len({r.technique for r in _RULES}),
    }


def export(directory: str | Path) -> list[Path]:
    """Tum kurallari Sigma YAML dosyalari olarak yazar."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for rule in _RULES:
        path = target / f"{rule.id}.yml"
        path.write_text(rule.to_yaml(), encoding="utf-8")
        written.append(path)
    return written


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "":
        return "''"
    needs_quote = (
        any(ch in text for ch in ":#{}[],&*!|>'\"%@`\n\t")
        or text.strip() != text
        or text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
        or _looks_numeric(text)
    )
    if not needs_quote:
        return text
    return "'" + text.replace("'", "''") + "'"


def _looks_numeric(text: str) -> bool:
    try:
        float(text)
        return True
    except ValueError:
        return False


def _yaml(value: Any, indent: int = 0) -> str:
    pad = " " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, dict) and item:
                lines.append(f"{pad}{key}:")
                lines.append(_yaml(item, indent + 2))
            elif isinstance(item, (list, tuple)) and item:
                lines.append(f"{pad}{key}:")
                lines.append(_yaml(list(item), indent + 2))
            elif isinstance(item, (list, tuple)) and not item:
                lines.append(f"{pad}{key}: []")
            elif isinstance(item, dict) and not item:
                lines.append(f"{pad}{key}: {{}}")
            else:
                lines.append(f"{pad}{key}: {_scalar(item)}")
    elif isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, dict):
                block = _yaml(item, indent + 2).splitlines()
                if block:
                    lines.append(f"{pad}- {block[0].strip()}")
                    lines.extend(block[1:])
            elif isinstance(item, (list, tuple)):
                lines.append(f"{pad}-")
                lines.append(_yaml(list(item), indent + 2))
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    else:
        lines.append(f"{pad}{_scalar(value)}")
    return "\n".join(lines)
