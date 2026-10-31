"""Teknik -> yetenek -> arac haritasi.

Sistemin kalbi burasi. Bir ATT&CK/ATLAS teknik kimligi verildiginde
hangi araclarin hangi sirayla calisacagi burada tanimli. Model bu
tabloyu *degistiremez*, sadece hangi teknikle ilgilendigini secer.

Her playbook `rules` alaninda tespit kural kimliklerini de tasir.
Boylece ayni teknik icin "saldiri adimi" ve "logda nasil gorunur"
bilgisi tek yerde durur.

Riskli adimlar (sqlmap, dalfox, msf) `required=("verify",)` ile opt-in
tutulur; `--arg verify=1` verilmeden plana girmez. Varsayilan kosu
gozlem ve dogrulama ile sinirlidir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import Risk

LLM_ARGS = ("endpoint", "model", "api", "canary", "system", "payload_ids", "delay")


@dataclass(frozen=True)
class Step:
    capability: str
    tool: str
    risk: Risk
    args: dict[str, Any] = field(default_factory=dict)
    required: tuple[str, ...] = ()
    accepts: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class Playbook:
    technique: str
    name: str
    tactic: str
    framework: str
    steps: tuple[Step, ...]
    detection: str = ""
    evidence: tuple[str, ...] = ()
    notes: str = ""
    rules: tuple[str, ...] = ()


_PLAYBOOKS: tuple[Playbook, ...] = (
    Playbook(
        technique="T1595",
        name="Active Scanning",
        tactic="reconnaissance",
        framework="attack",
        steps=(
            Step("passive_osint", "shodan", Risk.PASSIVE, note="Hedefe dokunmadan dışarıdan görüneni al"),
            Step(
                "port_scan",
                "nmap",
                Risk.ACTIVE,
                {"top_ports": 100},
                accepts=("top_ports", "ports", "rate"),
            ),
        ),
        detection="Dış IP'den çoklu porta SYN; firewall/NetFlow hacim artışı",
        evidence=("shodan_ports", "open_ports"),
        rules=("kalkan-recon-001", "kalkan-recon-004"),
    ),
    Playbook(
        technique="T1595.001",
        name="Scanning IP Blocks",
        tactic="reconnaissance",
        framework="attack",
        steps=(
            Step(
                "host_discovery",
                "nmap",
                Risk.ACTIVE,
                {"ports": None},
                accepts=("ports", "rate", "timeout"),
            ),
        ),
        detection="ICMP/ARP keşif artışı, aynı /24'ten sıralı tarama",
        evidence=("host_count",),
        rules=("kalkan-recon-001",),
    ),
    Playbook(
        technique="T1595.002",
        name="Vulnerability Scanning",
        tactic="reconnaissance",
        framework="attack",
        steps=(
            Step(
                "vuln_scan",
                "nuclei",
                Risk.ACTIVE,
                {"severity": "low,medium,high,critical"},
                accepts=("severity", "tags", "templates", "cve_id"),
            ),
        ),
        detection="WAF/gateway loglarında şablon imzaları, 404 patlaması",
        evidence=("findings", "by_severity"),
        rules=("kalkan-recon-003",),
        notes="Belirli bir CVE için --arg cve_id=CVE-2024-... verilebilir.",
    ),
    Playbook(
        technique="T1595.003",
        name="Wordlist Scanning",
        tactic="reconnaissance",
        framework="attack",
        steps=(
            Step(
                "content_discovery",
                "ffuf",
                Risk.ACTIVE,
                {"wordlist": None},
                accepts=("wordlist", "extensions", "method", "headers", "rate", "timeout"),
                note="Gizli dizin/dosya keşfi; 200/403 dönen yollar raporlanır",
            ),
        ),
        detection="Aynı istemciden sıralı 404 patlaması ve bilinen yol denemeleri",
        evidence=("findings", "interesting", "by_status"),
        rules=("kalkan-recon-002",),
    ),
    Playbook(
        technique="T1590",
        name="Gather Victim Network Information",
        tactic="reconnaissance",
        framework="attack",
        steps=(Step("host_lookup", "shodan", Risk.PASSIVE),),
        detection="Pasif; hedefte iz bırakmaz. Üçüncü taraf sorgu kaydı kalır.",
        evidence=("ports", "hostnames", "org"),
        rules=("kalkan-recon-004",),
    ),
    Playbook(
        technique="T1596",
        name="Search Open Technical Databases",
        tactic="reconnaissance",
        framework="attack",
        steps=(Step("exposure_lookup", "shodan", Risk.PASSIVE),),
        detection="Pasif; yalnızca API kota kaydı.",
        evidence=("known_vulns", "services"),
        rules=("kalkan-recon-004",),
    ),
    Playbook(
        technique="T1046",
        name="Network Service Discovery",
        tactic="discovery",
        framework="attack",
        steps=(
            Step("port_scan", "nmap", Risk.ACTIVE, {"top_ports": 1000}, accepts=("top_ports", "rate")),
            Step(
                "service_version",
                "nmap",
                Risk.ACTIVE,
                {"ports": "$open_ports"},
                note="Önceki adımın açık portları üzerinde versiyon tespiti",
            ),
        ),
        detection="Tek kaynaktan sıralı port denemesi; iç DNS/NetFlow",
        evidence=("hosts", "open_ports"),
        rules=("kalkan-recon-001",),
    ),
    Playbook(
        technique="T1592",
        name="Gather Victim Host Information",
        tactic="reconnaissance",
        framework="attack",
        steps=(
            Step("service_version", "nmap", Risk.ACTIVE, {"top_ports": 200}, accepts=("top_ports", "ports")),
            Step("tech_detect", "httpx", Risk.ACTIVE, accepts=("ports", "timeout", "rate_limit")),
        ),
        detection="Servis banner'larına yönelik tekrarlı bağlantılar",
        evidence=("hosts", "technologies"),
        rules=("kalkan-recon-003",),
    ),
    Playbook(
        technique="T1190",
        name="Exploit Public-Facing Application",
        tactic="initial-access",
        framework="attack",
        steps=(
            Step("waf_detect", "wafw00f", Risk.PASSIVE, note="Önce WAF/CDN var mı? Payload seçimi buna bağlı."),
            Step(
                "security_headers",
                "webprobe",
                Risk.ACTIVE,
                accepts=("timeout",),
                note="CSP/HSTS/X-Frame-Options gibi başlıkları denetler",
            ),
            Step("cors_check", "webprobe", Risk.ACTIVE, accepts=("origin", "timeout")),
            Step(
                "http_methods",
                "webprobe",
                Risk.ACTIVE,
                accepts=("timeout",),
                note="PUT/DELETE/TRACE açık mı?",
            ),
            Step(
                "web_template",
                "nuclei",
                Risk.ACTIVE,
                {"tags": "cve,exposure"},
                accepts=("tags", "templates", "severity", "cve_id"),
            ),
            Step(
                "sqli_check",
                "sqlmap",
                Risk.INTRUSIVE,
                {"verify": None, "level": 1, "risk": 1},
                required=("verify",),
                accepts=("verify", "level", "risk", "param", "data", "cookie", "forms", "timeout"),
                note="--arg verify=1 ile açılır; yalnızca tespit, veri çekmez",
            ),
            Step(
                "xss_scan",
                "dalfox",
                Risk.INTRUSIVE,
                {"verify": None},
                required=("verify",),
                accepts=("verify", "method", "data", "cookie", "workers", "deep_domxss"),
                note="--arg verify=1 ile açılır",
            ),
            Step(
                "exploit_check",
                "msf",
                Risk.INTRUSIVE,
                {"module": "", "mode": "check"},
                required=("module",),
                accepts=("module", "mode", "payload", "lhost", "lport", "options"),
                note="--arg module=... verilmezse atlanır; varsayılan mod check",
            ),
        ),
        detection="İstek gövdesinde exploit imzası; 500 patlaması; WAF kuralı",
        evidence=("findings", "vulnerable", "parameters", "rc_script"),
        notes="Exploit çalıştırma (mode=run) ayrıca --allow-exploit ister.",
        rules=(
            "kalkan-web-001",
            "kalkan-web-002",
            "kalkan-web-003",
            "kalkan-web-006",
            "kalkan-web-007",
            "kalkan-web-008",
            "kalkan-web-010",
            "kalkan-web-011",
            "kalkan-web-012",
            "kalkan-web-015",
            "kalkan-web-016",
        ),
    ),
    Playbook(
        technique="T1083",
        name="File and Directory Discovery",
        tactic="discovery",
        framework="attack",
        steps=(
            Step(
                "content_discovery",
                "ffuf",
                Risk.ACTIVE,
                {"wordlist": None, "extensions": "bak,old,sql,zip,config"},
                accepts=("wordlist", "extensions", "method", "headers", "rate"),
            ),
            Step("redirect_check", "webprobe", Risk.ACTIVE, accepts=("timeout",)),
        ),
        detection="Hassas dosya yollarına sıralı erişim; 200 dönen .git/.env",
        evidence=("findings", "interesting"),
        rules=("kalkan-web-004", "kalkan-web-005", "kalkan-web-013"),
    ),
    Playbook(
        technique="T1059.007",
        name="JavaScript/JScript (XSS)",
        tactic="execution",
        framework="attack",
        steps=(
            Step(
                "xss_scan",
                "dalfox",
                Risk.INTRUSIVE,
                {"verify": None},
                required=("verify",),
                accepts=("verify", "method", "data", "cookie", "workers", "deep_domxss", "blind"),
                note="--arg verify=1 ile açılır; yansıyan/stored XSS doğrular",
            ),
        ),
        detection="Yanıtta script etiketi; CSP raporları; WAF XSS kuralı",
        evidence=("findings", "vulnerable"),
        rules=("kalkan-web-003",),
    ),
    Playbook(
        technique="T1203",
        name="Exploitation for Client Execution",
        tactic="execution",
        framework="attack",
        steps=(
            Step(
                "exploit_check",
                "msf",
                Risk.INTRUSIVE,
                {"module": "", "mode": "check"},
                required=("module",),
                accepts=("module", "mode", "payload", "lhost", "lport", "options"),
            ),
        ),
        detection="İstemci tarafı exploit işaretleri; EDR belleği",
        evidence=("vulnerable", "rc_script"),
        rules=(),
    ),
    Playbook(
        technique="T1699",
        name="Direct Prompt Injection",
        tactic="execution",
        framework="attack",
        steps=(
            Step("llm_injection_probe", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
        ),
        detection="Ajan/araç çağrısı loglarında beklenmeyen komut veya argüman",
        evidence=("complied", "refused", "results"),
        notes="ATT&CK tarafındaki karşılığı; ATLAS AML.T0051 ile aynı adaptörü kullanır.",
        rules=("kalkan-ai-001",),
    ),
    Playbook(
        technique="T1698",
        name="Indirect Prompt Injection",
        tactic="execution",
        framework="attack",
        steps=(
            Step("llm_rag_injection", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
        ),
        detection="Getirilen belge/log içeriğinde talimat kalıpları; araç çağrısı sapması",
        evidence=("marker_hits", "injected", "results"),
        notes="Dolaylı enjeksiyon: RAG/ajan bağlamına gömülü talimatlar.",
        rules=("kalkan-ai-002",),
    ),
    Playbook(
        technique="AML.T0040",
        name="ML Model Inference API Access",
        tactic="discovery",
        framework="atlas",
        steps=(
            Step(
                "llm_api_access_probe",
                "llmprobe",
                Risk.PASSIVE,
                accepts=("endpoint", "api", "timeout"),
                note="Kimlik doğrulamasız /api/tags ve /v1/models erişimi",
            ),
        ),
        detection="Model sunucusunda auth'suz 200; erişim logunda token yok",
        evidence=("status", "models", "auth_required", "findings"),
        rules=("kalkan-ai-007",),
    ),
    Playbook(
        technique="AML.T0024",
        name="Exfiltration via ML Inference API",
        tactic="exfiltration",
        framework="atlas",
        steps=(
            Step("llm_model_extraction", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
            Step("llm_exfil_probe", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
        ),
        detection="Yanıtta anahtar/bağlam sızıntısı; anormal yanıt boyutu",
        evidence=("leaks", "extracted", "exfil_signals", "results"),
        rules=("kalkan-ai-009",),
    ),
    Playbook(
        technique="AML.T0029",
        name="Denial of ML Service",
        tactic="impact",
        framework="atlas",
        steps=(
            Step(
                "llm_dos_probe",
                "llmprobe",
                Risk.PASSIVE,
                {"payload_ids": ["ds-01", "ds-03"]},
                accepts=("endpoint", "model", "api", "payload_ids", "delay"),
                note="Yalnızca iki uzun istek; gecikme ölçülür, hizmet zorlanmaz",
            ),
        ),
        detection="Aynı istemciden uzun süreli/çok tokenlı istekler; kuyruk gecikmesi",
        evidence=("max_latency_ms", "slow", "results"),
        rules=("kalkan-ai-008",),
    ),
    Playbook(
        technique="AML.T0050",
        name="Command and Scripting Interpreter",
        tactic="execution",
        framework="atlas",
        steps=(
            Step("llm_agent_hijack", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
        ),
        detection="Ajan araç çağrısı logunda shell/http_request/file_write",
        evidence=("tool_calls", "hijacked", "results"),
        rules=("kalkan-ai-005",),
    ),
    Playbook(
        technique="AML.T0051",
        name="LLM Prompt Injection",
        tactic="execution",
        framework="atlas",
        steps=(
            Step("llm_injection_probe", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
            Step("llm_rag_injection", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
        ),
        detection="Ajan araç çağrısı loglarında beklenmeyen argümanlar",
        evidence=("complied", "refused", "marker_hits", "results"),
        rules=("kalkan-ai-001", "kalkan-ai-002"),
    ),
    Playbook(
        technique="AML.T0051.000",
        name="LLM Prompt Injection: Direct",
        tactic="execution",
        framework="atlas",
        steps=(
            Step("llm_injection_probe", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
        ),
        detection="Kullanıcı mesajında [SYSTEM] taklidi / talimat ezme",
        evidence=("complied", "refused", "results"),
        rules=("kalkan-ai-001",),
    ),
    Playbook(
        technique="AML.T0051.001",
        name="LLM Prompt Injection: Indirect",
        tactic="execution",
        framework="atlas",
        steps=(
            Step("llm_rag_injection", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
        ),
        detection="Getirilen belgede talimat kalıbı; yanıtta gömülü işaretçi",
        evidence=("marker_hits", "injected", "results"),
        rules=("kalkan-ai-002",),
    ),
    Playbook(
        technique="AML.T0054",
        name="LLM Jailbreak",
        tactic="defense-evasion",
        framework="atlas",
        steps=(
            Step("llm_jailbreak_probe", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
        ),
        detection="Yanıt politikası ihlalleri; çıktı filtreleri",
        evidence=("complied", "refused", "results"),
        rules=("kalkan-ai-003",),
    ),
    Playbook(
        technique="AML.T0057",
        name="LLM Data Leakage",
        tactic="exfiltration",
        framework="atlas",
        steps=(
            Step("llm_leak_probe", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
            Step("llm_exfil_probe", "llmprobe", Risk.PASSIVE, accepts=LLM_ARGS),
        ),
        detection="Yanıtta canary işaretçisi; DLP kuralı",
        evidence=("canary_leaks", "exfil_signals", "results"),
        rules=("kalkan-ai-004", "kalkan-ai-006"),
    ),
)

INDEX: dict[str, Playbook] = {p.technique.upper(): p for p in _PLAYBOOKS}


def get(technique: str) -> Playbook | None:
    return INDEX.get(technique.strip().upper())


def all_playbooks() -> tuple[Playbook, ...]:
    return _PLAYBOOKS


def by_tactic(tactic: str) -> list[Playbook]:
    t = tactic.strip().lower()
    return [p for p in _PLAYBOOKS if p.tactic == t]


def tactics() -> list[str]:
    return sorted({p.tactic for p in _PLAYBOOKS})


def techniques() -> list[str]:
    return sorted(INDEX)


def coverage(registry) -> list[dict[str, Any]]:
    """Her playbook icin araclarin kurulu olup olmadigini raporlar."""
    rows: list[dict[str, Any]] = []
    for pb in _PLAYBOOKS:
        missing: list[str] = []
        for step in pb.steps:
            try:
                adapter = registry.get(step.tool)
            except KeyError:
                missing.append(f"{step.tool} (kayıtlı değil)")
                continue
            if not adapter.available():
                missing.append(f"{step.tool} ({adapter.unavailable_reason()})")
        rows.append(
            {
                "technique": pb.technique,
                "name": pb.name,
                "tactic": pb.tactic,
                "framework": pb.framework,
                "steps": len(pb.steps),
                "max_risk": max((s.risk for s in pb.steps), default=Risk.PASSIVE),
                "ready": not missing,
                "missing": missing,
                "rules": list(pb.rules),
            }
        )
    return rows
