"""Otonom ajan dongusu - gozlemle, dusun, uygula, raporla.

Felsefe: kalkan'in GUVENLI CEKIRDEGI (scope + policy + audit + deterministik
adaptorler) oldugu gibi korunur. Ajan bu cekirdegin USTUNE oturur: her adimda
elindeki yetenek katalogundan + o ana kadarki bulgulardan + MITRE playbook
bilgisinden SONRAKI aksiyonu secer, ayni Executor kapilarindan gecirir, sonucu
geri okur ve "sunu denedim -> su oldu" diye raporlar.

Kor deneme yok: once kesif, sonra tespit, zafiyetli surum gorulurse korelasyon
(urun/surum -> CVE -> msf/sqlmap/nuclei) uzerinden exploit'e pivot. Secimi
mumkunse model (kalkan-router) yapar; model yoksa/gecersiz secerse deterministik
yedek ayni oncelik sirasiyla devam eder -> sistem modelsiz de calisir.

Argumanlar ve risk seviyeleri MODELDEN DEGIL, curated playbook'lardan gelir;
model yalnizca "siradaki hangi yetenek" sorusunu cevaplar. Boylece 4B'lik bir
model bile guvenle surucu koltuguna oturabilir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .. import correlate as _correlate
from ..audit import AuditLog
from ..knowledge import mapping
from ..models import Action, ActionResult, Plan, Risk
from ..policy import Policy, PolicyDenied
from ..registry import Registry
from ..scope import ScopeGuard, ScopeViolation
from .executor import Executor
from .router import Router

PURPOSE: dict[str, str] = {
    "passive_osint": "hedefe dokunmadan disaridan goruneni al (Shodan)",
    "host_lookup": "Shodan host kaydi (acik servisler/surumler)",
    "exposure_lookup": "disariya acik yuzey taramasi (Shodan)",
    "host_discovery": "canli host tespiti",
    "port_scan": "acik port taramasi",
    "service_version": "servis/surum parmak izi (surum -> CVE icin kritik)",
    "vuln_script": "nmap NSE zafiyet betikleri",
    "http_probe": "HTTP canlilik ve temel yanit",
    "tech_detect": "web teknoloji/surum parmak izi",
    "waf_detect": "WAF/koruma tespiti",
    "security_headers": "guvenlik basliklari denetimi (CSP/HSTS...)",
    "cookie_flags": "cerez bayraklari (HttpOnly/Secure)",
    "cors_check": "CORS yanlis yapilandirmasi",
    "http_methods": "izinli HTTP metotlari",
    "tls_inspect": "TLS surum/sifre denetimi",
    "redirect_check": "yonlendirme zinciri/acik yonlendirme",
    "source_recon": "istemci JS/kaynak haritasi + gomulu sir taramasi",
    "idor_probe": "IDOR/BOLA erisim kontrol denemesi",
    "content_discovery": "gizli dizin/dosya kesfi",
    "parameter_fuzzing": "parametre fuzzing",
    "param_discovery": "gizli HTTP parametreleri",
    "web_misconfig": "web sunucu yanlis yapilandirmasi (nikto)",
    "vuln_scan": "sablon tabanli zafiyet taramasi (nuclei)",
    "web_template": "belirli CVE sablonuyla dogrulama (nuclei -id)",
    "misconfig_scan": "yanlis yapilandirma sablonlari",
    "xss_scan": "XSS taramasi (dalfox)",
    "dom_render": "tarayicida DOM render (CDP)",
    "net_capture": "tarayici ag trafigi yakalama (DevTools/CDP)",
    "js_eval": "tarayicida JS calistirma (CDP)",
    "dom_xss": "DOM tabanli XSS denemesi (CDP)",
    "screenshot": "sayfa ekran goruntusu",
    "sqli_check": "SQLi dogrulama (sqlmap)",
    "sqli_dump": "SQLi ile veri cekme (YIKICI)",
    "exploit_check": "exploit uygunlugu dogrula (msf check)",
    "exploit_run": "gercek exploit calistir (msf, YIKICI)",
    "auxiliary_scan": "msf yardimci tarama modulu",
}

PHASE_ORDER: tuple[str, ...] = (
    "passive_osint", "host_lookup", "exposure_lookup",
    "host_discovery", "port_scan", "service_version", "http_probe",
    "tech_detect", "waf_detect",
    "security_headers", "cookie_flags", "cors_check", "http_methods",
    "tls_inspect", "redirect_check", "source_recon",
    "content_discovery", "param_discovery",
    "vuln_scan", "misconfig_scan", "web_misconfig", "vuln_script",
    "web_template", "idor_probe", "xss_scan", "dom_xss", "net_capture",
    "parameter_fuzzing", "sqli_check",
    "exploit_check", "exploit_run", "sqli_dump",
)

_NEEDS_CORRELATION = {"web_template", "exploit_check", "exploit_run", "auxiliary_scan"}


@dataclass(frozen=True)
class Capability:
    """Ajan eylem uzayindaki tek bir secenek."""

    name: str
    tool: str
    risk: Risk
    args: dict[str, Any]
    technique: str
    note: str
    available: bool

    @property
    def purpose(self) -> str:
        return PURPOSE.get(self.name, self.note or self.name)


def build_catalog(registry: Registry) -> dict[str, Capability]:
    """Curated playbook'lar + registry'den yetenek katalogu uret.

    Risk ve varsayilan argumanlar playbook adimlarindan okunur (modelin
    uydurmasina izin verilmez). Playbook'ta olmayan ama kayitli bir yetenek
    icin adaptor spec risk'i ve bos arguman kullanilir."""
    out: dict[str, Capability] = {}

    def owner(cap: str, preferred: str = "") -> Any:
        if preferred and preferred in registry.names():
            adapter = registry.get(preferred)
            if adapter.spec.supports(cap):  # type: ignore[attr-defined]
                return adapter
        providers = registry.by_capability(cap)
        if not providers:
            return None
        for a in providers:
            if a.available():  # type: ignore[attr-defined]
                return a
        return providers[0]

    for pb in mapping.all_playbooks():
        for step in pb.steps:
            adapter = owner(step.capability, step.tool)
            if adapter is None:
                continue
            spec = adapter.spec  # type: ignore[attr-defined]
            existing = out.get(step.capability)
            risk = step.risk if existing is None else max(existing.risk, step.risk)
            args = dict(existing.args) if existing else {}
            args.update({k: v for k, v in step.args.items() if v is not None})
            out[step.capability] = Capability(
                name=step.capability, tool=spec.name, risk=risk, args=args,
                technique=(existing.technique if existing else pb.technique),
                note=(existing.note if existing and existing.note else (step.note or pb.name)),
                available=adapter.available(),  # type: ignore[attr-defined]
            )

    for cap, tools in registry.capabilities().items():
        if cap in out:
            continue
        adapter = owner(cap)
        if adapter is None:
            continue
        spec = adapter.spec  # type: ignore[attr-defined]
        out[cap] = Capability(
            name=cap, tool=spec.name, risk=spec.risk, args={},
            technique="", note=spec.description, available=adapter.available(),  # type: ignore[attr-defined]
        )
    return out


@dataclass
class AgentState:
    objective: str
    target: str
    results: list[ActionResult] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    tried: set[str] = field(default_factory=set)
    steps: int = 0
    decisions: list[dict[str, Any]] = field(default_factory=list)
    _last_interim: int = -1


Event = dict[str, Any]
Reporter = Callable[[Event], None]


class AgentLoop:
    """Otonom saldiri dongusu. Kapsam + politika + denetim her adimda zorunlu."""

    def __init__(
        self,
        registry: Registry,
        scope: ScopeGuard,
        policy: Policy,
        audit: AuditLog,
        router: Router,
        *,
        reporter: Reporter | None = None,
        max_steps: int = 16,
        timeout: int = 300,
        dry_run: bool = False,
        summary_every: int = 4,
        smart_summary: bool = True,
    ):
        self.registry = registry
        self.scope = scope
        self.policy = policy
        self.audit = audit
        self.router = router
        self.reporter = reporter or (lambda e: None)
        self.max_steps = max_steps
        self.summary_every = max(1, summary_every)
        self.smart_summary = smart_summary
        self.catalog = build_catalog(registry)
        self.executor = Executor(
            scope=scope, policy=policy, audit=audit, registry=registry,
            approver=lambda action: True, dry_run=dry_run, timeout=timeout,
        )
        self.online = router.available()


    def run(self, objective: str, target: str) -> AgentState:
        state = AgentState(objective=objective, target=target)
        self.audit.append("agent.start", objective=objective, target=target,
                           online=self.online, max_steps=self.max_steps)
        while state.steps < self.max_steps:
            candidates = self._candidates(state)
            if not candidates:
                self._emit({"kind": "done", "reason": "denenecek uygun yetenek kalmadi"})
                break
            cap, thought, source, extra_args = self._decide(state, candidates)
            if cap is None:
                self._emit({"kind": "done", "reason": thought or "model durdu"})
                break
            self._emit({"kind": "think", "thought": thought, "source": source})
            state.steps += 1
            self._execute(state, cap, extra_args, thought=thought, source=source)
            if state.steps % self.summary_every == 0:
                self._interim(state)
        else:
            self._emit({"kind": "done", "reason": f"adim limiti ({self.max_steps}) doldu"})
        self.audit.append("agent.finish", steps=state.steps,
                          results=len(state.results),
                          cves=[c["cve"] for c in state.correlations[:10]])
        return state


    def _candidates(self, state: AgentState) -> list[Capability]:
        """Henuz denenmemis, kayitli ve risk/izin kurallarina uyan yetenekler.

        Korelasyon gerektiren yetenekler (exploit/web_template) ancak zafiyetli
        surum tespit edildiyse adaydir -> kor exploit yok."""
        max_risk = Risk.DESTRUCTIVE if self.policy.allow_destructive else (
            Risk.INTRUSIVE if self.policy.allow_intrusive else Risk.ACTIVE
        )
        have_corr = bool(state.correlations)
        out: list[Capability] = []
        for cap in self.catalog.values():
            if cap.name in state.tried:
                continue
            if cap.risk > max_risk:
                continue
            if cap.name in _NEEDS_CORRELATION and not have_corr:
                continue
            out.append(cap)
        order = {name: i for i, name in enumerate(PHASE_ORDER)}
        out.sort(key=lambda c: (order.get(c.name, 999), int(c.risk)))
        return out

    def _decide(
        self, state: AgentState, candidates: list[Capability]
    ) -> tuple[Capability | None, str, str, dict[str, Any]]:
        """Siradaki yetenegi sec. Once model, gecersizse deterministik yedek."""
        if self.online:
            chosen = self._decide_llm(state, candidates)
            if chosen is not None:
                cap, thought = chosen
                if cap is None:
                    return None, thought, "llm", {}
                return cap, thought, "llm", self._extra_args(state, cap)
        cap = candidates[0]
        thought = f"[kural] faz sirasinda sirada: {cap.name} — {cap.purpose}"
        return cap, thought, "rule", self._extra_args(state, cap)

    def _decide_llm(
        self, state: AgentState, candidates: list[Capability]
    ) -> tuple[Capability | None, str] | None:
        catalog = "\n".join(
            f"- {c.name} [{c.risk.label}]: {c.purpose}" for c in candidates
        )
        schema = {
            "type": "object",
            "properties": {
                "thought": {"type": "string"},
                "capability": {"type": "string"},
                "done": {"type": "boolean"},
            },
            "required": ["thought", "capability", "done"],
            "additionalProperties": False,
        }
        system = (
            "Sen bir yetkili sizma testi ajanisin. Elindeki YETENEK katalogundan "
            "SIRADAKI tek adimi seçersin. Kurallar: komut/arguman YAZMA, sadece "
            "katalogdan bir 'capability' adi sec. Once kesif ve tespit yap; "
            "zafiyetli surum/CVE gorulmeden agir istismar (exploit_run) secme. "
            "Hedefe ulasildiysa ya da denenecek anlamli adim kalmadiysa done=true. "
            "SADECE JSON dondur."
        )
        user = (
            f"Hedef: {state.target}\nAmac: {state.objective}\n\n"
            f"Simdiye kadarki bulgular:\n{self._observation_digest(state)}\n\n"
            f"Secebilecegin yetenekler:\n{catalog}\n\n"
            "Siradaki en mantikli yetenegi sec."
        )
        data = self.router.complete_json(system, user, schema, timeout=120)
        if not data:
            return None
        if data.get("done"):
            return None, str(data.get("thought") or "model hedefe ulasildi dedi")
        name = str(data.get("capability", "")).strip()
        by_name = {c.name: c for c in candidates}
        if name not in by_name:
            return None
        return by_name[name], str(data.get("thought") or by_name[name].purpose)

    def _extra_args(self, state: AgentState, cap: Capability) -> dict[str, Any]:
        """Korelasyondan turetilen dinamik argumanlar (modul/cve_id).

        msf icin modul, nuclei web_template icin cve_id korelasyonun en kritik
        satirindan baglanir -> istismar kor degil, kesfe dayali."""
        if not state.correlations:
            return {}
        if cap.name in ("exploit_check", "exploit_run", "auxiliary_scan"):
            for row in state.correlations:
                if row.get("msf_module"):
                    return {"module": row["msf_module"]}
        if cap.name == "web_template":
            ids = [r["cve"] for r in state.correlations[:5] if r.get("cve")]
            if ids:
                return {"cve_id": ",".join(ids)}
        return {}


    def _execute(
        self, state: AgentState, cap: Capability, extra: dict[str, Any],
        *, thought: str = "", source: str = "rule",
    ) -> None:
        state.tried.add(cap.name)
        args = dict(cap.args)
        args.update(extra)
        action = Action(
            tool=cap.tool, capability=cap.name, target=state.target, args=args,
            risk=cap.risk, technique=cap.technique,
            rationale=cap.purpose,
        )
        self._emit({"kind": "act", "action": action, "purpose": cap.purpose})
        plan = Plan(objective=state.objective, target=state.target, actions=[action])

        def record(status: str, findings: list[str], duration: float = 0.0) -> None:
            """Karar logu girdisi + denetim kaydi (her dalda cagrilir)."""
            entry = {
                "step": state.steps, "capability": cap.name, "tool": cap.tool,
                "risk": cap.risk.label, "technique": cap.technique,
                "source": source, "thought": thought, "status": status,
                "duration_s": round(duration, 2), "findings": findings,
            }
            state.decisions.append(entry)
            self.audit.append(
                "agent.decision", step=state.steps, capability=cap.name,
                tool=cap.tool, source=source, status=status, technique=cap.technique,
            )

        try:
            results = self.executor.run(plan)
        except ScopeViolation as exc:
            record("scope-ihlali", [f"KAPSAM: {exc}"])
            self._emit({"kind": "note", "text": f"KAPSAM IHLALI, adim atlandi: {exc}"})
            return
        except PolicyDenied as exc:
            record("denied", [f"POLITIKA: {exc}"])
            self._emit({"kind": "note", "text": f"POLITIKA REDDI: {exc}"})
            return
        except Exception as exc:  # noqa: BLE001
            self.audit.append("agent.step_error", action=action.key(), error=str(exc))
            failed = ActionResult(action=action, status="error",
                                  detail=f"adaptör hatası: {exc}")
            state.results.append(failed)
            record("error", [f"NEDEN: adaptör hatası: {exc}"])
            self._emit({"kind": "result", "action": action, "result": failed,
                        "findings": [f"NEDEN: adaptör hatası: {exc}"]})
            return
        if not results:
            record("bos", [])
            return
        result = results[0]
        state.results.append(result)
        findings = _findings(result)
        record(result.status, findings, result.duration_s)
        self._emit({"kind": "result", "action": action, "result": result,
                    "findings": findings})
        self._recorrelate(state)

    def _recorrelate(self, state: AgentState) -> None:
        """Her adimdan sonra surum->CVE korelasyonunu tazele; yeni zafiyetli
        surum cikarsa raporla. Bu, 'zafiyetli surum varsa tespit et' isteginin
        ta kendisi ve exploit pivotunu tetikleyen sinyal."""
        if self.executor.dry_run:
            return
        try:
            rows = _correlate.correlate(state.results)
        except Exception:  # noqa: BLE001 - CVE deposu bos/erisilemezse atla
            return
        known = {r["cve"] for r in state.correlations}
        fresh = [r for r in rows if r["cve"] not in known]
        state.correlations = rows
        if fresh:
            self._emit({"kind": "vuln", "rows": fresh})
            self._interim(state)

    def _interim(self, state: AgentState) -> None:
        """Ara ozet: o ana kadar ne bulundu, sirada ne var.

        `smart_summary` ve model cevrimiciyse modelden bulgu-odakli TURKCE ozet
        ister; model yoksa/bos donerse deterministik ozet (`_interim_text`) kullanir
        -> ozet katmani dongu'yu asla dusurmez. Ayni adimda iki kez tetiklenmez."""
        if state._last_interim == state.steps or not state.results:
            return
        state._last_interim = state.steps
        text = self._interim_text(state)
        source = "kural"
        if self.smart_summary and self.online:
            digest = (f"Amac: {state.objective}\nHedef: {state.target}\n"
                      f"Simdiye kadarki bulgular:\n{self._observation_digest(state)}")
            model_text = self.router.summarize(digest, timeout=120)
            if model_text:
                text, source = model_text, "model"
        self._emit({"kind": "interim", "text": text, "step": state.steps,
                    "source": source})

    def _interim_text(self, state: AgentState) -> str:
        ports: list[Any] = []
        techs: list[str] = []
        waf: str | None = None
        sev: dict[str, int] = {}
        for r in state.results:
            p = r.parsed or {}
            for x in p.get("open_ports", []) or []:
                if x not in ports:
                    ports.append(x)
            t = p.get("technologies")
            if t:
                for name in (t if isinstance(t, (list, tuple)) else list(t)):
                    if str(name) not in techs:
                        techs.append(str(name))
            if "protected" in p:
                det = p.get("detected") or []
                waf = ", ".join(det) if det else "yok"
            for f in p.get("findings", []) or []:
                s = str(f.get("severity", "info")).lower()
                sev[s] = sev.get(s, 0) + 1
        parts: list[str] = []
        if ports:
            parts.append("açık port: " + ", ".join(str(x) for x in ports[:12]))
        if techs:
            parts.append("teknoloji: " + ", ".join(techs[:8]))
        if waf is not None:
            parts.append(f"WAF: {waf}")
        if sev:
            order = ("critical", "high", "medium", "low", "info")
            parts.append("bulgular: " + ", ".join(
                f"{sev[k]} {k}" for k in order if sev.get(k)))
        if state.correlations:
            parts.append(f"zafiyetli sürüm/CVE: {len(state.correlations)} "
                         f"(en kritik {state.correlations[0]['cve']})")
        nxt = self._candidates(state)
        sira = f"sırada: {nxt[0].name}" if nxt else "sırada: adım kalmadı"
        gov = "; ".join(parts) if parts else "henüz somut bulgu yok"
        return f"{gov}  ·  {sira}"


    def _observation_digest(self, state: AgentState) -> str:
        if not state.results:
            return "(henuz bulgu yok)"
        lines: list[str] = []
        for r in state.results:
            tag = f"{r.action.tool}.{r.action.capability}={r.status}"
            fnd = _findings(r)
            lines.append("- " + tag + (f": {'; '.join(fnd[:3])}" if fnd else ""))
        if state.correlations:
            cves = ", ".join(
                f"{c['cve']}({c.get('product') or '?'} skor {c['score']}"
                + (f" msf:{c['msf_module']}" if c.get('msf_module') else "") + ")"
                for c in state.correlations[:6]
            )
            lines.append(f"- zafiyetli surum/CVE: {cves}")
        return "\n".join(lines)

    def _emit(self, event: Event) -> None:
        try:
            self.reporter(event)
        except Exception:  # noqa: BLE001 - raporlayici asla dongu dusurmez
            pass


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": 0}


def _findings(result: ActionResult) -> list[str]:
    """Bir sonuctan insana okunur kisa bulgu satirlari cikar (rapor icin)."""
    p = result.parsed or {}
    out: list[str] = []
    if result.status in ("unavailable", "error", "denied") and result.detail:
        out.append(f"NEDEN: {result.detail}")
    if p.get("open_ports"):
        out.append("acik port: " + ", ".join(str(x) for x in p["open_ports"][:15]))
    techs = p.get("technologies")
    if techs:
        names = list(techs)
        if names:
            out.append("teknoloji: " + ", ".join(map(str, names[:8])))
    if "protected" in p:
        det = p.get("detected") or []
        out.append("WAF: " + (", ".join(det) if det else "YOK"))
    if p.get("known_vulns"):
        out.append("bilinen CVE: " + ", ".join(p["known_vulns"][:8]))
    if p.get("vulnerable"):
        params = p.get("parameters") or []
        out.append("GECILEBILIR: zafiyet DOGRULANDI"
                   + (f" (parametre: {', '.join(map(str, params[:5]))})" if params else ""))
    if p.get("session_count"):
        out.append(f"ERISIM SAGLANDI: {p['session_count']} oturum")
    if p.get("dumped"):
        out.append("VERI CEKILDI: loot kaydedildi")
    findings = sorted(
        p.get("findings") or [],
        key=lambda f: _SEV_RANK.get(str(f.get("severity", "")).lower(), 0),
        reverse=True,
    )
    for f in findings[:5]:
        sev = str(f.get("severity", "info")).lower()
        label = f.get("detail") or f.get("name") or f.get("check") or "bulgu"
        cve = f.get("cve")
        out.append(f"[{sev}] {label}" + (f" ({cve})" if cve else ""))
    return out
