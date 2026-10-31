"""Kalkan komut satırı arayüzü."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__, correlate, ui
from .adapters import load_default_registry
from .adapters._common import host_of
from .audit import AuditLog
from .knowledge import atlas, bridge, mapping
from .knowledge.attack import AttackKnowledge
from .models import Action, Intent, Plan, Risk
from .orchestrator import (
    DEFAULT_ENDPOINT,
    DEFAULT_MODEL,
    Executor,
    Router,
    plan_for_intent,
)
from .policy import Policy, PolicyDenied
from .scope import Scope, ScopeGuard, ScopeViolation

DEFAULT_AUDIT = ".kalkan/audit.jsonl"


def _scope_guard(args) -> ScopeGuard:
    path = Path(args.scope)
    if not path.exists():
        raise SystemExit(
            f"kapsam dosyası yok: {path}\n"
            f"  örnek: examples/scope.json dosyasını kopyalayıp doldur"
        )
    return ScopeGuard(Scope.load(path))


def _approver(args):
    if args.yes:
        return lambda action: True

    def ask(action: Action) -> bool:
        print()
        print(f"  ! onay gerekiyor: {action.describe()}")
        if action.rationale:
            print(f"    gerekçe: {action.rationale}")
        if action.technique:
            print(f"    teknik : {action.technique}")
        if action.args:
            print(f"    argüman: {json.dumps(action.args, ensure_ascii=False)}")
        try:
            answer = input("  onaylıyor musun? [y/N] ")
        except EOFError:
            return False
        return answer.strip().lower() in ("y", "yes", "e", "evet")

    return ask


def _print_plan(p: Plan, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "objective": p.objective,
                    "target": p.target,
                    "actions": [
                        {
                            "tool": a.tool,
                            "capability": a.capability,
                            "target": a.target,
                            "risk": a.risk.label,
                            "technique": a.technique,
                            "args": a.args,
                        }
                        for a in p.actions
                    ],
                    "notes": p.notes,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    print(f"\n{ui.grey('hedef')}     : {ui.bold(p.target)}")
    print(f"{ui.grey('amaç')}      : {p.objective}")
    print(f"{ui.grey('aksiyon')}   : {len(p.actions)}  "
          f"({ui.grey('tavan risk:')} {ui.risk(p.max_risk().label)})")
    for i, a in enumerate(p.actions, 1):
        lbl = a.risk.label
        pad = " " * max(0, 9 - len(lbl))
        name = f"{a.tool}.{a.capability}"
        npad = " " * max(0, 20 - len(name))
        print(f"  {ui.dim(f'{i:2}.')} [{ui.risk(lbl)}]{pad} {ui.bold(name)}{npad} {ui.cyan(a.technique)}")
        if a.rationale:
            print(ui.dim(f"       - {a.rationale}"))
        if a.args:
            print(ui.dim(f"       - {json.dumps(a.args, ensure_ascii=False)}"))
    for note in p.notes:
        print(f"  {ui.grey('not:')} {ui.grey(note)}")


def _print_correlation(rows: list) -> None:
    """Sürüm→CVE korelasyon bulgularını ve 'sonraki adım' ipuçlarını bas."""
    if not rows:
        return
    print(f"\n  {ui.bold('Sürüm→CVE korelasyonu')} ({len(rows)} CVE):")
    for c in rows[:8]:
        kev = ui.red(" KEV") if c["kev"] else ""
        mod = ui.cyan(f"  → {c['msf_module']}") if c["msf_module"] else ""
        pv = f"{c.get('product', '')} {c.get('version', '')}".strip()
        print(f"    {ui.bold(c['cve'])}  {ui.risk('intrusive') if c['score'] >= 7 else c['tier']} "
              f"{c['score']}{kev}  {ui.dim(pv)}{mod}")
    for tip in correlate.next_steps(rows):
        print(ui.dim(f"    → {tip}"))


def _progress_event(evt: str, idx: int, total: int, action: Action, result) -> None:
    """Executor canli ilerleme olayini renkli satira cevirir (CLI geri cagrisi)."""
    tag = ui.dim(f"[{idx}/{total}]")
    name = f"{action.tool}.{action.capability}"
    if evt == "start":
        print(f"  {tag} {ui.cyan(ui.SYM['run'])} {ui.bold(name)}  {ui.risk(action.risk.label)}")
        return
    sym = ui.status_symbol(result.status)
    extra = f"  {ui.dim(result.detail)}" if (result.detail and result.status != "dry-run") else ""
    print(f"       {sym} {ui.status(result.status)}{extra}")
    if result.status == "dry-run" and result.detail:
        print(ui.dim(f"       {result.detail}"))
    if result.parsed:
        prev = json.dumps(result.parsed, ensure_ascii=False)
        print(ui.dim(f"       {prev[:300]}{'...' if len(prev) > 300 else ''}"))


def _augment_from_feed(args, intent: Intent) -> Intent:
    """--from-feed verildiyse canli CVE onerilerinden playbook'u olan
    teknikleri niyete ekle. Oneriler yalnizca TEKNIK ekler; her sey yine
    Scope/Policy/Audit kapisindan gecer. Besleme bos/erisilemezse niyet
    degismeden doner."""
    if not getattr(args, "from_feed", False):
        return intent
    try:
        from .feeds import suggest
        min_score = getattr(args, "feed_min_score", None) or 40.0
        sugg = suggest.suggest_for_text(
            args.text or intent.objective, targets=intent.targets, min_score=min_score
        )
    except Exception as exc:  # noqa: BLE001 - besleme yoklugu plani bozmasin
        return Intent(
            objective=intent.objective, targets=intent.targets,
            techniques=intent.techniques, rationale=intent.rationale,
            source=intent.source, notes=(*intent.notes, f"besleme atlandi: {exc}"),
        )
    if not sugg:
        return Intent(
            objective=intent.objective, targets=intent.targets,
            techniques=intent.techniques, rationale=intent.rationale,
            source=intent.source, notes=(*intent.notes, "besleme: eslesen CVE onerisi yok"),
        )
    extra = [t for t in suggest.techniques_from_suggestions(sugg) if t not in intent.techniques]
    cve_notes = [f"besleme: {s.cve} ({s.tier}{', KEV' if s.kev else ''}) -> {', '.join(s.techniques) or '-'}"
                 for s in sugg]
    nuclei_techs = {pb.technique for pb in mapping.all_playbooks()
                    for s in pb.steps if s.tool == "nuclei"}
    cve_ids = [s.cve for s in sugg if set(s.techniques) & nuclei_techs]
    if cve_ids:
        setattr(args, "feed_cve_id", ",".join(dict.fromkeys(cve_ids)))
        cve_notes.append(f"besleme: nuclei -id -> {', '.join(dict.fromkeys(cve_ids))}")

    msf = suggest.msf_candidates(sugg)
    if msf:
        if not getattr(args, "module", None):
            setattr(args, "feed_module", msf[0].msf_module)
        allc = ", ".join(f"{s.cve}->{s.msf_module}" for s in msf)
        cve_notes.append(f"besleme: MSF modul adaylari (check) -> {allc}")
        cve_notes.append(f"besleme: kullan: --arg mode=run yalnizca --allow-destructive ile")

    sqli = suggest.sqli_candidates(sugg)
    if sqli:
        ids = ", ".join(s.cve for s in sqli)
        cve_notes.append(f"besleme: SQLi sinifi CVE ({ids}); sqlmap icin --arg verify=1 ekle")

    return Intent(
        objective=intent.objective,
        targets=intent.targets,
        techniques=(*intent.techniques, *extra),
        rationale=intent.rationale,
        source=intent.source,
        notes=(*intent.notes, *cve_notes),
    )


def _intent_from_args(args) -> Intent:
    if args.technique:
        targets = tuple(t for t in ([args.target] if args.target else []))
        intent = Intent(
            objective=args.text or "",
            targets=targets,
            techniques=tuple(args.technique),
            rationale="kullanıcı doğrudan belirtti",
            source="explicit",
        )
        return _augment_from_feed(args, intent)
    if not args.text and not getattr(args, "from_feed", False):
        raise SystemExit("metin veya --technique gerekli")
    router = Router(endpoint=args.endpoint, model=args.model)
    intent = router.route(args.text or "")
    if args.target:
        notes = tuple(n for n in intent.notes if "hedef çıkarılamadı" not in n)
        intent = Intent(
            objective=intent.objective,
            targets=(args.target,),
            techniques=intent.techniques,
            rationale=intent.rationale,
            source=intent.source,
            notes=notes,
        )
    return _augment_from_feed(args, intent)


def _build_plans(args, intent: Intent) -> list[Plan]:
    """Niyetten (hedef başına bir) deterministik plan üret.

    Risk tavanı --max-risk ile; belirtilmezse INTRUSIVE. Model/modül/payload
    gibi değerler adım argümanlarına override olarak geçirilir.
    """
    registry = load_default_registry()
    max_risk = Risk.parse(args.max_risk) if getattr(args, "max_risk", None) else Risk.INTRUSIVE

    overrides: dict[str, Any] = {}
    feed_cve = getattr(args, "feed_cve_id", None)
    if feed_cve:
        overrides["cve_id"] = feed_cve
    feed_module = getattr(args, "feed_module", None)
    if feed_module:
        overrides["module"] = feed_module
    for key in ("module", "payload", "mode", "endpoint", "model"):
        value = getattr(args, key, None)
        if value:
            overrides[key] = value
    for raw in getattr(args, "arg", None) or []:
        if "=" not in raw:
            raise SystemExit(f"gecersiz --arg (key=value bekleniyor): {raw!r}")
        key, value = raw.split("=", 1)
        overrides[key.strip()] = value.strip()

    return plan_for_intent(intent, registry, max_risk, overrides)


def _resolve_msf_module(ident: str) -> tuple[str, str] | None:
    """Bir tanimi MSF moduluNE cozumle.

    - 'CVE-....'  -> kurasyonlu tablo, yoksa kurulu msf katalog indeksi
    - 'exploit/...' / 'auxiliary/...' (icinde '/') -> dogrudan modul yolu
    - digeri -> None (cozumlenemedi)
    Doner: (modul_yolu, kisa_not) ya da None.
    """
    s = (ident or "").strip()
    if not s:
        return None
    if s.upper().startswith("CVE-"):
        return bridge.msf_module(s)
    if "/" in s:
        return (s, "doğrudan modül")
    return None


def _exploit_plan(
    target: str,
    module: str,
    note: str = "",
    mode: str = "check",
    options: dict[str, Any] | None = None,
) -> Plan:
    """CVE/modul icin msf-odakli plan uret: exploit_check (+ mode=run ise
    exploit_run). Tum kapilar (scope/policy/onay) Executor'da uygulanir;
    bu fonksiyon yalnizca aksiyonlari olusturur. msf RHOSTS host ister,
    bu yuzden URL verilirse host'a indirilir."""
    options = dict(options or {})
    rhost = host_of(target)
    base_args: dict[str, Any] = {"module": module, **options}
    rationale = f"CVE→MSF doğrulama: {note}" if note else "MSF modül doğrulama (check)"
    actions = [
        Action(tool="msf", capability="exploit_check", target=rhost,
               args=dict(base_args), risk=Risk.INTRUSIVE, technique="T1190",
               rationale=rationale),
    ]
    if mode == "run":
        run_args = dict(base_args)
        run_args["mode"] = "run"
        actions.append(
            Action(tool="msf", capability="exploit_run", target=rhost,
                   args=run_args, risk=Risk.DESTRUCTIVE, technique="T1190",
                   rationale="GERÇEK exploit: başarırsa oturum açar"),
        )
    return Plan(objective=f"exploit {module}", target=rhost, actions=actions)


def cmd_scope(args) -> int:
    if args.action == "add":
        if not args.target:
            print("kullanım: kalkan scope add <hedef>", file=sys.stderr)
            return 2
        from .scope import add_to_scope_file
        try:
            info = add_to_scope_file(args.scope, args.target)
        except ScopeViolation as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if info["changed"]:
            print(f"eklendi ({info['kind']}): {info['host']}  → {args.scope}")
        else:
            print(f"zaten kapsamda ({info['kind']}): {info['host']}")
        if info["port_added"]:
            print(f"  port eklendi: {info['port']}")
        print("  ! bunu eklemek, bu hedefi test etmeye YETKİLİ olduğun beyanıdır.")
        return 0

    guard = _scope_guard(args)
    if args.action == "check":
        try:
            target = guard.check(args.target, risk=Risk.parse(args.risk))
        except ScopeViolation as exc:
            print(f"REDDEDİLDİ: {exc}")
            return 2
        print(f"İZIN VERİLDİ: {target}")
        return 0
    print(guard.describe())
    return 0


def cmd_tools(args) -> int:
    registry = load_default_registry()
    rows = []
    for adapter in registry.all():
        rows.append(
            {
                "tool": adapter.spec.name,
                "capabilities": list(adapter.spec.capabilities),
                "risk": adapter.spec.risk.label,
                "available": adapter.available(),
                "reason": adapter.unavailable_reason(),
                "description": adapter.spec.description,
            }
        )
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    print(ui.grey(f"{'ARAÇ':<10} {'DURUM':<8} {'RİSK':<9} YETENEKLER"))
    for row in rows:
        ok = row["available"]
        st = "hazır" if ok else "eksik"
        st_c = (ui.green if ok else ui.grey)(st) + " " * max(0, 8 - len(st))
        rlbl = row["risk"]
        r_c = ui.risk(rlbl) + " " * max(0, 9 - len(rlbl))
        tool = row["tool"]
        print(f"{ui.bold(tool)}{' ' * max(0, 10 - len(tool))} {st_c} {r_c} {', '.join(row['capabilities'])}")
        if row["reason"]:
            print(ui.grey(f"{'':<10} - {row['reason']}"))
    return 0


def cmd_coverage(args) -> int:
    registry = load_default_registry()
    rows = mapping.coverage(registry)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    print(ui.grey(f"{'TEKNİK':<12} {'FRAMEWORK':<10} {'TAKTİK':<18} {'ADIM':<5} DURUM"))
    for row in rows:
        st = ui.green("hazır") if row["ready"] else ui.grey("eksik")
        print(
            f"{row['technique']:<12} {row['framework']:<10} {row['tactic']:<18} "
            f"{row['steps']:<5} {st}"
        )
        for missing in row["missing"]:
            print(ui.grey(f"{'':<12} - {missing}"))
    auto = atlas.automated()
    manual = atlas.manual()
    print(f"\nATLAS: {len(auto)} teknik otomatik test edilebilir, {len(manual)} manuel.")
    for tech in manual:
        print(f"  - {tech.id} {tech.name} (manuel): {tech.test_approach}")
    return 0


def cmd_navigator(args) -> int:
    """ATT&CK Navigator layer üret: Kalkan otomasyon kapsamını matris üzerine boya.

    attack-navigator'dan destekle tüm ATT&CK tekniklerini (veri seti indirilmişse)
    layer'a koyar; kapsananlar risk rengiyle, kalanlar gri işaretlenir."""
    from .knowledge import navigator
    layer, stats = navigator.build_layer(
        domain=getattr(args, "domain", "enterprise"),
        include_all=not getattr(args, "covered_only", False),
        name=getattr(args, "name", "Kalkan Coverage"),
        cache_dir=getattr(args, "cache_root", None),
    )
    out = Path(getattr(args, "out", "kalkan-coverage.json"))
    out.write_text(json.dumps(layer, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Navigator layer yazıldı: {ui.bold(str(out))}")
    print(f"  kapsanan ATT&CK tekniği : {stats['covered']} (çalıştırılabilir playbook)")
    if stats.get("all"):
        print(f"  matris toplam tekniği   : {stats['all']} (kapsanmayanlar gri)")
    else:
        print(f"  {ui.grey('tüm matrisi boyamak için: kalkan knowledge fetch → sonra tekrar çalıştır')}")
    print(f"  yükle: https://mitre-attack.github.io/attack-navigator/  →  "
          f"Open Existing Layer → Upload from local")
    return 0


def _print_entity(info: dict) -> int:
    """Grup / yazilim / kampanya / veri kaynagi kaydini tum detayiyla bas."""
    kind = info.get("kind")
    label = {"group": "GRUP", "software": "YAZILIM", "campaign": "KAMPANYA",
             "data_source": "VERİ KAYNAĞI"}.get(kind, str(kind))
    print(f"{info['id']}  {info['name']}  [{label}]")
    if info.get("aliases"):
        print(f"takma adlar : {', '.join(info['aliases'])}")
    if info.get("software_type"):
        print(f"tür         : {info['software_type']}")
    if info.get("platforms"):
        print(f"platformlar : {', '.join(info['platforms'])}")
    if info.get("first_seen") or info.get("last_seen"):
        print(f"görülme     : {info.get('first_seen', '?')} → {info.get('last_seen', '?')}")
    print(f"url         : {info.get('url', '')}")
    if info.get("description"):
        print(f"\naçıklama (ne/nasıl):\n{info['description'][:1600].strip()}")
    techs = info.get("techniques") or []
    if techs:
        print(f"\nkullandığı teknikler ({len(techs)}): {', '.join(techs[:40])}"
              + (" ..." if len(techs) > 40 else ""))
    soft = info.get("software") or []
    if soft:
        print(f"kullandığı yazılım ({len(soft)}): {', '.join(soft[:30])}")
    groups = info.get("groups") or []
    if groups:
        print(f"ilişkili gruplar ({len(groups)}): {', '.join(groups[:30])}")
    comps = info.get("components") or []
    if comps:
        print(f"veri bileşenleri ({len(comps)}): {', '.join(comps)}")
    return 0


def cmd_knowledge(args) -> int:
    query = args.search_query if args.search_query else args.query

    if args.action == "atlas":
        for tech in atlas.ATLAS.values():
            mode = "manuel" if tech.manual else "otomatik"
            print(f"{tech.id:<10} {tech.tactic:<16} {mode:<9} {tech.name}")
        return 0

    cache_root = getattr(args, "cache_root", None)
    domain = getattr(args, "domain", "enterprise")

    if domain == "atlas":
        return _knowledge_atlas(args, query, cache_root)

    knowledge = AttackKnowledge(domain=domain, cache_dir=cache_root)

    def _print_stats(st: dict) -> None:
        print(f"içerik    : {st['techniques']} teknik (+{st['sub_techniques']} alt teknik), "
              f"{st['tactics']} taktik, {st['mitigations']} mitigasyon, "
              f"{st['procedures']} prosedür örneği")
        print(f"            {st['groups']} grup (G), {st['software']} yazılım (S), "
              f"{st['campaigns']} kampanya (C), {st['data_sources']} veri kaynağı (DS)")

    if args.action == "fetch":
        path = knowledge.fetch(force=args.force)
        print(f"indirildi: {path} ({path.stat().st_size / 1e6:.1f} MB)")
        _print_stats(knowledge.statistics())
        return 0

    if args.action == "stats":
        _print_stats(knowledge.statistics())
        return 0

    if args.action in ("groups", "software", "campaigns", "datasources"):
        rows = {
            "groups": knowledge.groups, "software": knowledge.software_catalog,
            "campaigns": knowledge.campaigns, "datasources": knowledge.data_sources,
        }[args.action]()
        if query:
            q = query.lower()
            rows = [r for r in rows
                    if q in r["name"].lower()
                    or any(q in a.lower() for a in r.get("aliases", []))]
        for r in rows:
            extra = ""
            if r.get("kind") in ("group", "software", "campaign"):
                extra = f"  [{len(r.get('techniques', []))} teknik]"
            alias = f"  ({', '.join(r['aliases'][:3])})" if r.get("aliases") else ""
            print(f"{r['id']:<8} {r['name']}{alias}{extra}")
        print(f"\ntoplam: {len(rows)}  —  detay için: knowledge show --technique <ID>")
        return 0

    if args.action == "search":
        if not query:
            print("sorgu bos: knowledge search \"kelime\"", file=sys.stderr)
            return 2
        hits = knowledge.search_all(query)
        if not hits:
            print("sonuc yok", file=sys.stderr)
        for info in hits:
            kind = info.get("kind", "technique")
            tag = {"technique": "T", "group": "GRUP", "software": "YZLM",
                   "campaign": "KMPY"}.get(kind, kind)
            ctx = (", ".join(info.get("tactics", [])) if kind == "technique"
                   else ", ".join(info.get("aliases", [])[:3]))
            print(f"[{tag:<4}] {info['id']:<10} {info['name']}" + (f"  ({ctx})" if ctx else ""))
        return 0

    info = knowledge.lookup(args.technique or query)
    if info and info.get("kind") in ("group", "software", "campaign", "data_source"):
        return _print_entity(info)
    if not info:
        print(f"teknik bulunamadı: {args.technique}", file=sys.stderr)
        return 2

    print(f"{info['id']}  {info['name']}" + ("  [alt-teknik]" if info.get("is_subtechnique") else ""))
    print(f"taktikler : {', '.join(info['tactics'])}")
    print(f"platformlar: {', '.join(info['platforms'])}")
    if info.get("parent"):
        print(f"üst teknik: {info['parent']}")
    if info.get("sub_techniques"):
        print(f"alt teknikler: {', '.join(info['sub_techniques'])}")
    if info.get("data_sources"):
        print(f"veri kaynakları: {', '.join(info['data_sources'][:12])}")
    if info.get("permissions"):
        print(f"gerekli izin: {', '.join(info['permissions'])}")
    if info.get("defenses_bypassed"):
        print(f"aşılan savunma: {', '.join(info['defenses_bypassed'][:10])}")
    print(f"url       : {info['url']}")
    if info["description"]:
        print(f"\nnasıl yapılır (açıklama):\n{info['description'][:1600].strip()}")
    if info["detection"]:
        print(f"\ntespit    :\n{info['detection'][:900].strip()}")
    mitig = info.get("mitigations") or []
    if mitig:
        print(f"\nmitigasyonlar ({len(mitig)}):")
        for m in mitig[:12]:
            print(f"  - {m['id']:<8} {m['name']}")
    procs = info.get("procedures") or []
    if procs:
        print(f"\nprosedür örnekleri — gerçekte nasıl kullanılmış ({len(procs)}):")
        for p in procs[:8]:
            desc = (p.get("description") or "").replace("\n", " ")[:160]
            print(f"  - [{p['type']}] {p['source']}: {desc}")
        if len(procs) > 8:
            print(f"  (+{len(procs) - 8} örnek daha)")
    playbook = mapping.get(info["id"])
    if playbook:
        print(f"\nplaybook  : {playbook.name} ({len(playbook.steps)} adım) — Kalkan otomatik çalıştırır")
        for step in playbook.steps:
            print(f"  - {step.tool}.{step.capability} [{step.risk.label}]")
    else:
        print("\nplaybook  : yok (yalnızca bilgi/referans; otomasyon yok)")
    return 0


def _knowledge_atlas(args, query: str, cache_root: str | None) -> int:
    knowledge = atlas.AtlasKnowledge(cache_dir=cache_root)

    if args.action == "fetch":
        path = knowledge.fetch(force=args.force)
        stats = knowledge.statistics()
        print(f"indirildi: {path} ({path.stat().st_size / 1e6:.1f} MB)")
        print(
            f"içerik    : {stats['tactics']} taktik, {stats['techniques']} teknik "
            f"(+{stats['sub_techniques']} alt teknik), "
            f"{stats['mitigations']} mitigation, {stats['case_studies']} case study"
        )
        return 0

    if args.action == "search":
        if not query:
            print('sorgu bos: knowledge search --domain atlas "kelime"', file=sys.stderr)
            return 2
        hits = knowledge.search(query)
        if not hits:
            print("sonuc yok", file=sys.stderr)
        for info in hits:
            tactics = ", ".join(info["tactics"]) or "-"
            seed = " [test-edilebilir]" if info["in_seed"] else ""
            print(f"{info['id']:<12} {info['name']}{seed}  ({tactics})")
        return 0

    info = knowledge.technique(args.technique)
    if not info:
        print(f"teknik bulunamadı: {args.technique}", file=sys.stderr)
        return 2
    print(f"{info['id']}  {info['name']}")
    print(f"taktikler : {', '.join(info['tactics'])}")
    print(f"platformlar: {', '.join(info['platforms'])}")
    print(f"url       : {info['url']}")
    if info["description"]:
        print(f"\naçıklama  : {info['description'][:1200].strip()}")
    if info["mitigations"]:
        print(f"\nmitigasyonlar ({len(info['mitigations'])}):")
        for m in info["mitigations"]:
            label = m["name"][:78]
            print(f"  - {m['id']:<12} {label}  ({m['url']})")
    if info["cases"]:
        print(f"\ncase study'ler ({len(info['cases'])}):")
        for c_name in info["cases"]:
            print(f"  - {c_name[:96]}")
    if info["in_seed"]:
        tech = atlas.get(info["id"])
        if tech:
            mode = "manuel test" if tech.manual else "otomatik test"
            print(f"\nkalkan testi ({mode}):")
            if tech.capabilities:
                print(f"  - yetenekler : {', '.join(tech.capabilities)}"
                      " (llmprobe adaptörü)")
            if tech.test_approach:
                print(f"  - yaklaşım   : {tech.test_approach}")
    return 0


def cmd_router(args) -> int:
    router = Router(endpoint=args.endpoint, model=args.model)
    intent = router.route(args.text)
    out: dict[str, Any] = {
        "objective": intent.objective,
        "targets": list(intent.targets),
        "techniques": list(intent.techniques),
        "rationale": intent.rationale,
        "source": intent.source,
        "notes": list(intent.notes),
    }
    if not getattr(args, "no_suggest", False):
        try:
            from .feeds import suggest
            sugg = suggest.suggest_for_text(args.text, targets=intent.targets)
            if sugg:
                out["live_suggestions"] = [s.to_dict() for s in sugg]
                extra = suggest.techniques_from_suggestions(sugg)
                out["suggested_techniques"] = [t for t in extra if t not in intent.techniques]
        except Exception as exc:  # noqa: BLE001 - oneri yoklugu router'i bozmasin
            out.setdefault("notes", []).append(f"oneri katmani atlandi: {exc}")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_plan(args) -> int:
    intent = _intent_from_args(args)
    plans = _build_plans(args, intent)
    for plan in plans:
        _print_plan(plan, args.json)
    return 0


def cmd_run(args) -> int:
    intent = _intent_from_args(args)
    plans = _build_plans(args, intent)
    guard = _scope_guard(args)
    policy = Policy(
        allow_intrusive=args.allow_intrusive,
        allow_destructive=args.allow_destructive,
    )
    audit = AuditLog(args.audit)
    registry = load_default_registry()

    exit_code = 0
    for plan in plans:
        _print_plan(plan, False)
        if not plan.actions:
            continue
        executor = Executor(
            scope=guard,
            policy=policy,
            audit=audit,
            registry=registry,
            approver=_approver(args),
            dry_run=args.dry_run,
            timeout=args.timeout,
        )
        print()
        try:
            results = executor.run(plan, on_event=_progress_event)
        except ScopeViolation as exc:
            print(f"\n{ui.red('KAPSAM İHLALİ')} - plan durduruldu: {exc}", file=sys.stderr)
            return 2
        except PolicyDenied as exc:
            print(f"\n{ui.red('POLİTİKA REDDİ')} - plan durduruldu: {exc}", file=sys.stderr)
            return 2
        print(f"\n  {ui.grey('denetim kaydı:')} {args.audit}")
        kor = correlate.correlate(results) if not args.dry_run else []
        _print_correlation(kor)
        if not getattr(args, "no_report", False) and not args.dry_run:
            from . import report
            try:
                rp = report.write_report(plan, results, scope=args.scope, correlation=kor)
                print(f"  rapor: {rp}")
            except Exception as exc:  # noqa: BLE001 - rapor hatası taramayı bozmasın
                print(f"  rapor yazılamadı: {exc}", file=sys.stderr)

    return exit_code


def cmd_exploit(args) -> int:
    """CVE/modülü hedefe karşı doğrula (check) veya exploit et (run) — tek komut.

    Tespitle kalmayan akışın komut satırı karşılığı: scope + policy + onay
    kapılarından geçer; mode=run için --allow-destructive ve scope tavanı
    destructive olmalıdır."""
    resolved = _resolve_msf_module(args.ident)
    if not resolved:
        print(f"'{args.ident}' için MSF modülü çözümlenemedi "
              f"(CVE kurasyonlu tablo/katalog eşleşmedi; doğrudan modül için tam yol verin)",
              file=sys.stderr)
        return 2
    module, note = resolved
    opts: dict[str, Any] = {}
    for key in ("payload", "lhost", "lport", "rport", "post"):
        val = getattr(args, key, None)
        if val:
            opts[key] = val
    plan = _exploit_plan(args.target, module, note=note, mode=args.mode, options=opts)

    guard = _scope_guard(args)
    policy = Policy(allow_intrusive=True, allow_destructive=args.allow_destructive)
    audit = AuditLog(args.audit)
    registry = load_default_registry()
    executor = Executor(
        scope=guard, policy=policy, audit=audit, registry=registry,
        approver=_approver(args), dry_run=args.dry_run, timeout=args.timeout,
    )
    _print_plan(plan, False)
    print(f"\n  modül: {ui.cyan(module)} ({note})  mod={ui.risk('destructive' if args.mode == 'run' else 'intrusive')}")
    print()
    try:
        results = executor.run(plan, on_event=_progress_event)
    except ScopeViolation as exc:
        print(f"\n{ui.red('KAPSAM İHLALİ')}: {exc}", file=sys.stderr)
        return 2
    except PolicyDenied as exc:
        print(f"\n{ui.red('POLİTİKA REDDİ')}: {exc}", file=sys.stderr)
        return 2
    print(f"\n  {ui.grey('denetim kaydı:')} {args.audit}")
    bad = [r for r in results if r.status in ("error", "denied", "aborted", "unavailable")]
    return 1 if bad else 0


def _chat_shim(base: dict[str, Any], text: str):
    """chat turu icin _augment_from_feed/_build_plans'in bekledigi args shim'i."""
    import types
    ns = types.SimpleNamespace(
        text=text,
        from_feed=base["from_feed"],
        feed_min_score=base["feed_min_score"],
        max_risk=base["max_risk"],
        module=base.get("module"),
        payload=None, mode=None,
        endpoint=base["endpoint"], model=base["model"],
        arg=list(base.get("arg", [])),
    )
    return ns


def cmd_chat(args) -> int:
    """Etkilesimli sohbet (REPL): NL yaz -> niyet -> plan -> kapilar -> sonuc.

    Risk modeli (b): passive/active OTOMATIK calisir; intrusive/destructive
    satir-ici onay ister. Model asla serbest komut uretmez; yalnizca
    katalogdan teknik secer, calistiran deterministik planlayicidir.
    """
    import types

    router = Router(endpoint=args.endpoint, model=args.model)
    model_name, warn = router.resolve_model()
    if warn:
        print(f"uyari: {warn}", file=sys.stderr)
    online = router.available()

    guard = _scope_guard(args)
    policy = Policy(allow_intrusive=args.allow_intrusive, allow_destructive=args.allow_destructive)
    audit = AuditLog(args.audit)
    registry = load_default_registry()

    state = {"target": args.target or "", "auto": True,
             "summary": not getattr(args, "no_summary", False),
             "no_report": getattr(args, "no_report", False),
             "last_exploit": None}

    def approver(action: Action) -> bool:
        if state["auto"]:
            print(ui.dim(f"    {ui.SYM['ok']} [auto] onaylandı: {action.describe()}"))
            return True
        print(f"\n  {ui.yellow(ui.SYM['warn'] + ' onay gerekiyor')}: {action.describe()}")
        if action.technique:
            print(f"    teknik : {action.technique}")
        if action.args:
            print(f"    argüman: {json.dumps(action.args, ensure_ascii=False)}")
        try:
            ans = input("  onaylıyor musun? [y/N] ").strip().lower()
        except EOFError:
            return False
        return ans in ("y", "yes", "e", "evet")

    executor = Executor(
        scope=guard, policy=policy, audit=audit, registry=registry,
        approver=approver, dry_run=args.dry_run, timeout=args.timeout,
    )

    base = {
        "from_feed": args.from_feed, "feed_min_score": args.feed_min_score,
        "max_risk": args.max_risk, "endpoint": args.endpoint, "model": args.model,
        "arg": [],
    }

    _SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1,
                 "info": 0, "unknown": 0, "": 0}

    def _summary_digest(user_text: str, plan: Plan, results: list) -> str:
        """Model ozeti icin bulgu-odakli plan/sonuc dokumu.

        Sadece sayilari degil, SOMUT bulgulari (acik port, teknoloji, zafiyet
        parametresi, eksik baslik, CVE) modele verir ki ozet 'nerede ne eksik /
        ne gecilebilir' diye detaylandirabilsin. Yine de kompakt tutulur:
        bulgular onem derecesine gore siralanir, adim basina en fazla 6 tanesi.
        """
        lines = [f"Istek: {user_text}", f"Hedef: {plan.target}",
                 "Plan: " + ", ".join(f"{a.tool}.{a.capability}[{a.risk.label}]"
                                       for a in plan.actions),
                 "Sonuclar ve bulgular:"]
        for r in results:
            a = r.action
            head = f"- {a.tool}.{a.capability}: {r.status}"
            if r.status in ("unavailable", "error", "denied") and r.detail:
                head += f" (NEDEN: {r.detail})"
            lines.append(head)
            p = r.parsed or {}
            if p.get("open_ports"):
                lines.append("    acik portlar: "
                             + ", ".join(str(x) for x in p["open_ports"][:20]))
            techs = p.get("technologies")
            if techs:
                names = list(techs) if isinstance(techs, dict) else list(techs)
                if names:
                    lines.append(f"    teknoloji: {', '.join(map(str, names[:8]))}")
            if "protected" in p:
                det = p.get("detected") or []
                lines.append(f"    WAF: {', '.join(det) if det else 'YOK (koruma tespit edilmedi)'}")
            if p.get("vulnerable"):
                params = p.get("parameters") or []
                extra = f" (parametre: {', '.join(map(str, params[:5]))})" if params else ""
                lines.append(f"    GECILEBILIR: zafiyet DOGRULANDI{extra}")
            if p.get("session_count"):
                lines.append(f"    ERISIM SAGLANDI: {p['session_count']} oturum acildi")
            if p.get("dumped"):
                lines.append("    VERI CEKILDI: veritabani icerigi loot olarak kaydedildi")
            if p.get("known_vulns"):
                lines.append(f"    bilinen CVE: {', '.join(p['known_vulns'][:8])}")
            findings = p.get("findings") or []
            findings = sorted(
                findings,
                key=lambda f: _SEV_RANK.get(str(f.get("severity", "")).lower(), 0),
                reverse=True,
            )
            for f in findings[:6]:
                sev = str(f.get("severity", "info")).lower()
                label = f.get("detail") or f.get("name") or f.get("check") or "bulgu"
                loc = (f.get("header") or f.get("parameter")
                       or f.get("matched_at") or f.get("url") or "")
                cve = f.get("cve")
                bit = f"    [{sev}] {label}"
                if cve:
                    bit += f" ({cve})"
                if loc and str(loc) not in str(label):
                    bit += f" -> {loc}"
                lines.append(bit)
            if len(findings) > 6:
                lines.append(f"    (+{len(findings) - 6} bulgu daha)")
        return "\n".join(lines)

    def run_plan(plan: Plan, user_text: str = "") -> None:
        _print_plan(plan, False)
        if not plan.actions:
            return
        print()
        try:
            results = executor.run(plan, on_event=_progress_event)
        except ScopeViolation as exc:
            print(f"  {ui.red('KAPSAM İHLALİ')}: {exc}", file=sys.stderr)
            return
        except PolicyDenied as exc:
            print(f"  {ui.red('POLİTİKA REDDİ')}: {exc}", file=sys.stderr)
            return
        if any(r.status == "aborted" for r in results):
            print(f"\n  {ui.yellow(ui.SYM['warn'] + ' durduruldu')} — prompt'a dönülüyor"
                  f" {ui.dim('(denetim kaydına yazıldı)')}")
            return
        ozet = ""
        if state["summary"] and online:
            print(ui.dim("\n  ... özet hazırlanıyor"))
            ozet = router.summarize(_summary_digest(user_text, plan, results), timeout=240)
            if ozet:
                print("  🗒  " + ozet.replace("\n", "\n      "))
        kor = correlate.correlate(results) if not args.dry_run else []
        _print_correlation(kor)
        for c in kor:
            if c.get("msf_module"):
                state["last_exploit"] = {"cve": c["cve"], "module": c["msf_module"]}
                print(ui.dim(f"    → /exploit {c['cve']}  ile bu modülü (check) deneyebilirsin"))
                break
        if not state.get("no_report") and not args.dry_run:
            from . import report
            try:
                rp = report.write_report(plan, results, summary=ozet, scope=args.scope, correlation=kor)
                print(f"  rapor: {rp}")
            except Exception as exc:  # noqa: BLE001
                print(f"  rapor yazılamadı: {exc}", file=sys.stderr)

    def make_plan(text: str, extra_args: list[str] | None = None) -> Plan | None:
        shim = _chat_shim(base, text)
        if extra_args:
            shim.arg = list(extra_args)
        print(ui.dim(f"  ... model düşünüyor ({model_name})") if online
              else ui.dim("  ... kural tabanlı eşleştirme"))
        intent = router.route(text)
        used_session_target = not intent.targets and bool(state["target"])
        targets = intent.targets or ((state["target"],) if state["target"] else ())
        if not targets:
            print("  hedef yok. '/target <host>' ile belirle ya da metinde hedef ver.")
            return None
        notes = intent.notes
        if used_session_target:
            notes = tuple(n for n in notes if "hedef çıkarılamadı" not in n)
        intent = Intent(
            objective=intent.objective or text, targets=targets,
            techniques=intent.techniques, rationale=intent.rationale,
            source=intent.source, notes=notes,
        )
        intent = _augment_from_feed(shim, intent)
        if not intent.techniques:
            print("  model katalogdan teknik seçemedi. Daha açık yaz (örn. 'port tara', 'web zafiyet').")
            for n in intent.notes:
                print(f"  not: {n}")
            return None
        plans = _build_plans(shim, intent)
        return plans[0] if plans else None

    def handle_exploit(rest: str) -> None:
        """CVE/modul -> msf exploit_check (+ 'run' ile exploit_run). Tespitle
        kalma: bulunan zafiyeti dogrula, yetki varsa somur."""
        if not state["target"]:
            print("  önce hedef ver: /target <host>  (msf RHOSTS buna göre kurulur)")
            return
        mode = "check"
        toks: list[str] = []
        for tok in rest.split():
            if tok.lower() == "run":
                mode = "run"
            else:
                toks.append(tok)
        ident = toks[0] if toks else ""
        opts: dict[str, Any] = {}
        for kv in toks[1:]:
            if "=" in kv:
                k, v = kv.split("=", 1)
                opts[k.strip()] = v.strip()
            else:
                print(f"  yok sayıldı (key=value bekleniyor): {kv}")
        note = ""
        if not ident:
            le = state.get("last_exploit")
            if not le:
                print("  kullanım: /exploit <CVE-...|exploit/modül/yolu> [k=v...] [run]")
                print("  örnek   : /exploit CVE-2017-0144         (sadece doğrula)")
                print("            /exploit CVE-2017-0144 run lhost=10.10.10.5")
                print("  not     : tarama bir MSF'li CVE bulursa argümansız /exploit onu dener")
                return
            ident, module, note = le["cve"], le["module"], "son korelasyon"
        else:
            resolved = _resolve_msf_module(ident)
            if not resolved:
                print(f"  '{ident}' için MSF modülü çözümlenemedi.")
                print("  - CVE ise: kurasyonlu tabloda ve msf kataloğunda eşleşme yok")
                print("  - doğrudan modül için tam yol yaz (örn. exploit/windows/smb/ms17_010_eternalblue)")
                return
            module, note = resolved
        if mode == "run":
            if not executor.policy.allow_destructive:
                print(f"  {ui.yellow(ui.SYM['warn'])} mode=run DESTRUCTIVE. Önce: {ui.bold('/allow destructive on')}")
                return
            if executor.scope._max_risk < Risk.DESTRUCTIVE:
                print(f"  {ui.yellow(ui.SYM['warn'])} kapsam tavanı destructive değil; gerçek exploit "
                      f"KAPSAM İHLALİ verir.\n    scope dosyasında max_risk=\"destructive\" yap.")
                return
        plan = _exploit_plan(state["target"], module, note=note, mode=mode, options=opts)
        tag = ui.risk("destructive" if mode == "run" else "intrusive")
        print(f"  modül: {ui.cyan(module)} {ui.dim('(' + note + ')') if note else ''}  [{tag}]")
        run_plan(plan, f"exploit {ident} ({module})")

    def handle_cve(rest: str) -> None:
        """CVE'yi incele: skor/KEV/CWE + ATT&CK köprüsü + varsa MSF modülü.
        Bulunan modülü /exploit için hatırlar (tespitten saldırıya köprü)."""
        cid = rest.strip().upper()
        if not cid:
            print("  kullanım: /cve CVE-2017-0144")
            return
        from .knowledge import vuln
        rec = vuln.VulnStore().get(cid)
        if rec:
            kev = ui.red(" KEV") if getattr(rec, "kev", False) else ""
            print(f"  {ui.bold(cid)}  skor {rec.score():.1f} ({rec.tier()}){kev}")
            if rec.cwe:
                print(f"    CWE: {', '.join(rec.cwe[:4])}")
        else:
            print(f"  {ui.bold(cid)}  (yerel CVE deposunda yok; MSF yine de denenir)")
        module = bridge.msf_module(cid)
        if module:
            state["last_exploit"] = {"cve": cid, "module": module[0]}
            print(f"    MSF modülü: {ui.cyan(module[0])} {ui.dim('(' + module[1] + ')')}")
            print(f"    → {ui.bold('/exploit ' + cid)} (doğrula) · "
                  f"{ui.bold('/exploit ' + cid + ' run')} (gerçek exploit)")
        else:
            print("    MSF modülü: yok (otomatik exploit adayı değil)")
        if rec:
            info = bridge.enrich(rec)
            if info.get("techniques"):
                tids = ", ".join(t["technique"] for t in info["techniques"][:5])
                print(f"    teknik köprüsü: {tids}")
            if info.get("sqli"):
                print("    SQLi sınıfı: sqlmap için /arm (verify=1)")

    def handle_allow(rest: str) -> None:
        """Oturum içinde politika kapısını aç/kapat (intrusive|destructive)."""
        parts = rest.lower().split()
        if not parts:
            print(f"  intrusive={executor.policy.allow_intrusive}  "
                  f"destructive={executor.policy.allow_destructive}")
            print("  kullanım: /allow destructive on|off  ·  /allow intrusive on|off")
            return
        on = (parts[1] if len(parts) > 1 else "on") in ("on", "1", "evet", "aç", "ac")
        if parts[0].startswith("destr"):
            executor.policy.allow_destructive = on
            print(f"  destructive = {ui.red('AÇIK') if on else 'kapalı'}")
            if on and executor.scope._max_risk < Risk.DESTRUCTIVE:
                print(f"  {ui.yellow(ui.SYM['warn'])} scope max_risk destructive değil; "
                      f"gerçek exploit yine engellenir. scope.json → max_risk=\"destructive\".")
        elif parts[0].startswith("intr"):
            executor.policy.allow_intrusive = on
            print(f"  intrusive = {'AÇIK' if on else 'kapalı'}")
        else:
            print("  bilinmeyen: /allow destructive|intrusive [on|off]")

    def run_browser(cap: str, extra: dict[str, Any]) -> None:
        """Tarayıcı (Chrome/Edge, CDP) yeteneğini doğrudan çalıştır — scope+policy kapılı."""
        if not state["target"]:
            print("  önce hedef ver: /target <host>")
            return
        act = Action(tool="browser", capability=cap, target=state["target"],
                     args=extra, risk=Risk.ACTIVE, technique="T1592",
                     rationale=f"tarayıcı {cap}")
        plan = Plan(objective=f"browser {cap}", target=state["target"], actions=[act])
        try:
            results = executor.run(plan, on_event=_progress_event)
        except ScopeViolation as exc:
            print(f"  {ui.red('KAPSAM İHLALİ')}: {exc}", file=sys.stderr)
            return
        except PolicyDenied as exc:
            print(f"  {ui.red('POLİTİKA REDDİ')}: {exc}", file=sys.stderr)
            return
        for r in results:
            p = r.parsed or {}
            if p.get("error"):
                print(f"  {ui.red('hata')}: {p['error']}")
                continue
            if cap == "js_eval":
                print(f"  sonuç ({p.get('type', '')}): {p.get('result')}")
                if p.get("exception"):
                    print(f"  {ui.red('istisna')}: {p['exception']}")
            elif cap == "screenshot":
                if p.get("screenshot_path"):
                    print(f"  🖼  {p['screenshot_path']}  ({p.get('size_bytes', 0)} B)")
            else:
                print(f"  başlık: {ui.bold(p.get('title', '') or '-')}  · "
                      f"network {p.get('network_count', 0)} · "
                      f"XHR/fetch {ui.cyan(str(p.get('xhr_fetch_count', 0)))}")
                for x in (p.get("xhr_fetch") or [])[:15]:
                    print(ui.dim(f"    {x.get('method', ''):<5} {x.get('status', ''):<4} "
                                 f"{x.get('url', '')[:92]}"))
                for f in (p.get("findings") or [])[:5]:
                    print(ui.dim(f"    [{f.get('severity')}] {f.get('detail', '')}"))

    def arm_all() -> None:
        """TAM SİLAH: tüm opt-in saldırı adımlarını silahlandır, onayı kaldır,
        politikayı sonuna kadar aç ve risk tavanını destructive yap. Her adım
        çalışırken adı yazılır ama SORULMAZ. Kapsam (scope) tek dürüst kapı
        olarak kalır — yetki beyanı odur."""
        merged = dict(tok.split("=", 1) for tok in (base.get("arg") or []))
        merged.update({"verify": "1", "render": "1", "dump": "1", "mode": "run"})
        base["arg"] = [f"{k}={v}" for k, v in merged.items()]
        base["max_risk"] = "destructive"
        state["auto"] = True
        executor.policy.allow_intrusive = True
        executor.policy.allow_destructive = True
        print(f"  {ui.red('⚔ TAM SİLAH')} — her şey silahlandı, onay SORULMAYACAK:")
        print(f"    silahlar : sqli_check+dump · xss (dalfox) · idor/bola · dom_xss (tarayıcı)"
              f" · dom_render · msf(modül verilince)")
        print(f"    yetki    : risk tavanı={ui.risk('destructive')} · auto=AÇIK · "
              f"intrusive+destructive=AÇIK")
        print(f"    arglar   : {', '.join(base['arg'])}")
        print(ui.dim("    her adım çalışırken adı yazılır (sorulmaz). Durdurmak için Ctrl+C."))
        if executor.scope._max_risk < Risk.DESTRUCTIVE:
            print(f"  {ui.yellow(ui.SYM['warn'])} kapsam tavanı '{executor.scope._max_risk.label}'. "
                  f"DESTRUCTIVE adımlar (gerçek exploit / sqli dump) KAPSAM İHLALİ verir.")
            print(ui.dim("    tam güç için YETKİLİ hedefte scope.json → max_risk=\"destructive\"."))
        print(ui.dim("    msf exploit_run için modül şart: /cve <CVE> → /exploit <CVE> run"))

    print()
    print(ui.rule())
    print(ui.banner(__version__, model_name, online, Path(args.scope).exists()))
    print(ui.rule())
    print(f"  {ui.grey('çıkış')} /quit (Ctrl+D)    {ui.grey('durdur')} Ctrl+C    "
          f"{ui.grey('yardım')} /help    {ui.grey('saldırı')} /cve · /exploit")
    print(f"  {ui.grey('hedef')} : {ui.bold(state['target']) if state['target'] else ui.grey('(ayarlı değil — /target ile belirle)')}")
    onay = (ui.yellow('OTOMATIK — intrusive sormadan çalışır (/auto off ile kapat)')
            if state['auto'] else 'intrusive/destructive ONAY ister')
    print(f"  {ui.grey('onay')}  : {onay}{ui.dim(' · dry-run') if args.dry_run else ''}")
    print(f"  {ui.grey('özet')}  : {ui.green('açık') if state['summary'] and online else ui.grey('kapalı')}")
    print(f"  {ui.grey('kapsam')}: {args.scope}   {ui.grey('denetim')}: {args.audit}")

    interrupted = False
    while True:
        try:
            line = input(f"\n{ui.cyan('kalkan')}({ui.bold(state['target'] or '-')})> ").strip()
        except EOFError:
            print("\ngörüşürüz.")
            return 0
        except KeyboardInterrupt:
            if interrupted:
                print("\ngörüşürüz.")
                return 0
            interrupted = True
            print(f"\n  {ui.dim('(iptal — çıkmak için /quit ya da tekrar Ctrl+C)')}")
            continue
        interrupted = False
        if not line:
            continue

        if line.startswith("/"):
            parts = line[1:].split(maxsplit=1)
            cmd = parts[0].lower()
            rest = parts[1].strip() if len(parts) > 1 else ""
            if cmd in ("quit", "exit", "q"):
                print("görüşürüz.")
                return 0
            if cmd in ("help", "?", "h"):
                print("  akış:")
                print("    /target [host]   oturum hedefini göster/ayarla")
                print("    /plan <metin>    sadece planla, çalıştırma")
                print("    Ctrl+C           çalışan taramayı durdur (prompt'a döner)")
                print("    /quit · Ctrl+D   çık")
                print("  saldırı (tespitle kalma):")
                print("    /arm             ⚔ TAM SİLAH: her şeyi silahla, sorma, tam yetki")
                print("    /cve <CVE-id>    CVE'yi incele: skor/KEV/CWE + MSF modülü")
                print("    /exploit <CVE|modül> [k=v...] [run]  doğrula (check) / exploit_run")
                print("    /allow destructive on   gerçek exploit (run) için politikayı aç")
                print("  tarayıcı (Chrome/Edge, DevTools):")
                print("    /render          sayfayı render et: Network + XHR/fetch + konsol + form")
                print("    /js <kod>        snippet: hedef sayfada JS çalıştır (sonucu döner)")
                print("    /shot            ekran görüntüsü (PNG kanıt)")
                print("  ayar:")
                print("    /risk <seviye>   tavan risk (passive|active|intrusive|destructive)")
                print("    /auto [on|off]   intrusive onayını atla (dikkat)")
                print("    /arg k=v ...     tek tek adım argümanı silahla (örn. verify=1, module=...)")
                print("    /ozet [on|off]   her turdan sonra Türkçe model özeti")
                print("    /feed [tail|status]  son besleme olayları")
                print("    /scope [add <h>] kapsamı göster / hedef ekle")
                print("  (bunların dışında yazdığın her şey modele niyet olarak gider)")
                continue
            if cmd == "target":
                if rest:
                    state["target"] = rest
                    print(f"  hedef = {rest}")
                else:
                    print(f"  hedef = {state['target'] or '(ayarlı değil)'}")
                continue
            if cmd == "risk":
                try:
                    base["max_risk"] = Risk.parse(rest).label
                    print(f"  tavan risk = {base['max_risk']}")
                except (ValueError, AttributeError):
                    print("  geçersiz. passive|active|intrusive|destructive")
                continue
            if cmd == "auto":
                state["auto"] = rest.lower() in ("on", "1", "evet", "aç")
                print(f"  auto-onay = {'AÇIK (intrusive sormadan çalışır)' if state['auto'] else 'kapalı'}")
                continue
            if cmd == "arm":
                arm_all()
                continue
            if cmd == "arg":
                if not rest:
                    cur = base.get("arg") or []
                    print(f"  aktif arg: {', '.join(cur) if cur else '(yok)'}")
                    print("  kullanım: /arg key=value [key=value...]  ·  /arg clear  ·  /arm (tam silah)")
                    continue
                if rest.strip().lower() == "clear":
                    base["arg"] = []
                    print("  argümanlar temizlendi (adımlar yeniden kilitli)")
                    continue
                bad = [tok for tok in rest.split() if "=" not in tok]
                if bad:
                    print(f"  geçersiz (key=value bekleniyor): {', '.join(bad)}")
                    continue
                merged = dict(tok.split("=", 1) for tok in (base.get("arg") or []))
                for tok in rest.split():
                    k, v = tok.split("=", 1)
                    merged[k.strip()] = v.strip()
                base["arg"] = [f"{k}={v}" for k, v in merged.items()]
                print(f"  aktif arg: {', '.join(base['arg'])}")
                if "verify" in merged:
                    print("    → sqli_check (sqlmap) + xss_scan (dalfox) SİLAHLI "
                          "[INTRUSIVE · her çalıştırmada onay sorar]")
                if "module" in merged:
                    print("    → exploit_check (msf) SİLAHLI [INTRUSIVE · mode=check]."
                          " Gerçek exploit için: mode=run + başlatırken --allow-destructive")
                continue
            if cmd in ("ozet", "özet"):
                if rest:
                    state["summary"] = rest.lower() in ("on", "1", "evet", "aç")
                print(f"  özet = {'açık' if state['summary'] else 'kapalı'}"
                      f"{'' if online else ' (model çevrimdışı → özet üretilemez)'}")
                continue
            if cmd == "scope":
                sub = rest.split(maxsplit=1)
                if sub and sub[0].lower() == "add":
                    tgt = sub[1].strip() if len(sub) > 1 else state["target"]
                    if not tgt:
                        print("  kullanım: /scope add <hedef>  (ya da önce /target)")
                        continue
                    from .scope import Scope, ScopeGuard, add_to_scope_file
                    try:
                        info = add_to_scope_file(args.scope, tgt)
                    except ScopeViolation as exc:
                        print(f"  {exc}", file=sys.stderr)
                        continue
                    executor.scope = ScopeGuard(Scope.load(args.scope))
                    msg = "eklendi" if info["changed"] else "zaten kapsamda"
                    print(f"  {msg} ({info['kind']}): {info['host']}")
                    print("  ! bu, hedefi test etmeye YETKİLİ olduğun beyanıdır.")
                else:
                    print(executor.scope.describe())
                continue
            if cmd == "feed":
                from .feeds import JsonlSink
                sub = rest.lower() or "tail"
                if sub.startswith("stat"):
                    from .feeds import FeedDaemon
                    st = FeedDaemon().status().get("store", {})
                    print(f"  CVE deposu: {st.get('cve_count', 0)} "
                          f"(KEV {st.get('kev_in_store', 0)}, kritik {st.get('critical', 0)})")
                else:
                    for e in JsonlSink().tail(limit=8):
                        mark = "!" if e.kind == "cve.kev" else ("*" if e.kind == "cve.critical" else " ")
                        print(f"  {mark} {e.kind:<15} {e.id or e.source:<16} {e.title[:60]}")
                continue
            if cmd == "plan":
                if not rest:
                    print("  kullanım: /plan <metin>")
                    continue
                p = make_plan(rest)
                if p:
                    _print_plan(p, False)
                continue
            if cmd in ("exploit", "saldiri", "attack"):
                handle_exploit(rest)
                continue
            if cmd in ("cve", "vuln"):
                handle_cve(rest)
                continue
            if cmd == "allow":
                handle_allow(rest)
                continue
            if cmd in ("js", "snippet", "eval"):
                if not rest:
                    print("  kullanım: /js <javascript>   (hedef sayfada tarayıcıda çalıştırır)")
                    continue
                run_browser("js_eval", {"script": rest})
                continue
            if cmd in ("render", "dom", "network", "xhr"):
                run_browser("dom_render", {"wait": 3})
                continue
            if cmd in ("shot", "screenshot", "ss"):
                run_browser("screenshot", {})
                continue
            print(f"  bilinmeyen komut: /{cmd}  (/help)")
            continue

        try:
            plan = make_plan(line)
            if plan:
                run_plan(plan, line)
        except Exception as exc:  # noqa: BLE001 - bir tur hatasi oturumu dusurmesin
            print(f"  hata: {exc}", file=sys.stderr)

    return 0


def _home_ns(base: dict[str, Any], **over):
    """Menüden mevcut cmd_* fonksiyonlarını çağırmak için tam varsayılanlı args."""
    import types
    d = dict(
        scope=base.get("scope", "scope.json"), audit=base.get("audit", DEFAULT_AUDIT),
        text="", technique=[], tactic=None, target=None,
        max_risk="intrusive", module=None, payload=None, mode=None,
        endpoint=base.get("endpoint", DEFAULT_ENDPOINT), model=base.get("model", DEFAULT_MODEL),
        timeout=300, json=False, yes=False, dry_run=False,
        allow_intrusive=True, allow_destructive=False,
        from_feed=False, feed_min_score=40.0, arg=[], no_summary=False, no_report=False,
        action=None, risk="passive",
        once=False, max_cycles=None, vuln_interval=None, attack_interval=None,
        atlas_interval=None, days=None, no_kev=False, no_epss=False,
        stdout=False, webhook="", from_start=False, kind=[], min_tier="", limit=20,
        query="", search_query=None, domain="enterprise", force=False, cache_root=None,
        out="kalkan-coverage.json", covered_only=False, name="Kalkan Coverage",
    )
    d.update(over)
    return types.SimpleNamespace(**d)


def _ask(prompt: str, default: str = "") -> str:
    try:
        v = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return v or default


def cmd_home(args) -> int:
    """Kalkan ana menü arayüzü — neyin ne yaptığını gösterir, seçtir."""
    base = {"scope": getattr(args, "scope", "scope.json"),
            "audit": getattr(args, "audit", DEFAULT_AUDIT),
            "endpoint": getattr(args, "endpoint", DEFAULT_ENDPOINT),
            "model": getattr(args, "model", DEFAULT_MODEL)}

    router = Router(endpoint=base["endpoint"], model=base["model"])
    online = router.available()
    scope_ok = Path(base["scope"]).exists()

    def banner():
        print()
        print(ui.rule())
        print(ui.banner(__version__, base["model"], online, scope_ok))
        print(ui.rule())

    MENU = [
        ("1", "Sohbet (chat)", "Modelle konuşarak planla/çalıştır — ana kullanım"),
        ("2", "Plan üret", "Tek istek → plan göster (çalıştırmaz)"),
        ("3", "Çalıştır", "Tek istek → planı kapılardan geçirip yürüt"),
        ("w", "Web uygulama taraması", "httpx + wafw00f + webprobe + nuclei (deterministik)"),
        ("4", "Kapsam (scope)", "İzinli hedefleri göster / yeni hedef ekle"),
        ("5", "Canlı besleme", "CVE/ATT&CK akışı: durum · son olaylar · başlat"),
        ("6", "Araçlar & kapsama", "Kurulu araçlar ve teknik kapsama durumu"),
        ("7", "Bilgi tabanı", "ATT&CK / ATLAS teknik arama"),
        ("n", "ATT&CK haritası", "Navigator layer üret (Kalkan kapsama)"),
        ("h", "Yardım", "Bu menüyü açıklar"),
        ("q", "Çıkış", ""),
    ]

    def show_menu():
        print()
        for key, title, desc in MENU:
            print(f"  [{ui.cyan(key)}] {ui.bold(title)}{' ' * max(0, 20 - len(title))} {ui.grey(desc)}")

    banner()
    if not scope_ok:
        print(f"  ⚠ kapsam dosyası yok ({base['scope']}). '4 → ekle' ile hedef tanımla\n"
              f"    veya examples/scope.json'u kopyala.")
    show_menu()

    while True:
        choice = _ask("\nkalkan> ").lower()
        if choice in ("q", "quit", "exit", "0"):
            print("görüşürüz.")
            return 0
        try:
            if choice in ("h", "?", "help"):
                show_menu()
            elif choice == "1":
                tgt = _ask("  hedef (boş geç, sonra /target): ")
                cmd_chat(_home_ns(base, target=tgt or ""))
                banner(); show_menu()
            elif choice in ("2", "3"):
                tgt = _ask("  hedef: ")
                if not tgt:
                    print("  hedef gerekli."); continue
                req = _ask("  ne yapılsın? (örn. port tara, web zafiyet): ")
                ns = _home_ns(base, target=tgt, text=req)
                (cmd_plan if choice == "2" else cmd_run)(ns)
            elif choice == "w":
                tgt = _ask("  web hedefi (örn. https://site veya alan adı): ")
                if not tgt:
                    print("  hedef gerekli."); continue
                cmd_run(_home_ns(base, target=tgt, technique=["T1592", "T1190"]))
            elif choice == "4":
                print("  [g] göster   [e] hedef ekle")
                s = _ask("  seçim: ").lower()
                if s == "e":
                    tgt = _ask("  eklenecek hedef: ")
                    if tgt:
                        cmd_scope(_home_ns(base, action="add", target=tgt))
                else:
                    cmd_scope(_home_ns(base, action="show"))
            elif choice == "5":
                print("  [d] durum   [o] son olaylar   [b] arka planda başlat")
                s = _ask("  seçim: ").lower()
                act = {"d": "status", "o": "tail", "b": "start"}.get(s, "status")
                cmd_feed(_home_ns(base, action=act))
            elif choice == "6":
                cmd_tools(_home_ns(base))
                cmd_coverage(_home_ns(base))
            elif choice == "7":
                dom = _ask("  domain [enterprise/mobile/ics/atlas] (boş=enterprise): ") or "enterprise"
                q = _ask("  arama: ")
                cmd_knowledge(_home_ns(base, action="search", search_query=q, domain=dom))
            elif choice == "n":
                out = _ask("  çıktı dosyası [kalkan-coverage.json]: ") or "kalkan-coverage.json"
                cmd_navigator(_home_ns(base, out=out))
            else:
                print("  geçersiz seçim. [h] yardım")
        except SystemExit as exc:
            print(f"  (iptal: {exc})")
        except Exception as exc:  # noqa: BLE001 - menü oturumu düşmesin
            print(f"  hata: {exc}", file=sys.stderr)

    return 0


def cmd_audit(args) -> int:
    audit = AuditLog(args.audit)
    if args.action == "verify":
        ok, message = audit.verify()
        print(("SAĞLAM: " if ok else "BOZUK: ") + message)
        return 0 if ok else 2
    for record in audit.tail(args.count):
        print(json.dumps(record, ensure_ascii=False))
    return 0


def cmd_vuln(args) -> int:
    from .knowledge import vuln

    store = vuln.VulnStore()

    action = args.action
    if action == "update":
        result = store.sync(
            days=args.days,
            max_pages=args.max_pages,
            with_kev=args.with_kev,
            with_epss=args.with_epss,
        )
        print(
            f"synced: fetched={result['fetched']}, added={result['added']}, "
            f"new={len(result['new'])}, total={result['total']}, "
            f"kev={result['kev']} ({result['synced_at']})"
        )
        if result["new"]:
            print(" Yeni CVEs:")
            for cve in result["new"][:10]:
                print(f"  - {cve}")
        return 0

    if action == "show":
        cve_id = args.cve
        if not cve_id:
            print("--cve argümanı gerekli", file=sys.stderr)
            return 2
        record = store.get(cve_id)
        if not record:
            print(f"Kayıt bulunamadı: {cve_id}", file=sys.stderr)
            return 2
        st = record.base_score
        vector = record.vector
        cwe = record.cwe[0] if record.cwe else "bilinmiyor"
        kev = record.kev
        epss = record.epss
        print(f"CVE ID      : {cve_id}")
        print(f"CVSS v3.1   : {st}")
        print(f"Vektor      : {vector}")
        print(f"CWE         : {cwe}")
        print(f"KEV         : {'evet' if kev else 'hayır'}")
        print(f"EPSS        : {epss}")
        print(f"Referanslar: {', '.join(record.references[:3])}")
        return 0

    if action == "top":
        limit = args.limit if args.limit else 20
        min_score = args.min_score if args.min_score else 0.0
        records = store.top(limit=limit, min_score=min_score)
        print(f"{'CVE ID':<15} {'SKOR':<8} {'DERECE':<10}")
        for record in records:
            print(f"{record.id:<15} {record.score():<8.1f} {record.tier():<10}")
        return 0

    if action == "search":
        query = args.query if args.query else ""
        records = store.search(query, limit=args.limit)
        print(f"{'CVE ID':<15} {'SKOR':<8} {'DERECE':<10}")
        for record in records:
            print(f"{record.id:<15} {record.score():<8.1f} {record.tier():<10}")
        return 0

    if action == "match":
        cve_id = args.cve
        product = args.product
        version = args.version
        if not cve_id and not product:
            print("--cve or --product argümanı gerekli", file=sys.stderr)
            return 2
        if cve_id:
            record = store.get(cve_id)
            if not record:
                print(f"Kayıt bulunamadı: {cve_id}", file=sys.stderr)
                return 2
            use_cve_id = True
        else:
            record = store.match(product=product, version=version)
            if not record:
                print(f"Eşleşme bulunamadı: {product} {version or ''}", file=sys.stderr)
                return 2
            use_cve_id = False
        st = record.base_score
        vector = record.vector
        kev = record.kev
        epss = record.epss
        print(f"CVE ID      : {record.id}")
        print(f"CVSS v3.1   : {st}")
        print(f"Vektor      : {vector}")
        print(f"KEV         : {'evet' if kev else 'hayır'}")
        print(f"EPSS        : {epss}")
        if use_cve_id:
            print(f"Referanslar: {', '.join(record.references[:3])}")
        return 0

    if action == "enrich":
        cve_id = args.cve
        if not cve_id:
            print("--cve argmani gerekli", file=sys.stderr)
            return 2
        intel = store.enrich(cve_id)
        if not intel:
            print(f"Kayit bulunamadi: {cve_id}", file=sys.stderr)
            return 2
        for key, val in intel.items():
            if isinstance(val, list):
                vals = ", ".join(str(v) for v in val[:5])
            else:
                vals = str(val)
            print(f"{key:<14}: {vals}")
        return 0

    if action == "watch":
        import threading

        interval = args.interval if args.interval else 3600
        max_cycles = args.max_cycles
        if args.once:
            max_cycles = 1

        def on_cycle(result):
            print(
                f"döngü tamamlandı: fetched={result['fetched']}, "
                f"added={result['added']}, total={result['total']}, "
                f"kev={result['kev']} ({result['synced_at']})"
            )
            if result["new"]:
                print(" Yeni CVEs:")
                for cve in result["new"][:5]:
                    print(f"  - {cve}")

        def watch_loop():
            cycle = 0
            while max_cycles is None or cycle < max_cycles:
                cycle += 1
                result = store.sync(
                    days=args.days,
                    max_pages=args.max_pages,
                    with_kev=args.with_kev,
                    with_epss=args.with_epss,
                )
                on_cycle(result)
                if max_cycles is not None and cycle >= max_cycles:
                    break
                threading.Event().wait(interval)

        print(f"watch başlıyor - aralık: {interval}s, maksimum döngü: {max_cycles or 'sonsuz'}")
        thread = threading.Thread(target=watch_loop, daemon=True)
        thread.start()
        try:
            import time
            while thread.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nwatch durduruldu")
        return 0

    print(f"Bilinmeyen vuln eylemi: {action}", file=sys.stderr)
    return 2


def _feed_config(args) -> "Any":
    from .feeds import FeedConfig

    cfg = FeedConfig()
    if getattr(args, "vuln_interval", None):
        cfg.vuln_interval = args.vuln_interval
    if getattr(args, "attack_interval", None):
        cfg.attack_interval = args.attack_interval
    if getattr(args, "atlas_interval", None):
        cfg.atlas_interval = args.atlas_interval
    if getattr(args, "days", None):
        cfg.vuln_days = args.days
    cfg.with_kev = not getattr(args, "no_kev", False)
    cfg.with_epss = not getattr(args, "no_epss", False)
    return cfg


def cmd_feed(args) -> int:
    from .feeds import FanOut, FeedDaemon, JsonlSink, StdoutSink, WebhookSink
    from .feeds.events import FeedEvent

    action = args.action

    if action == "stream":
        sink = JsonlSink()
        kinds = set(args.kind) if args.kind else None
        tier_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        floor = tier_rank.get(args.min_tier, 0) if args.min_tier else 0
        try:
            for ev in sink.follow(from_start=args.from_start):
                if kinds and ev.kind not in kinds:
                    continue
                if ev.tier and tier_rank.get(ev.tier, 0) < floor and ev.kind != "cve.kev":
                    continue
                sys.stdout.write(ev.to_json() + "\n")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("\nakis durduruldu", file=sys.stderr)
        return 0

    if action == "tail":
        sink = JsonlSink()
        events = sink.tail(limit=args.limit)
        if args.json:
            print(json.dumps([__import__("dataclasses").asdict(e) for e in events], ensure_ascii=False, indent=2))
        else:
            for e in events:
                mark = "!" if e.kind == "cve.kev" else ("*" if e.kind == "cve.critical" else " ")
                ident = e.id or e.source
                print(f"{mark} {e.ts}  {e.kind:<16} {ident:<18} {e.title[:70]}")
        return 0

    if action == "status":
        daemon = FeedDaemon(config=_feed_config(args))
        st = daemon.status()
        if args.json:
            print(json.dumps(st, ensure_ascii=False, indent=2))
        else:
            pid = st.get("pid")
            print(f"daemon       : {'calisiyor (pid ' + str(pid) + ')' if pid else 'calismiyor'}")
            print(f"baslama      : {st.get('started_at', '-')}")
            print(f"vuln senkron : {st.get('vuln_synced', '-')}")
            print(f"attack sync  : {st.get('enterprise_synced', '-')}")
            print(f"atlas sync   : {st.get('atlas_synced', '-')}")
            store = st.get("store", {})
            print(f"CVE deposu   : {store.get('cve_count', 0)} (KEV {store.get('kev_in_store', 0)}, "
                  f"kritik {store.get('critical', 0)}, high {store.get('high', 0)})")
        return 0

    if action == "stop":
        daemon = FeedDaemon()
        pid = daemon._running_pid()
        if not pid:
            print("calisan daemon yok")
            return 0
        import signal
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"daemon durduruldu (pid {pid})")
        except (OSError, ProcessLookupError) as exc:
            print(f"durdurulamadi: {exc}", file=sys.stderr)
            return 1
        daemon._clear_pid()
        return 0

    if action == "start":
        daemon = FeedDaemon()
        if daemon._running_pid():
            print(f"daemon zaten calisiyor (pid {daemon._running_pid()})", file=sys.stderr)
            return 1
        import subprocess
        cmd = [sys.executable, "-m", "kalkan.cli", "feed", "run"]
        for flag, val in (("--vuln-interval", args.vuln_interval),
                          ("--attack-interval", args.attack_interval),
                          ("--atlas-interval", args.atlas_interval)):
            if val:
                cmd += [flag, str(val)]
        if getattr(args, "no_kev", False):
            cmd.append("--no-kev")
        if getattr(args, "no_epss", False):
            cmd.append("--no-epss")
        if args.webhook:
            cmd += ["--webhook", args.webhook]
        kwargs: dict[str, Any] = {}
        if os.name == "nt":
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008
            )
        else:
            kwargs["start_new_session"] = True
        log = (FeedDaemon().home / "daemon.log").open("a", encoding="utf-8")
        subprocess.Popen(cmd, stdout=log, stderr=log, stdin=subprocess.DEVNULL, **kwargs)
        print("daemon baslatildi (arka plan). Akis icin: kalkan feed stream")
        return 0

    if action == "run":
        sinks: list[Any] = [JsonlSink()]
        if args.stdout:
            sinks.append(StdoutSink())
        if args.webhook:
            sinks.append(WebhookSink(args.webhook, min_tier=args.min_tier or "high"))
        sink = sinks[0] if len(sinks) == 1 else FanOut(*sinks)
        daemon = FeedDaemon(config=_feed_config(args), sink=sink)
        max_cycles = 1 if args.once else args.max_cycles
        if not args.once:
            cfg = daemon.config
            print(f"feed daemon calisiyor — vuln/{cfg.vuln_interval}s, "
                  f"attack/{cfg.attack_interval}s, atlas/{cfg.atlas_interval}s "
                  f"(Ctrl+C ile dur)", file=sys.stderr)
        try:
            res = daemon.run(once=args.once, max_cycles=max_cycles)
        except KeyboardInterrupt:
            print("\ndaemon durduruldu", file=sys.stderr)
            return 0
        if args.once:
            print(f"tek tur tamamlandi ({res['cycles']} dongu)")
        return 0

    print(f"Bilinmeyen feed eylemi: {action}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kalkan",
        description="ATT&CK/ATLAS haritalı güvenlik orchestrasyon çekirdeği",
    )
    parser.add_argument("--scope", default="scope.json", help="kapsam dosyası (JSON)")
    parser.add_argument("--audit", default=DEFAULT_AUDIT, help="denetim kaydı yolu")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scope = sub.add_parser("scope", help="kapsamı göster, denetle veya hedef ekle")
    p_scope.add_argument("action", choices=["show", "check", "add"], nargs="?", default="show")
    p_scope.add_argument("target", nargs="?", default="")
    p_scope.add_argument("--risk", default="passive")
    p_scope.set_defaults(func=cmd_scope)

    p_tools = sub.add_parser("tools", help="kayıtlı araçları listele")
    p_tools.add_argument("--json", action="store_true")
    p_tools.set_defaults(func=cmd_tools)

    p_cov = sub.add_parser("coverage", help="teknik kapsamını ve araç hazırlığını göster")
    p_cov.add_argument("--json", action="store_true")
    p_cov.set_defaults(func=cmd_coverage)

    p_know = sub.add_parser("knowledge", help="ATT&CK/ATLAS bilgi tabanı (tam veri seti)")
    p_know.add_argument("action", choices=[
        "fetch", "search", "show", "atlas", "stats",
        "groups", "software", "campaigns", "datasources",
    ])
    p_know.add_argument("query", nargs="?", default="")
    p_know.add_argument(
        "--query", "-q",
        dest="search_query",
        default=None,
        help="arama sorgusu (option srasindan bagimsiz calisir)",
    )
    p_know.add_argument("--technique", default="")
    p_know.add_argument(
        "--domain",
        default="enterprise",
        choices=["enterprise", "mobile", "ics", "atlas"],
        help="veri domeni; atlas = TAM ATLAS katalogu (STIX)",
    )
    p_know.add_argument("--force", action="store_true")
    p_know.add_argument(
        "--cache-root",
        default=None,
        help="onbellek dizini (varsayilan ~/.kalkan/<domain>)",
    )
    p_know.set_defaults(func=cmd_knowledge)

    p_vuln = sub.add_parser("vuln", help="CVE / CVSS / EPSS / KEV istihbarati")
    p_vuln.add_argument("action", choices=["update", "show", "top", "search", "match", "watch", "enrich"])
    p_vuln.add_argument("--cve", default="", help="CVE kimliği (show, enrich, match için)")
    p_vuln.add_argument("--product", default="", help="Ürün adı (match için)")
    p_vuln.add_argument("--version", default="", help="Sürüm (match için)")
    p_vuln.add_argument("--query", default="", help="Ara sorgusu (search için)")
    p_vuln.add_argument("--limit", type=int, default=20, help="Maksimum sonuç sayısı")
    p_vuln.add_argument("--min-score", type=float, default=0.0)
    p_vuln.add_argument("--days", type=int, default=30, help="NCD için gün aralığı")
    p_vuln.add_argument("--max-pages", type=int, default=5, help="NCD sayfa limiti")
    p_vuln.add_argument("--with-kev", action="store_true", help="KEV'i de senkronize")
    p_vuln.add_argument("--with-epss", action="store_true", help="EPSS'i de senkronize")
    p_vuln.add_argument("--interval", type=int, default=3600, help="watch için saniye aralığı")
    p_vuln.add_argument("--once", action="store_true", help="watch: tek seferlik çalış (test/CI)")
    p_vuln.add_argument("--max-cycles", type=int, default=None, help="watch: maksimum döngü sayısı (None = sonsuz)")
    p_vuln.set_defaults(func=cmd_vuln)

    p_feed = sub.add_parser("feed", help="canli besleme (ATT&CK/ATLAS + CVE/CVSS/KEV akisi)")
    p_feed.add_argument(
        "action",
        choices=["run", "start", "stop", "status", "stream", "tail"],
        help="run=on planda daemon, start=arka planda, stream=canli akis, tail=son olaylar",
    )
    p_feed.add_argument("--once", action="store_true", help="run: tek tur (test/CI)")
    p_feed.add_argument("--max-cycles", type=int, default=None, help="run: maksimum dongu")
    p_feed.add_argument("--vuln-interval", type=int, default=None, help="CVE tazeleme periyodu (sn)")
    p_feed.add_argument("--attack-interval", type=int, default=None, help="ATT&CK tazeleme periyodu (sn)")
    p_feed.add_argument("--atlas-interval", type=int, default=None, help="ATLAS tazeleme periyodu (sn)")
    p_feed.add_argument("--days", type=int, default=None, help="her turda cekilecek CVE gun araligi")
    p_feed.add_argument("--no-kev", action="store_true", help="KEV senkronunu kapat")
    p_feed.add_argument("--no-epss", action="store_true", help="EPSS senkronunu kapat")
    p_feed.add_argument("--stdout", action="store_true", help="run: olaylari stdout'a da bas")
    p_feed.add_argument("--webhook", default="", help="kritik/KEV olaylarini bu URL'ye POST et")
    p_feed.add_argument("--from-start", action="store_true", help="stream: bastan oku")
    p_feed.add_argument("--kind", action="append", default=[], help="stream: olay turu filtresi (tekrarlanabilir)")
    p_feed.add_argument("--min-tier", default="", choices=["", "info", "low", "medium", "high", "critical"])
    p_feed.add_argument("--limit", type=int, default=20, help="tail: olay sayisi")
    p_feed.add_argument("--json", action="store_true")
    p_feed.set_defaults(func=cmd_feed)

    p_home = sub.add_parser("home", help="Kalkan ana menü arayüzü (argümansız 'kalkan' bunu açar)")
    p_home.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    p_home.add_argument("--model", default=DEFAULT_MODEL)
    p_home.set_defaults(func=cmd_home)

    p_chat = sub.add_parser("chat", help="modelle sohbet ederek planla/çalıştır (REPL)")
    p_chat.add_argument("--target", default="", help="oturum hedefi (sonra /target ile değişir)")
    p_chat.add_argument("--from-feed", action="store_true", help="canlı CVE beslemesini öneriye kat")
    p_chat.add_argument("--feed-min-score", type=float, default=40.0)
    p_chat.add_argument("--max-risk", default="intrusive",
                        choices=["passive", "active", "intrusive", "destructive"])
    p_chat.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    p_chat.add_argument("--model", default=DEFAULT_MODEL)
    p_chat.add_argument("--timeout", type=int, default=300)
    p_chat.add_argument("--dry-run", action="store_true", help="komutları üret, çalıştırma")
    p_chat.add_argument("--no-summary", action="store_true", help="tur sonu Türkçe model özetini kapat")
    p_chat.add_argument("--no-report", action="store_true", help="tarama sonrası .md rapor yazımını kapat")
    p_chat.add_argument("--allow-intrusive", action="store_true")
    p_chat.add_argument("--allow-destructive", action="store_true")
    p_chat.add_argument("--scope", default=argparse.SUPPRESS, help="kapsam dosyası (global --scope'u ezer)")
    p_chat.add_argument("--audit", default=argparse.SUPPRESS, help="denetim kaydı (global --audit'i ezer)")
    p_chat.set_defaults(func=cmd_chat)

    p_router = sub.add_parser("router", help="modelin niyet çıkarımını gör")
    p_router.add_argument("text")
    p_router.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    p_router.add_argument("--model", default=DEFAULT_MODEL)
    p_router.add_argument("--no-suggest", action="store_true", help="canli besleme onerilerini kapat")
    p_router.set_defaults(func=cmd_router)

    for name, func, help_text in (
        ("plan", cmd_plan, "plan üret (çalıştırmaz)"),
        ("run", cmd_run, "planı kapsam/politika denetimiyle çalıştır"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("text", nargs="?", default="")
        p.add_argument("--technique", action="append", default=[], help="teknik kimliği (tekrarlanabilir)")
        p.add_argument("--from-feed", action="store_true",
                       help="canli CVE beslemesinden eslesen playbook tekniklerini plana ekle")
        p.add_argument("--feed-min-score", type=float, default=40.0,
                       help="--from-feed: minimum CVE oncelik skoru (varsayilan 40)")
        p.add_argument("--arg", action="append", default=[], metavar="KEY=VALUE",
                       help="adim argumani override'i (tekrarlanabilir); orn. --arg verify=1 "
                            "sqlmap/dalfox'u acar, --arg module=exploit/... msf'i acar")
        p.add_argument("--no-report", action="store_true", help="tarama sonrası .md rapor yazımını kapat")
        p.add_argument("--tactic", default=None)
        p.add_argument("--target", default=None)
        p.add_argument("--max-risk", default="intrusive", choices=["passive", "active", "intrusive", "destructive"])
        p.add_argument("--module", default=None, help="msf modül yolu")
        p.add_argument("--payload", default=None, help="msf payload")
        p.add_argument("--mode", default=None, choices=["check", "run"])
        p.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
        p.add_argument("--model", default=DEFAULT_MODEL)
        p.add_argument("--timeout", type=int, default=300)
        p.add_argument("--scope", default=argparse.SUPPRESS, help="kapsam dosyası (global --scope'u ezer)")
        p.add_argument("--audit", default=argparse.SUPPRESS, help="denetim kaydı (global --audit'i ezer)")
        p.add_argument("--json", action="store_true")
        p.add_argument("--yes", action="store_true", help="onay sormadan geç (dikkat)")
        p.add_argument("--dry-run", action="store_true", help="komutları üret, çalıştırma")
        p.add_argument("--allow-intrusive", action="store_true")
        p.add_argument("--allow-destructive", action="store_true")
        p.set_defaults(func=func)

    p_nav = sub.add_parser("navigator", help="ATT&CK Navigator layer üret (Kalkan kapsama haritası)")
    p_nav.add_argument("--out", default="kalkan-coverage.json", help="çıktı JSON yolu")
    p_nav.add_argument("--domain", default="enterprise", choices=["enterprise", "mobile", "ics"])
    p_nav.add_argument("--covered-only", action="store_true", help="yalnızca playbook'u olan teknikleri yaz")
    p_nav.add_argument("--name", default="Kalkan Coverage", help="layer adı")
    p_nav.add_argument("--cache-root", default=None, help="ATT&CK önbellek dizini")
    p_nav.set_defaults(func=cmd_navigator)

    p_exploit = sub.add_parser(
        "exploit",
        help="CVE/modülü hedefe karşı doğrula (check) veya exploit et (run)",
    )
    p_exploit.add_argument("target", help="hedef host/IP (kapsam içinde olmalı)")
    p_exploit.add_argument("ident", help="CVE kimliği (CVE-2017-0144) ya da msf modül yolu (exploit/...)")
    p_exploit.add_argument("--mode", choices=["check", "run"], default="check",
                           help="check=doğrula (INTRUSIVE, varsayılan); run=gerçek exploit (DESTRUCTIVE)")
    p_exploit.add_argument("--payload", default=None, help="msf payload (run için)")
    p_exploit.add_argument("--lhost", default=None, help="geri bağlantı adresi (reverse payload)")
    p_exploit.add_argument("--lport", default=None)
    p_exploit.add_argument("--rport", default=None)
    p_exploit.add_argument("--post", default=None,
                           help="oturum sonrası keşif komutları (örn. 'sysinfo;getuid')")
    p_exploit.add_argument("--timeout", type=int, default=600)
    p_exploit.add_argument("--yes", action="store_true", help="onay sormadan geç (dikkat)")
    p_exploit.add_argument("--dry-run", action="store_true", help="komutu üret, çalıştırma")
    p_exploit.add_argument("--allow-intrusive", action="store_true", default=True)
    p_exploit.add_argument("--allow-destructive", action="store_true", help="mode=run için zorunlu")
    p_exploit.add_argument("--scope", default=argparse.SUPPRESS, help="kapsam dosyası (global --scope'u ezer)")
    p_exploit.add_argument("--audit", default=argparse.SUPPRESS, help="denetim kaydı (global --audit'i ezer)")
    p_exploit.set_defaults(func=cmd_exploit)

    p_audit = sub.add_parser("audit", help="denetim kaydını doğrula/göster")
    p_audit.add_argument("action", choices=["verify", "tail"], nargs="?", default="verify")
    p_audit.add_argument("--count", type=int, default=10)
    p_audit.add_argument("--audit", default=argparse.SUPPRESS, help="denetim kaydı (global --audit'i ezer)")
    p_audit.set_defaults(func=cmd_audit)

    return parser


def _setup_console() -> None:
    """Dar kodlamalı Windows konsollarında (cp1254 vb.) çökmeyi engeller."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


_KNOWN_COMMANDS = {
    "scope", "tools", "coverage", "knowledge", "vuln", "feed",
    "home", "chat", "router", "plan", "run", "audit", "exploit", "navigator",
}
_GLOBAL_VALUE_OPTS = {"--scope", "--audit"}


def _inject_default_command(argv: list[str]) -> list[str]:
    """Alt komut verilmemişse menü arayüzüne düş: argümansız `kalkan` → 'home'.
    Global bayraktan sonra komut yoksa yine 'home'; bilinmeyen bir bayrakla
    gelinmişse (örn. --target) 'chat'e verilir (geriye dönük kolaylık)."""
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-h", "--help"):
            return argv
        if tok in _GLOBAL_VALUE_OPTS:
            i += 2
            continue
        if tok.startswith("--") and "=" in tok and tok.split("=", 1)[0] in _GLOBAL_VALUE_OPTS:
            i += 1
            continue
        break
    if i >= len(argv):
        return argv[:i] + ["home"] + argv[i:]
    if argv[i] not in _KNOWN_COMMANDS:
        return argv[:i] + ["chat"] + argv[i:]
    return argv


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    if argv is None:
        argv = sys.argv[1:]
    argv = _inject_default_command(list(argv))
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())