"""Kalkan komut satırı arayüzü."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .adapters import load_default_registry
from .audit import AuditLog
from .knowledge import atlas, mapping
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
    print(f"\nhedef     : {p.target}")
    print(f"amaç      : {p.objective}")
    print(f"aksiyon   : {len(p.actions)}  (tavan risk: {p.max_risk().label})")
    for i, a in enumerate(p.actions, 1):
        print(f"  {i}. [{a.risk.label:9}] {a.tool}.{a.capability:<18} {a.technique}")
        if a.rationale:
            print(f"       - {a.rationale}")
        if a.args:
            print(f"       - {json.dumps(a.args, ensure_ascii=False)}")
    for note in p.notes:
        print(f"  not: {note}")


def _intent_from_args(args) -> Intent:
    if args.technique:
        targets = tuple(t for t in ([args.target] if args.target else []))
        return Intent(
            objective=args.text or "",
            targets=targets,
            techniques=tuple(args.technique),
            rationale="kullanıcı doğrudan belirtti",
            source="explicit",
        )
    if not args.text:
        raise SystemExit("metin veya --technique gerekli")
    router = Router(endpoint=args.endpoint, model=args.model)
    intent = router.route(args.text)
    if args.target:
        intent = Intent(
            objective=intent.objective,
            targets=(args.target,),
            techniques=intent.techniques,
            rationale=intent.rationale,
            source=intent.source,
            notes=intent.notes,
        )
    return intent


def _build_plans(args, intent: Intent) -> list[Plan]:
    """Niyetten (hedef başına bir) deterministik plan üret.

    Risk tavanı --max-risk ile; belirtilmezse INTRUSIVE. Model/modül/payload
    gibi değerler adım argümanlarına override olarak geçirilir.
    """
    registry = load_default_registry()
    max_risk = Risk.parse(args.max_risk) if getattr(args, "max_risk", None) else Risk.INTRUSIVE

    overrides: dict[str, Any] = {}
    for key in ("module", "payload", "mode", "endpoint", "model"):
        value = getattr(args, key, None)
        if value:
            overrides[key] = value

    return plan_for_intent(intent, registry, max_risk, overrides)


def cmd_scope(args) -> int:
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
    print(f"{'ARAÇ':<10} {'DURUM':<12} {'RİSK':<9} YETENEKLER")
    for row in rows:
        state = "hazır" if row["available"] else "eksik"
        print(
            f"{row['tool']:<10} {state:<12} {row['risk']:<9} {', '.join(row['capabilities'])}"
        )
        if row["reason"]:
            print(f"{'':<10} - {row['reason']}")
    return 0


def cmd_coverage(args) -> int:
    registry = load_default_registry()
    rows = mapping.coverage(registry)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    print(f"{'TEKNİK':<12} {'FRAMEWORK':<10} {'TAKTİK':<18} {'ADIM':<5} {'DURUM'}")
    for row in rows:
        state = "hazır" if row["ready"] else "eksik"
        print(
            f"{row['technique']:<12} {row['framework']:<10} {row['tactic']:<18} "
            f"{row['steps']:<5} {state}"
        )
        for missing in row["missing"]:
            print(f"{'':<12} - {missing}")
    auto = atlas.automated()
    manual = atlas.manual()
    print(f"\nATLAS: {len(auto)} teknik otomatik test edilebilir, {len(manual)} manuel.")
    for tech in manual:
        print(f"  - {tech.id} {tech.name} (manuel): {tech.test_approach}")
    return 0


def cmd_knowledge(args) -> int:
    if args.action == "fetch":
        knowledge = AttackKnowledge(domain=args.domain)
        path = knowledge.fetch(force=args.force)
        print(f"indirildi: {path} ({path.stat().st_size / 1e6:.1f} MB)")
        return 0

    if args.action == "atlas":
        for tech in atlas.ATLAS.values():
            mode = "manuel" if tech.manual else "otomatik"
            print(f"{tech.id:<10} {tech.tactic:<16} {mode:<9} {tech.name}")
        return 0

    if args.action == "search":
        for info in knowledge.search(args.query):
            print(f"{info['id']:<10} {info['name']}  ({', '.join(info['tactics'])})")
        return 0

    info = knowledge.technique(args.technique)
    if not info:
        print(f"teknik bulunamadı: {args.technique}", file=sys.stderr)
        return 2
    print(f"{info['id']}  {info['name']}")
    print(f"taktikler : {', '.join(info['tactics'])}")
    print(f"platformlar: {', '.join(info['platforms'])}")
    print(f"url       : {info['url']}")
    if info["detection"]:
        print(f"\ntespit    : {info['detection'][:800]}")
    playbook = mapping.get(info["id"])
    if playbook:
        print(f"\nplaybook  : {playbook.name} ({len(playbook.steps)} adım)")
        for step in playbook.steps:
            print(f"  - {step.tool}.{step.capability} [{step.risk.label}]")
    else:
        print("\nplaybook  : yok (manuel)")
    return 0


def cmd_router(args) -> int:
    router = Router(endpoint=args.endpoint, model=args.model)
    intent = router.route(args.text)
    print(json.dumps(
        {
            "objective": intent.objective,
            "targets": list(intent.targets),
            "techniques": list(intent.techniques),
            "rationale": intent.rationale,
            "source": intent.source,
            "notes": list(intent.notes),
        },
        ensure_ascii=False,
        indent=2,
    ))
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
        try:
            results = executor.run(plan)
        except ScopeViolation as exc:
            print(f"\nKAPSAM İHLALİ - plan durduruldu: {exc}", file=sys.stderr)
            return 2
        except PolicyDenied as exc:
            print(f"\nPOLİTİKA REDDİ - plan durduruldu: {exc}", file=sys.stderr)
            return 2

        print()
        for result in results:
            print(f"  {result.summary()}")
            if result.status == "dry-run":
                print(f"    {result.detail}")
            elif result.detail:
                print(f"    - {result.detail}")
            if result.parsed:
                preview = json.dumps(result.parsed, ensure_ascii=False)
                print(f"    - {preview[:600]}{'...' if len(preview) > 600 else ''}")
        print(f"\n  denetim kaydı: {args.audit}")

    return exit_code


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kalkan",
        description="ATT&CK/ATLAS haritalı güvenlik orchestrasyon çekirdeği",
    )
    parser.add_argument("--scope", default="scope.json", help="kapsam dosyası (JSON)")
    parser.add_argument("--audit", default=DEFAULT_AUDIT, help="denetim kaydı yolu")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scope = sub.add_parser("scope", help="kapsamı göster veya bir hedefi denetle")
    p_scope.add_argument("action", choices=["show", "check"], nargs="?", default="show")
    p_scope.add_argument("target", nargs="?", default="")
    p_scope.add_argument("--risk", default="passive")
    p_scope.set_defaults(func=cmd_scope)

    p_tools = sub.add_parser("tools", help="kayıtlı araçları listele")
    p_tools.add_argument("--json", action="store_true")
    p_tools.set_defaults(func=cmd_tools)

    p_cov = sub.add_parser("coverage", help="teknik kapsamını ve araç hazırlığını göster")
    p_cov.add_argument("--json", action="store_true")
    p_cov.set_defaults(func=cmd_coverage)

    p_know = sub.add_parser("knowledge", help="ATT&CK/ATLAS bilgi tabanı")
    p_know.add_argument("action", choices=["fetch", "search", "show", "atlas"])
    p_know.add_argument("query", nargs="?", default="")
    p_know.add_argument("--technique", default="")
    p_know.add_argument("--domain", default="enterprise", choices=["enterprise", "mobile", "ics"])
    p_know.add_argument("--force", action="store_true")
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

    p_router = sub.add_parser("router", help="modelin niyet çıkarımını gör")
    p_router.add_argument("text")
    p_router.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    p_router.add_argument("--model", default=DEFAULT_MODEL)
    p_router.set_defaults(func=cmd_router)

    for name, func, help_text in (
        ("plan", cmd_plan, "plan üret (çalıştırmaz)"),
        ("run", cmd_run, "planı kapsam/politika denetimiyle çalıştır"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("text", nargs="?", default="")
        p.add_argument("--technique", action="append", default=[], help="teknik kimliği (tekrarlanabilir)")
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


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())