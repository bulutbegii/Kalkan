"""Deterministik planlayici.

Model burada yok. Teknik kimligi -> playbook -> aksiyon listesi.
Ayni girdi her zaman ayni plani uretir; test edilebilir olmasinin
sebebi bu.
"""

from __future__ import annotations

from typing import Any

from ..knowledge import mapping
from ..models import Action, Intent, Plan, Risk
from ..registry import Registry


def _resolve_args(step: mapping.Step, overrides: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    args = dict(step.args)
    for key, value in overrides.items():
        if key in args or key in step.required or key in step.accepts:
            args[key] = value
    missing = [k for k in step.required if not args.get(k)]
    return args, missing


def plan(
    objective: str,
    target: str,
    techniques: list[str] | None = None,
    tactic: str | None = None,
    registry: Registry | None = None,
    max_risk: Risk = Risk.INTRUSIVE,
    overrides: dict[str, Any] | None = None,
) -> Plan:
    overrides = overrides or {}
    result = Plan(objective=objective, target=target)

    selected: list[mapping.Playbook] = []
    if techniques:
        for tid in techniques:
            playbook = mapping.get(tid)
            if playbook is None:
                result.notes.append(f"{tid}: katalogda playbook yok (manuel veya uygulanmadı)")
                continue
            selected.append(playbook)
    elif tactic:
        selected = mapping.by_tactic(tactic)
        if not selected:
            result.notes.append(f"'{tactic}' taktiği için playbook yok")
    else:
        result.notes.append("teknik veya taktik belirtilmedi")

    seen: set[str] = set()
    for playbook in selected:
        for step in playbook.steps:
            args, missing = _resolve_args(step, overrides)
            if missing:
                result.notes.append(
                    f"{playbook.technique}: '{step.capability}' atlandı (eksik: {', '.join(missing)})"
                )
                continue
            if registry is not None and step.tool not in registry.names():
                result.notes.append(f"{playbook.technique}: '{step.tool}' kayıtlı değil, atlandı")
                continue
            if step.risk > max_risk:
                result.notes.append(
                    f"{playbook.technique}: '{step.capability}' risk tavanını aşıyor, atlandı"
                )
                continue
            action = Action(
                tool=step.tool,
                capability=step.capability,
                target=target,
                args=args,
                risk=step.risk,
                technique=playbook.technique,
                rationale=step.note or playbook.name,
            )
            if action.key() in seen:
                continue
            seen.add(action.key())
            result.actions.append(action)

    result.actions.sort(key=lambda a: (int(a.risk), a.tool))
    return result


def plan_for_intent(
    intent: Intent,
    registry: Registry,
    max_risk: Risk = Risk.INTRUSIVE,
    overrides: dict[str, Any] | None = None,
) -> list[Plan]:
    """Her hedef icin ayri plan. Coklu hedef destekli."""
    plans: list[Plan] = []
    for target in intent.targets or ("",):
        p = plan(
            objective=intent.objective,
            target=target,
            techniques=list(intent.techniques),
            registry=registry,
            max_risk=max_risk,
            overrides=overrides,
        )
        p.notes = list(intent.notes) + p.notes
        plans.append(p)
    return plans
