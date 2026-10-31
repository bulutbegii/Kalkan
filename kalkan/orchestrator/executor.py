"""Executor - plani kapsam ve politika kapilarindan gecirerek uygular.

Her aksiyon icin sira:
  1. $degisken cozumleme (onceki adimlarin ciktisindan)
  2. ScopeGuard.check      -> kapsam disiysa plan durur
  3. Policy.check          -> onay yoksa plan durur
  4. AuditLog.append(start)
  5. adapter.run / dry_run
  6. AuditLog.append(result)
  7. parsed ciktiyi baglama yaz (sonraki adimlar kullanabilir)
"""

from __future__ import annotations

from typing import Any, Callable

from ..audit import AuditLog
from ..models import Action, ActionResult, Plan, Risk
from ..policy import Policy, PolicyDenied
from ..registry import Registry
from ..scope import ScopeGuard, ScopeViolation

Approver = Callable[[Action], bool]


class UnresolvedArgument(Exception):
    pass


class Executor:
    def __init__(
        self,
        scope: ScopeGuard,
        policy: Policy,
        audit: AuditLog,
        registry: Registry,
        approver: Approver | None = None,
        dry_run: bool = False,
        timeout: int = 300,
    ):
        self.scope = scope
        self.policy = policy
        self.audit = audit
        self.registry = registry
        self.approver = approver
        self.dry_run = dry_run
        self.timeout = timeout
        self.context: dict[str, Any] = {}

    def _materialize(self, action: Action) -> Action:
        resolved: dict[str, Any] = {}
        for key, value in action.args.items():
            if value is None:
                continue
            if isinstance(value, str) and value.startswith("$"):
                name = value[1:]
                if name not in self.context:
                    if self.dry_run:
                        value = f"<{name}:bekliyor>"
                    else:
                        raise UnresolvedArgument(
                            f"'{name}' bağımlılığı çözülemedi (önceki adım üretmedi)"
                        )
                else:
                    value = self.context[name]
            if isinstance(value, list):
                value = ",".join(str(v) for v in value)
            resolved[key] = value
        return Action(
            tool=action.tool,
            capability=action.capability,
            target=action.target,
            args=resolved,
            risk=action.risk,
            technique=action.technique,
            rationale=action.rationale,
        )

    def run(self, plan: Plan) -> list[ActionResult]:
        results: list[ActionResult] = []
        self.audit.append(
            "plan.start",
            objective=plan.objective,
            target=plan.target,
            actions=[a.key() for a in plan.actions],
            dry_run=self.dry_run,
        )

        for action in plan.actions:
            try:
                action = self._materialize(action)
            except UnresolvedArgument as exc:
                denied = ActionResult(action=action, status="denied", detail=str(exc))
                results.append(denied)
                self.audit.append("action.denied", action=action.key(), reason=str(exc))
                continue

            try:
                self.scope.check(action.target, risk=action.risk)
            except ScopeViolation as exc:
                self.audit.append("scope.violation", action=action.key(), target=action.target, reason=str(exc))
                raise

            try:
                self.policy.check(action, self.approver)
            except PolicyDenied as exc:
                self.audit.append("policy.denied", action=action.key(), reason=str(exc))
                raise

            self.audit.append(
                "action.start",
                action=action.key(),
                target=action.target,
                risk=action.risk.label,
                technique=action.technique,
                args=action.args,
            )

            adapter = self.registry.get(action.tool)
            if self.dry_run:
                command = adapter.dry_run(action)
                result = ActionResult(action=action, status="dry-run", detail=command)
            else:
                result = adapter.run(action, timeout=self.timeout)

            self.audit.append(
                "action.result",
                action=action.key(),
                status=result.status,
                duration_s=round(result.duration_s, 3),
                detail=result.detail,
            )
            results.append(result)
            self._absorb(result)

        self.audit.append("plan.finish", results=len(results), target=plan.target)
        return results

    def _absorb(self, result: ActionResult) -> None:
        for key, value in result.parsed.items():
            if isinstance(value, (str, int, float, bool)):
                self.context[key] = value
            elif isinstance(value, list) and all(isinstance(v, (str, int, float)) for v in value):
                self.context[key] = value
