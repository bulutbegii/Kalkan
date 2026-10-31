import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kalkan.adapters import load_default_registry
from kalkan.audit import AuditLog
from kalkan.models import Action, Risk
from kalkan.orchestrator.executor import Executor
from kalkan.orchestrator.planner import plan
from kalkan.policy import Policy, PolicyDenied
from kalkan.scope import Scope, ScopeGuard, ScopeViolation


def guard(**overrides) -> ScopeGuard:
    base = dict(
        name="t",
        authorized_by="t",
        ticket="t",
        expires=datetime.now(timezone.utc) + timedelta(days=1),
        allow_cidrs=("10.0.0.0/24",),
        allow_domains=("example.com",),
        allow_ports=(),
        deny_cidrs=(),
        max_risk="intrusive",
    )
    base.update(overrides)
    return ScopeGuard(Scope(**base))


class TestExecutor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = AuditLog(Path(self.tmp.name) / "audit.jsonl")
        self.registry = load_default_registry()

    def tearDown(self):
        self.tmp.cleanup()

    def _executor(self, scope=None, dry_run=True, approver=lambda a: True, **policy_kwargs) -> Executor:
        return Executor(
            scope=scope or guard(),
            policy=Policy(**policy_kwargs),
            audit=self.audit,
            registry=self.registry,
            approver=approver,
            dry_run=dry_run,
        )

    def test_dry_run_produces_commands(self):
        p = plan("kesif", "10.0.0.5", techniques=["T1046"], registry=self.registry)
        results = self._executor().run(p)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.status == "dry-run" for r in results))
        self.assertIn("nmap", results[0].detail)

    def test_audit_written(self):
        p = plan("kesif", "10.0.0.5", techniques=["T1046"], registry=self.registry)
        self._executor().run(p)
        ok, message = self.audit.verify()
        self.assertTrue(ok, message)

    def test_scope_violation_aborts(self):
        p = plan("kesif", "192.168.1.1", techniques=["T1046"], registry=self.registry)
        with self.assertRaises(ScopeViolation):
            self._executor().run(p)

    def test_scope_violation_recorded(self):
        p = plan("kesif", "192.168.1.1", techniques=["T1046"], registry=self.registry)
        with self.assertRaises(ScopeViolation):
            self._executor().run(p)
        events = [r["event"] for r in self.audit.tail(10)]
        self.assertIn("scope.violation", events)

    def test_policy_blocks_intrusive_without_approver(self):
        p = plan("ilk erisim", "10.0.0.5", techniques=["T1190"], registry=self.registry,
                 overrides={"module": "auxiliary/scanner/smb/smb_version"})
        executor = Executor(
            scope=guard(),
            policy=Policy(allow_intrusive=True),
            audit=self.audit,
            registry=self.registry,
            approver=None,
            dry_run=True,
        )
        with self.assertRaises(PolicyDenied):
            executor.run(p)

    def test_policy_blocks_when_user_refuses(self):
        p = plan("ilk erisim", "10.0.0.5", techniques=["T1190"], registry=self.registry,
                 overrides={"module": "auxiliary/scanner/smb/smb_version"})
        with self.assertRaises(PolicyDenied):
            self._executor(approver=lambda a: False).run(p)

    def test_destructive_blocked_by_default(self):
        executor = self._executor()
        action = Action(tool="msf", capability="exploit_run", target="10.0.0.5",
                        risk=Risk.DESTRUCTIVE, technique="T1190")
        with self.assertRaises(PolicyDenied):
            executor.policy.check(action, lambda a: True)

    def test_unresolved_variable_is_denied_not_crashed(self):
        p = plan("kesif", "10.0.0.5", techniques=["T1046"], registry=self.registry)
        executor = self._executor()
        results = executor.run(p)
        self.assertEqual(results[0].status, "dry-run")

    def test_context_feeds_next_step(self):
        executor = self._executor()
        executor.context["open_ports"] = [80, 443]
        p = plan("kesif", "10.0.0.5", techniques=["T1046"], registry=self.registry)
        results = executor.run(p)
        self.assertIn("80,443", results[1].detail)


if __name__ == "__main__":
    unittest.main()
