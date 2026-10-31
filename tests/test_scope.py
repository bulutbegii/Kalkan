import unittest
from datetime import datetime, timedelta, timezone

from kalkan.models import Risk
from kalkan.scope import Scope, ScopeGuard, ScopeViolation, parse_target


def make_scope(**overrides) -> Scope:
    base = dict(
        name="test",
        authorized_by="test",
        ticket="T-1",
        expires=datetime.now(timezone.utc) + timedelta(days=1),
        allow_cidrs=("10.0.0.0/24",),
        allow_domains=("example.com",),
        allow_ports=(80, 443),
        deny_cidrs=("10.0.0.66/32",),
        max_risk="intrusive",
    )
    base.update(overrides)
    return Scope(**base)


class TestParseTarget(unittest.TestCase):
    def test_ip(self):
        self.assertEqual(parse_target("10.0.0.5"), ("ip", "10.0.0.5", None))

    def test_cidr(self):
        self.assertEqual(parse_target("10.0.0.0/24"), ("cidr", "10.0.0.0/24", None))

    def test_url(self):
        self.assertEqual(parse_target("https://example.com:8443/x"), ("domain", "example.com", 8443))

    def test_host_port(self):
        self.assertEqual(parse_target("example.com:443"), ("domain", "example.com", 443))

    def test_case_and_dot(self):
        self.assertEqual(parse_target("EXAMPLE.com."), ("domain", "example.com", None))


class TestScopeGuard(unittest.TestCase):
    def setUp(self):
        self.guard = ScopeGuard(make_scope())

    def test_allowed_ip(self):
        self.assertEqual(self.guard.check("10.0.0.5"), "10.0.0.5")

    def test_ip_outside_range(self):
        with self.assertRaises(ScopeViolation):
            self.guard.check("192.168.1.1")

    def test_denied_ip_wins(self):
        with self.assertRaises(ScopeViolation):
            self.guard.check("10.0.0.66")

    def test_allowed_domain_and_subdomain(self):
        self.assertEqual(self.guard.check("example.com"), "example.com")
        self.assertEqual(self.guard.check("api.example.com"), "api.example.com")

    def test_domain_suffix_lookalike_rejected(self):
        with self.assertRaises(ScopeViolation):
            self.guard.check("notexample.com")

    def test_port_not_allowed(self):
        with self.assertRaises(ScopeViolation):
            self.guard.check("10.0.0.5", port=22)

    def test_port_allowed(self):
        self.assertEqual(self.guard.check("10.0.0.5", port=443), "10.0.0.5:443")

    def test_risk_ceiling(self):
        guard = ScopeGuard(make_scope(max_risk="active"))
        with self.assertRaises(ScopeViolation):
            guard.check("10.0.0.5", risk=Risk.INTRUSIVE)

    def test_expired_scope(self):
        guard = ScopeGuard(make_scope(expires=datetime.now(timezone.utc) - timedelta(hours=1)))
        with self.assertRaises(ScopeViolation):
            guard.check("10.0.0.5")

    def test_empty_scope(self):
        guard = ScopeGuard(make_scope(allow_cidrs=(), allow_domains=()))
        with self.assertRaises(ScopeViolation):
            guard.check("10.0.0.5")

    def test_cidr_target(self):
        self.assertEqual(self.guard.check("10.0.0.0/28"), "10.0.0.0/28")

    def test_cidr_overlapping_deny(self):
        with self.assertRaises(ScopeViolation):
            self.guard.check("10.0.0.64/28")


if __name__ == "__main__":
    unittest.main()
