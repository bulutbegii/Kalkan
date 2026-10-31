import json
import tempfile
import unittest
from pathlib import Path

from kalkan.scope import ScopeViolation, add_to_scope_file


BASE = {
    "name": "t", "authorized_by": "x", "ticket": "T-1",
    "expires": "2099-12-31T23:59:59Z",
    "allow_cidrs": ["10.0.0.0/24"], "allow_domains": ["example.com"],
    "allow_ports": [80, 443],
}


class TestScopeAdd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "scope.json"
        self.path.write_text(json.dumps(BASE), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _read(self):
        return json.loads(self.path.read_text(encoding="utf-8"))

    def test_add_domain(self):
        info = add_to_scope_file(self.path, "https://biri.com.tr:8443/x")
        self.assertEqual(info["kind"], "domain")
        self.assertTrue(info["changed"])
        self.assertIn("biri.com.tr", self._read()["allow_domains"])
        self.assertIn(8443, self._read()["allow_ports"])

    def test_add_ip_becomes_host_route(self):
        info = add_to_scope_file(self.path, "192.168.1.9")
        self.assertEqual(info["kind"], "ip")
        self.assertIn("192.168.1.9/32", self._read()["allow_cidrs"])

    def test_add_cidr(self):
        add_to_scope_file(self.path, "172.16.0.0/16")
        self.assertIn("172.16.0.0/16", self._read()["allow_cidrs"])

    def test_idempotent(self):
        info = add_to_scope_file(self.path, "example.com")
        self.assertFalse(info["changed"])
        self.assertEqual(self._read()["allow_domains"].count("example.com"), 1)

    def test_preserves_other_fields(self):
        add_to_scope_file(self.path, "yeni.com")
        d = self._read()
        self.assertEqual(d["authorized_by"], "x")
        self.assertEqual(d["ticket"], "T-1")

    def test_missing_file_raises(self):
        with self.assertRaises(ScopeViolation):
            add_to_scope_file(Path(self.tmp.name) / "yok.json", "a.com")


if __name__ == "__main__":
    unittest.main()
