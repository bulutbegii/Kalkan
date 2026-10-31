import json
import tempfile
import unittest
from pathlib import Path

from kalkan.audit import AuditLog


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "audit.jsonl"
        self.log = AuditLog(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_chain_ok(self):
        self.log.append("plan.start", target="10.0.0.5")
        self.log.append("action.start", action="nmap.port_scan")
        ok, message = self.log.verify()
        self.assertTrue(ok, message)
        self.assertIn("2 kayıt", message)

    def test_chain_links(self):
        first = self.log.append("a")
        second = self.log.append("b")
        self.assertEqual(second["prev"], first["hash"])

    def test_tamper_detected(self):
        self.log.append("a", value=1)
        self.log.append("b", value=2)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["data"]["value"] = 999
        lines[0] = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, message = self.log.verify()
        self.assertFalse(ok)
        self.assertIn("değiştirilmiş", message)

    def test_deleted_line_detected(self):
        self.log.append("a")
        self.log.append("b")
        self.log.append("c")
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
        ok, message = self.log.verify()
        self.assertFalse(ok)
        self.assertIn("seq", message)

    def test_empty_log_is_valid(self):
        ok, _ = self.log.verify()
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
