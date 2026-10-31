"""IDOR / kirik erisim kontrolu (webprobe.idor_probe) testleri.

Gercek ag yok: _request monkeypatch ile sahte yanitlar uretilir."""

import unittest

from kalkan.adapters.webprobe import HttpResponse, WebProbeAdapter
from kalkan.models import Action, Risk


def _mk(adapter, responder):
    adapter._request = responder  # type: ignore[assignment]


class TestIdorProbe(unittest.TestCase):
    def _run(self, target, responder, **args):
        a = WebProbeAdapter()
        _mk(a, responder)
        action = Action(tool="webprobe", capability="idor_probe", target=target,
                        args=args, risk=Risk.INTRUSIVE)
        return a._idor(action)

    def test_detects_horizontal_enumeration(self):
        def resp(url, **kw):
            return HttpResponse(url=url, status=200, body="user-data-" + url[-4:])
        out = self._run("http://example.com/users/1001", resp)
        self.assertTrue(out["vulnerable"])
        checks = {f["check"] for f in out["findings"]}
        self.assertIn("idor_enumeration", checks)

    def test_no_finding_when_forbidden(self):
        def resp(url, **kw):
            if url.endswith("/1001"):
                return HttpResponse(url=url, status=200, body="mine")
            return HttpResponse(url=url, status=403, body="forbidden")
        out = self._run("http://example.com/users/1001", resp)
        self.assertFalse(out["vulnerable"])
        self.assertFalse([f for f in out["findings"] if f["check"] == "idor_enumeration"])

    def test_missing_authentication(self):
        def resp(url, headers=None, **kw):
            return HttpResponse(url=url, status=200, body="same-body")
        out = self._run("http://example.com/profile?id=5", resp,
                        cookie="session=abc", ids="5")
        checks = {f["check"] for f in out["findings"]}
        self.assertIn("missing_authentication", checks)

    def test_bola_two_sessions_critical(self):
        def resp(url, headers=None, **kw):
            return HttpResponse(url=url, status=200, body="A-object")
        out = self._run("http://example.com/api/orders/42", resp,
                        cookie="A", cookie_b="B", ids="42")
        crit = [f for f in out["findings"] if f["check"] == "bola_horizontal"]
        self.assertTrue(crit)
        self.assertEqual(crit[0]["severity"], "critical")

    def test_no_object_id_graceful(self):
        def resp(url, **kw):
            return HttpResponse(url=url, status=200, body="x")
        out = self._run("http://example.com/", resp)
        self.assertEqual(out["findings"], [])
        self.assertIn("note", out)

    def test_query_param_detection(self):
        def resp(url, **kw):
            return HttpResponse(url=url, status=200, body="row-" + url[-2:])
        out = self._run("http://example.com/item?id=10&lang=tr", resp)
        self.assertEqual(out["param"], "id")
        self.assertEqual(out["object_id"], "10")


if __name__ == "__main__":
    unittest.main()
