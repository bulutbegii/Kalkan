"""webprobe.source_recon (DevTools 'Sources' karsiligi) testleri.

Ag yok: _request monkeypatch ile HTML -> JS -> source map zinciri uretilir."""

import json
import unittest

from kalkan.adapters.webprobe import HttpResponse, WebProbeAdapter
from kalkan.models import Action, Risk

_HTML = '<html><head><script src="/static/app.js"></script></head><body>x</body></html>'
_JS = (
    'const AWS="AKIAIOSFODNN7EXAMPLE";\n'
    'fetch("/api/secret/users");\n'
    'axios.get("/v1/admin/config");\n'
    '//# sourceMappingURL=app.js.map\n'
)
_MAP = json.dumps({
    "version": 3,
    "sources": ["webpack:///src/app.js", "webpack:///src/lib/secret.js"],
    "sourcesContent": ["console.log('ok')", "const TOKEN='ghp_" + "a" * 36 + "';"],
})


def _responder(url, **kw):
    if url.endswith("/static/app.js.map"):
        return HttpResponse(url=url, status=200, body=_MAP)
    if url.endswith("/static/app.js"):
        return HttpResponse(url=url, status=200, body=_JS)
    if url.endswith("/.git/HEAD"):
        return HttpResponse(url=url, status=200, body="ref: refs/heads/main\n")
    if url.endswith("/.env") or url.endswith("/.svn/entries"):
        return HttpResponse(url=url, status=404, body="")
    return HttpResponse(url=url, status=200, body=_HTML)


class TestSourceRecon(unittest.TestCase):
    def _run(self):
        a = WebProbeAdapter()
        a._request = _responder  # type: ignore[assignment]
        action = Action(tool="webprobe", capability="source_recon",
                        target="http://example.com", args={}, risk=Risk.ACTIVE)
        return a._source_recon(action)

    def test_source_map_reconstructs_tree(self):
        out = self._run()
        self.assertEqual(out["sources_recovered"], 2)
        self.assertIn("webpack:///src/lib/secret.js", out["sources_tree"])
        self.assertTrue(any(f["check"] == "source_map_exposed" for f in out["findings"]))

    def test_secret_detected_in_js_and_map(self):
        out = self._run()
        secrets = [f for f in out["findings"] if f["check"] == "secret_in_source"]
        labels = " ".join(f["detail"] for f in secrets)
        self.assertIn("aws_access_key", labels)
        self.assertIn("github_token", labels)
        self.assertTrue(out["vulnerable"])

    def test_endpoints_extracted(self):
        out = self._run()
        self.assertIn("/api/secret/users", out["endpoints"])
        self.assertIn("/v1/admin/config", out["endpoints"])

    def test_exposed_git_repo(self):
        out = self._run()
        self.assertTrue(any(f["check"] == "exposed_source" and ".git" in f["detail"]
                            for f in out["findings"]))


if __name__ == "__main__":
    unittest.main()
