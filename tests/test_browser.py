"""Browser (CDP) adaptoru icin ag/ tarayici gerektirmeyen birim testler.

Canli CDP/WebSocket yolu ayrica gercek Chrome ile smoke-test edildi; burada
saf yardimcilar ve 'unavailable' davranisi test edilir."""

import unittest

from kalkan.adapters.browser import BrowserAdapter, _norm_url
from kalkan.models import Action, Risk


class TestNormUrl(unittest.TestCase):
    def test_prepends_http_for_bare_host(self):
        self.assertEqual(_norm_url("example.com"), "http://example.com")
        self.assertEqual(_norm_url("example.com/a"), "http://example.com/a")

    def test_preserves_scheme(self):
        self.assertEqual(_norm_url("https://x.y"), "https://x.y")
        self.assertEqual(_norm_url("data:text/html,<h1>x</h1>"), "data:text/html,<h1>x</h1>")
        self.assertEqual(_norm_url("file:///tmp/a.html"), "file:///tmp/a.html")


class TestCollectNetwork(unittest.TestCase):
    def test_classifies_xhr_and_console(self):
        a = BrowserAdapter()
        events = [
            {"method": "Network.requestWillBeSent",
             "params": {"requestId": "1", "type": "XHR",
                        "request": {"url": "https://a/api/users", "method": "GET"}}},
            {"method": "Network.responseReceived",
             "params": {"requestId": "1", "response": {"status": 200, "mimeType": "application/json"}}},
            {"method": "Network.requestWillBeSent",
             "params": {"requestId": "2", "type": "Image",
                        "request": {"url": "https://a/logo.png", "method": "GET"}}},
            {"method": "Runtime.consoleAPICalled",
             "params": {"type": "error", "args": [{"value": "boom"}]}},
        ]
        network, xhr, console = a._collect_network(events)
        self.assertEqual(len(network), 2)
        self.assertEqual(len(xhr), 1)
        self.assertTrue(xhr[0]["url"].endswith("/api/users"))
        self.assertEqual(xhr[0]["status"], 200)
        self.assertEqual(console[0]["type"], "error")
        self.assertEqual(console[0]["text"], "boom")


class TestUnavailable(unittest.TestCase):
    def test_unavailable_when_no_browser(self):
        a = BrowserAdapter()
        a._bin_cache = ""
        self.assertFalse(a.available())
        r = a.run(Action("browser", "dom_render", "http://example.com", {}, Risk.ACTIVE))
        self.assertEqual(r.status, "unavailable")

    def test_dry_run_mentions_capability(self):
        a = BrowserAdapter()
        out = a.dry_run(Action("browser", "js_eval", "http://example.com", {}, Risk.ACTIVE))
        self.assertIn("js_eval", out)


if __name__ == "__main__":
    unittest.main()
