import unittest

from kalkan.adapters.shodan import resolve_ip


class TestResolveIp(unittest.TestCase):
    def test_plain_ip(self):
        self.assertEqual(resolve_ip("1.2.3.4"), "1.2.3.4")

    def test_ip_in_url_with_port(self):
        self.assertEqual(resolve_ip("http://1.2.3.4:443/x"), "1.2.3.4")

    def test_ip_with_port(self):
        self.assertEqual(resolve_ip("1.2.3.4:8080"), "1.2.3.4")

    def test_localhost_resolves(self):
        self.assertTrue(resolve_ip("localhost").startswith("127."))


if __name__ == "__main__":
    unittest.main()
