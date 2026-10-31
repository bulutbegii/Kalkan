"""ATT&CK Navigator layer uretici testleri (ag gerekmez: include_all=False)."""

import unittest

from kalkan.knowledge import navigator


class TestNavigatorLayer(unittest.TestCase):
    def test_covered_only_layer_shape(self):
        layer, stats = navigator.build_layer(include_all=False)
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertTrue(stats["covered"] > 0)
        self.assertEqual(stats["all"], 0)
        self.assertEqual(len(layer["techniques"]), stats["covered"])
        for t in layer["techniques"]:
            self.assertIn("techniqueID", t)
            self.assertIn("color", t)
            self.assertTrue(t["enabled"])

    def test_atlas_techniques_excluded(self):
        layer, _ = navigator.build_layer(include_all=False)
        ids = [t["techniqueID"] for t in layer["techniques"]]
        self.assertFalse(any(i.startswith("AML.") for i in ids))
        self.assertIn("T1190", ids)

    def test_t1190_colored_by_max_risk(self):
        layer, _ = navigator.build_layer(include_all=False)
        t1190 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1190")
        self.assertEqual(t1190["score"], 100)
        self.assertEqual(t1190["color"], "#e4584f")

    def test_has_legend(self):
        layer, _ = navigator.build_layer(include_all=False)
        self.assertTrue(layer["legendItems"])


if __name__ == "__main__":
    unittest.main()
