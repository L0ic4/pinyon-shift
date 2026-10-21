import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "shader_discovery", Path(__file__).parents[1] / "discover-fh1-shaders.py")
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)

NAME = "shader_0000000000000001_0000000000000002_0000000000000003.spv"


def capture(root):
    (root / NAME).touch()
    surface = {"key": "12345678", "depth": False, "slot": 1, "width": 1280,
               "height": 720, "samples": 1, "format": 0}
    draw = {"frame": 300, "vertex": "", "pixel": NAME, "hud": True, "surfaces": [surface]}
    (root / "draws.jsonl").write_text(json.dumps(draw) + "\n" + json.dumps(draw) + "\n")


class ShaderDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        capture(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_lists_exact_identity_and_surfaces(self):
        entries = discovery.discover(self.root)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["draws"], [1, 2])
        self.assertEqual(entries[0]["hud_draws"], [1, 2])
        self.assertEqual(len(entries[0]["surfaces"]), 1)
        self.assertEqual(entries[0]["translated_hash"], "0000000000000003")

    def test_stale_translation_is_distinct_from_unseen_shader(self):
        shaders = self.root / "shaders"
        shaders.mkdir()
        names = [NAME, NAME.replace("0003.spv", "0004.spv"),
                 NAME.replace("0001_", "0005_"), "shader_bad.spv"]
        for name in names:
            (shaders / name).touch()
        checks = {row["file"]: row["status"] for row in
                  discovery.check_mod(discovery.discover(self.root), shaders)}
        self.assertEqual([checks[name] for name in names], [
            "matches capture", "stale translation", "not seen in this frame", "invalid filename"])

    def test_missing_shader_and_empty_capture_fail(self):
        (self.root / NAME).unlink()
        with self.assertRaisesRegex(ValueError, "missing or invalid"):
            discovery.discover(self.root)
        (self.root / "draws.jsonl").write_text("")
        with self.assertRaisesRegex(ValueError, "no shaders"):
            discovery.discover(self.root)


if __name__ == "__main__":
    unittest.main()
