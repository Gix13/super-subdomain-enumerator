import importlib.util
import pathlib
import sys
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "SuperSubdomainEnumerator.py"
SPEC = importlib.util.spec_from_file_location("super_subdomain_enumerator", MODULE_PATH)
enumerator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = enumerator
SPEC.loader.exec_module(enumerator)


class HelperTests(unittest.TestCase):
    def test_safe_name_normalizes_path_separators(self):
        self.assertEqual(enumerator.safe_name("https://demo.example:443"), "https___demo.example_443")

    def test_ssrf_key_heuristics(self):
        for key in ("url", "callback", "redirect_uri", "imageUrl"):
            with self.subTest(key=key):
                self.assertTrue(enumerator._is_ssrfy_key(key))
        self.assertFalse(enumerator._is_ssrfy_key("page"))

    def test_query_replacement_preserves_non_candidate_values(self):
        source = "https://demo.example/view?page=2&url=https%3A%2F%2Foriginal.example"
        result = enumerator._python_qsreplace_line(source, "https://oast.example/probe")

        self.assertIn("page=2", result)
        self.assertIn("oast.example", result)
        self.assertNotIn("original.example", result)

    def test_parse_and_save_keeps_only_requested_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "raw.txt"
            source.write_text("https://api.example.com/x\nhttps://outside.test/x\n")

            found = enumerator.parse_and_save(
                str(source), "clean.txt", "example.com", directory
            )

            self.assertEqual(found, {"api.example.com"})


if __name__ == "__main__":
    unittest.main()
