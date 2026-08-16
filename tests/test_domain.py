import tempfile
import unittest
from pathlib import Path

from lordms_recon.domain import build_output_folder, validate_domain


class DomainValidationTests(unittest.TestCase):
    def test_accepts_and_normalizes_hostname(self):
        self.assertEqual(validate_domain("API.Example.COM"), "api.example.com")
        self.assertEqual(validate_domain("türkiye.example"), "xn--trkiye-3ya.example")

    def test_rejects_urls_paths_ports_and_wildcards(self):
        invalid = [
            "../../../tmp/result", "example.com/../../x", "https://example.com",
            r"example.com\..\x", "example.com:8080", "*.example.com",
            "localhost", "example.com.",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_domain(value)

    def test_output_folder_remains_below_selected_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder, domain = build_output_folder("API.Example.com", temp_dir)
            self.assertEqual(domain, "api.example.com")
            self.assertEqual(folder, Path(temp_dir).resolve() / "recon_api.example.com")


if __name__ == "__main__":
    unittest.main()
