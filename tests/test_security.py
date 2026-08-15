import tempfile
import unittest
from pathlib import Path

from recon_prime import build_output_folder, generate_html, validate_domain


class DomainValidationTests(unittest.TestCase):
    def test_accepts_and_normalizes_valid_domains(self):
        self.assertEqual(validate_domain("API.Example.COM"), "api.example.com")
        self.assertEqual(validate_domain("türkiye.example"), "xn--trkiye-3ya.example")

    def test_rejects_path_and_url_inputs(self):
        invalid_domains = [
            "../../../tmp/result",
            "example.com/../../x",
            "https://example.com",
            r"example.com\..\x",
            "example.com:8080",
        ]
        for domain in invalid_domains:
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError):
                    validate_domain(domain)

    def test_rejects_malformed_domains(self):
        invalid_domains = ["", " example.com", "example.com ", "example..com", "-example.com", "localhost"]
        for domain in invalid_domains:
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError):
                    validate_domain(domain)

    def test_output_folder_is_directly_below_selected_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder, domain = build_output_folder("API.Example.com", temp_dir)
            self.assertEqual(domain, "api.example.com")
            self.assertEqual(folder, Path(temp_dir).resolve() / "recon_api.example.com")
            self.assertEqual(folder.parent, Path(temp_dir).resolve())

    def test_invalid_domain_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                build_output_folder("../../outside", temp_dir)
            self.assertEqual(list(Path(temp_dir).iterdir()), [])


class HtmlReportTests(unittest.TestCase):
    def test_escapes_all_dynamic_report_values(self):
        target = {
            "url": "https://example.com/<script>alert(1)</script>?a=1&b=2",
            "status_code": '<img src=x onerror="alert(2)">',
            "score": "20<script>",
            "risk": 'HIGH\" onclick=\"alert(3)',
            "content_length": "1<2",
            "reasons": ["reason <script>alert(4)</script>", 'quoted "value"'],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = generate_html("<script>alert(0)</script>.example", [target], temp_dir)
            report = Path(report_path).read_text(encoding="utf-8")

        self.assertNotIn("<script>", report)
        self.assertNotIn("<img src=x", report)
        self.assertNotIn('onclick="alert(3)', report)
        self.assertIn("&lt;script&gt;alert(0)&lt;/script&gt;.example", report)
        self.assertIn("?a=1&amp;b=2", report)
        self.assertIn("&lt;img src=x onerror=&quot;alert(2)&quot;&gt;", report)
        self.assertIn('<td class="LOW">LOW</td>', report)
        self.assertIn("reason &lt;script&gt;alert(4)&lt;/script&gt;", report)

    def test_preserves_allowed_risk_class(self):
        target = {
            "url": "https://example.com",
            "status_code": 200,
            "score": 40,
            "risk": "HIGH",
            "content_length": 123,
            "reasons": ["Standart"],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = generate_html("example.com", [target], temp_dir)
            report = Path(report_path).read_text(encoding="utf-8")

        self.assertIn('<td class="HIGH">HIGH</td>', report)


if __name__ == "__main__":
    unittest.main()
