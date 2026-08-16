import tempfile
import unittest
from pathlib import Path

from lordms_recon.models import Target
from lordms_recon.reporting import write_html_report, write_json_report


class ReportTests(unittest.TestCase):
    def test_html_escapes_untrusted_values_and_risk_class(self):
        target = Target(
            url='https://example.com/?q=<script>alert(1)</script>&x="',
            title='<img src=x onerror="alert(2)">', webserver="<server>",
            technologies=['quoted "value"'], risk='HIGH" onclick="alert(3)',
            reasons=["<script>reason</script>"],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            report = write_html_report("example.com", [target], Path(temp_dir)).read_text(encoding="utf-8")
        self.assertNotIn("<script>", report)
        self.assertNotIn("<img src=x", report)
        self.assertNotIn('onclick="alert(3)', report)
        self.assertIn('<span class="badge low">LOW</span>', report)

    def test_json_report_is_written(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = write_json_report("example.com", [Target(url="https://example.com")], Path(temp_dir))
            self.assertIn('"target_count": 1', path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

