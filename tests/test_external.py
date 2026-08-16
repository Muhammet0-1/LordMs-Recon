import subprocess
import unittest
from unittest.mock import patch

from lordms_recon.external import ToolError, discover_subdomains, probe_http, run_command


class CommandTests(unittest.TestCase):
    @patch("lordms_recon.external.subprocess.run")
    def test_surfaces_nonzero_exit_and_stderr(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(["tool"], 2, stdout="", stderr="bad flag")
        with self.assertRaisesRegex(ToolError, "bad flag"):
            run_command(["tool"])

    @patch("lordms_recon.external.resolve_binary", return_value="subfinder")
    @patch("lordms_recon.external.run_command")
    def test_filters_invalid_and_out_of_scope_subdomains(self, command_mock, _resolve_mock):
        command_mock.return_value = "api.example.com\noutside.example.net\nhttps://bad.example.com\nAPI.EXAMPLE.COM\n"
        result = discover_subdomains("example.com", binary=None, timeout=10)
        self.assertEqual(result, ["api.example.com"])

    @patch("lordms_recon.external.resolve_binary", return_value="httpx")
    @patch("lordms_recon.external.run_command")
    def test_skips_malformed_httpx_lines_without_desynchronizing(self, command_mock, _resolve_mock):
        command_mock.return_value = "\n".join([
            '{"url":"https://one.example.com","status_code":200}',
            "not-json",
            '{"url":"https://two.example.com","status_code":500}',
        ])
        targets, warnings = probe_http(["one.example.com", "two.example.com"], binary=None, timeout=10)
        self.assertEqual([target.status_code for target in targets], [200, 500])
        self.assertEqual(len(warnings), 1)

    @patch("lordms_recon.external.resolve_binary", return_value="httpx")
    @patch("lordms_recon.external.run_command")
    def test_rejects_out_of_scope_httpx_url(self, command_mock, _resolve_mock):
        command_mock.return_value = '{"url":"https://outside.example.net","status_code":200}'
        targets, warnings = probe_http(["inside.example.com"], binary=None, timeout=10)
        self.assertEqual(targets, [])
        self.assertIn("outside the discovered scope", warnings[0])


if __name__ == "__main__":
    unittest.main()
