import unittest

from lordms_recon.models import Target
from lordms_recon.scoring import apply_content_length_anomalies, score_target


class TargetModelTests(unittest.TestCase):
    def test_normalizes_httpx_record(self):
        target = Target.from_httpx(
            {"url": "https://api.example.com", "status_code": "403", "content_length": "42", "tech": "nginx"}
        )
        self.assertEqual(target.status_code, 403)
        self.assertEqual(target.content_length, 42)
        self.assertEqual(target.technologies, ["nginx"])

    def test_rejects_record_without_url(self):
        with self.assertRaises(ValueError):
            Target.from_httpx({"status_code": 200})

    def test_rejects_non_http_url(self):
        with self.assertRaises(ValueError):
            Target.from_httpx({"url": "javascript:alert(1)"})


class ScoringTests(unittest.TestCase):
    def test_scores_transparent_signals(self):
        target = score_target(Target(url="https://admin.example.com", status_code=403, title="Swagger UI"))
        self.assertEqual(target.score, 70)
        self.assertEqual(target.risk, "CRITICAL")
        self.assertEqual(len(target.reasons), 4)

    def test_applies_statistical_outlier_signal(self):
        targets = [score_target(Target(url=f"https://h{i}.example.com", content_length=value)) for i, value in enumerate([10, 10, 10, 10, 10, 1000])]
        apply_content_length_anomalies(targets)
        self.assertEqual(targets[-1].score, 20)
        self.assertEqual(targets[-1].risk, "MEDIUM")


if __name__ == "__main__":
    unittest.main()
