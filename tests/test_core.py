import unittest

from webscope.core import Report, normalize_url, score


class WebScopeTests(unittest.TestCase):
    def test_normalize_defaults_to_https(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")

    def test_empty_url_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("   ")

    def test_clean_https_report_scores_full_marks(self):
        report = Report(
            url="https://example.com",
            status=200,
            ip=["93.184.216.34"],
            tls_version="TLSv1.3",
            cert_expires=None,
            cert_days_left=100,
            headers={},
            missing_security_headers=[],
            server=None,
            error=None,
        )
        self.assertEqual(score(report), 100)

    def test_http_and_missing_headers_reduce_score(self):
        report = Report(
            url="http://example.com",
            status=200,
            ip=[],
            tls_version=None,
            cert_expires=None,
            cert_days_left=None,
            headers={},
            missing_security_headers=["content-security-policy"],
            server=None,
            error=None,
        )
        self.assertEqual(score(report), 70)


if __name__ == "__main__":
    unittest.main()
