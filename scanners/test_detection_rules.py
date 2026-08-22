import unittest

from common import response_contains_sql_errors
from tech_fingerprint import detect_from_text


class SqlErrorSignatureTests(unittest.TestCase):
    def test_matches_common_mysql_error_without_a_trailing_product_name(self):
        matched, label = response_contains_sql_errors(
            "You have an error in your SQL syntax; check the manual that corresponds to your server version"
        )

        self.assertTrue(matched)
        self.assertEqual(label, "MySQL syntax error")


class TechnologyFingerprintTests(unittest.TestCase):
    def test_generic_php_header_does_not_imply_laravel(self):
        detected = detect_from_text("<html></html>", {"X-Powered-By": "PHP/8.2"})

        self.assertIn("PHP", detected)
        self.assertNotIn("Laravel", detected)

    def test_laravel_cookie_remains_a_specific_signal(self):
        detected = detect_from_text("laravel_session", {})

        self.assertIn("Laravel", detected)


if __name__ == "__main__":
    unittest.main()
