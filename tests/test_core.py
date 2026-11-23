import unittest

from http_strict_transport_security_tools import HSTSPolicy, parse_hsts


class ParseHSTSTests(unittest.TestCase):
    def test_absent_header(self):
        policy = parse_hsts(None)
        self.assertIsNone(policy.max_age)
        self.assertFalse(policy.include_subdomains)
        self.assertFalse(policy.preload)

    def test_empty_header(self):
        policy = parse_hsts("")
        self.assertIsNone(policy.max_age)
        self.assertFalse(policy.include_subdomains)
        self.assertFalse(policy.preload)

    def test_only_max_age(self):
        policy = parse_hsts("max-age=31536000")
        self.assertEqual(policy.max_age, 31536000)
        self.assertFalse(policy.include_subdomains)
        self.assertFalse(policy.preload)

    def test_all_directives(self):
        policy = parse_hsts("max-age=31536000; includeSubDomains; preload")
        self.assertEqual(policy.max_age, 31536000)
        self.assertTrue(policy.include_subdomains)
        self.assertTrue(policy.preload)

    def test_case_insensitive_directive_names(self):
        policy = parse_hsts("max-age=100; INCLUDESUBDOMAINS; PreLoad")
        self.assertEqual(policy.max_age, 100)
        self.assertTrue(policy.include_subdomains)
        self.assertTrue(policy.preload)

    def test_whitespace_is_trimmed(self):
        policy = parse_hsts("  max-age = 42 ;  includeSubDomains ; preload  ")
        self.assertEqual(policy.max_age, 42)
        self.assertTrue(policy.include_subdomains)
        self.assertTrue(policy.preload)

    def test_missing_max_age(self):
        policy = parse_hsts("includeSubDomains")
        self.assertIsNone(policy.max_age)
        self.assertTrue(policy.include_subdomains)
        self.assertFalse(policy.preload)

    def test_malformed_max_age(self):
        policy = parse_hsts("max-age=abc")
        self.assertEqual(policy.max_age, -1)
        self.assertFalse(policy.include_subdomains)
        self.assertFalse(policy.preload)

    def test_negative_max_age(self):
        policy = parse_hsts("max-age=-5")
        self.assertEqual(policy.max_age, -1)

    def test_zero_max_age(self):
        policy = parse_hsts("max-age=0")
        self.assertEqual(policy.max_age, 0)

    def test_duplicate_directives_last_wins_for_max_age(self):
        policy = parse_hsts("max-age=10; max-age=20")
        self.assertEqual(policy.max_age, 20)

    def test_duplicate_flags_remain_true(self):
        policy = parse_hsts("includeSubDomains; includeSubDomains")
        self.assertTrue(policy.include_subdomains)

    def test_unknown_directives_are_ignored(self):
        policy = parse_hsts("max-age=5; foo=bar; baz")
        self.assertEqual(policy.max_age, 5)
        self.assertFalse(policy.include_subdomains)
        self.assertFalse(policy.preload)

    def test_empty_parts_are_ignored(self):
        policy = parse_hsts(";; max-age=7 ;; preload ;")
        self.assertEqual(policy.max_age, 7)
        self.assertTrue(policy.preload)

    def test_max_age_with_plus_sign(self):
        # int() accepts a leading plus; RFC 6797 does not, but we keep the
        # parser permissive and document the result.
        policy = parse_hsts("max-age=+60")
        self.assertEqual(policy.max_age, 60)

    def test_max_age_with_internal_whitespace(self):
        policy = parse_hsts("max-age= 60")
        self.assertEqual(policy.max_age, 60)

    def test_returns_hsts_policy_instance(self):
        policy = parse_hsts("max-age=1")
        self.assertIsInstance(policy, HSTSPolicy)

    def test_frozen_dataclass(self):
        policy = parse_hsts("max-age=1")
        with self.assertRaises(Exception):
            policy.max_age = 2  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
