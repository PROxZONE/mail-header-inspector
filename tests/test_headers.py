import unittest
from inspect_headers import inspect, domain, MAX_INPUT_BYTES


class HeaderTests(unittest.TestCase):
    def test_authentication_claim_is_never_trusted(self):
        report = inspect(b'From: alice@example.test\nAuthentication-Results: attacker.test; dkim=pass; spf=pass\n\n')
        self.assertFalse(report['authentication_results'][0]['trusted'])
        self.assertEqual(report['authentication_results'][0]['claims'][0]['reported_result'], 'pass')

    def test_mismatch_is_observation_not_phishing_verdict(self):
        report = inspect(b'From: alice@example.test\nReply-To: help@other.test\n\n')
        self.assertIn('legitimate services', report['observations'][0])
        self.assertNotIn('risk_score', report)

    def test_duplicate_from_and_missing_from(self):
        self.assertTrue(inspect(b'From: a@example.test\nFrom: b@example.test\n\n')['observations'])
        self.assertIn('No From', inspect(b'Subject: missing sender\n\n')['observations'][0])

    def test_unicode_domain_is_shown_in_ascii(self):
        self.assertEqual(domain('a@bücher.test'), 'xn--bcher-kva.test')

    def test_body_is_not_reported(self):
        self.assertNotIn('private body', str(inspect(b'From: a@example.test\n\nprivate body')))

    def test_empty_or_oversized_input_is_rejected(self):
        for raw in (b'', b'x' * (MAX_INPUT_BYTES + 1)):
            with self.assertRaises(ValueError):
                inspect(raw)


if __name__ == '__main__':
    unittest.main()
