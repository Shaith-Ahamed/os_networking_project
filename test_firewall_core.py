import os
import tempfile
import time
import unittest

import firewall_core as core


class PasswordTests(unittest.TestCase):
    def test_hash_roundtrip_and_salt(self):
        a, b = core.hash_password("s3cret-pass", 1000), core.hash_password("s3cret-pass", 1000)
        self.assertNotEqual(a, b)  # salted
        self.assertTrue(core.verify_password("s3cret-pass", a))
        self.assertFalse(core.verify_password("wrong", a))

    def test_garbage_hash_never_verifies(self):
        self.assertFalse(core.verify_password("x", "not-a-hash"))
        self.assertFalse(core.verify_password("x", "md5$1$00$00"))


class HelperTests(unittest.TestCase):
    def test_parse_duration(self):
        self.assertEqual(core.parse_duration("30s"), 30)
        self.assertEqual(core.parse_duration("10m"), 600)
        self.assertEqual(core.parse_duration("2h"), 7200)
        self.assertEqual(core.parse_duration("1d"), 86400)
        for bad in ("", "10", "m", "0m", "-5m", "1w"):
            with self.assertRaises(ValueError):
                core.parse_duration(bad)

    def test_ip_rules(self):
        self.assertTrue(core.valid_ip_rule("10.0.0.5"))
        self.assertTrue(core.valid_ip_rule("192.168.1.0/24"))
        self.assertFalse(core.valid_ip_rule("999.1.1.1"))
        self.assertFalse(core.valid_ip_rule("nonsense/99"))
        self.assertTrue(core.ip_in_rule("192.168.1.77", "192.168.1.0/24"))
        self.assertFalse(core.ip_in_rule("192.168.2.1", "192.168.1.0/24"))


class RulesTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, 'rules.json')
        self.rules = core.Rules(self.path)
        self.rules.load()

    def tearDown(self):
        self.dir.cleanup()

    def test_word_rule_does_not_match_inside_other_words(self):
        self.rules.add_keyword('ass', 'word')
        self.assertTrue(self.rules.check_message('what a class act').allowed)
        self.assertFalse(self.rules.check_message('what an ASS.').allowed)

    def test_substring_and_regex_rules(self):
        self.rules.add_keyword('bad', 'substring')
        self.rules.add_keyword(r'\d{4}-\d{4}', 'regex')
        self.assertFalse(self.rules.check_message('so badly').allowed)
        self.assertFalse(self.rules.check_message('card 1234-5678 here').allowed)
        self.assertTrue(self.rules.check_message('card 12-34').allowed)

    def test_redact_and_warn_actions(self):
        self.rules.add_keyword('secret', 'word', 'redact')
        self.rules.add_keyword('hmm', 'word', 'warn')
        verdict = self.rules.check_message('the Secret is hmm here')
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.text, 'the ****** is hmm here')
        self.assertTrue(verdict.redacted)
        self.assertEqual(verdict.warnings, ['hmm'])

    def test_block_beats_redact(self):
        self.rules.add_keyword('secret', 'word', 'redact')
        self.rules.add_keyword('evil', 'word', 'block')
        self.assertFalse(self.rules.check_message('secret evil').allowed)

    def test_bad_rules_rejected(self):
        for args in (('', 'word'), ('(', 'regex'), ('a*', 'regex'), ('x', 'nope'), ('x', 'word', 'nope')):
            with self.assertRaises(ValueError):
                self.rules.add_keyword(*args)

    def test_add_updates_and_remove_is_case_insensitive(self):
        self.assertEqual(self.rules.add_keyword('Foo', 'word'), 'added')
        self.assertEqual(self.rules.add_keyword('foo', 'substring'), 'updated')
        self.assertTrue(self.rules.remove_keyword('FOO'))
        self.assertFalse(self.rules.remove_keyword('foo'))

    def test_ip_block_cidr_and_equivalent_spellings(self):
        self.rules.add_ip_block('192.168.1.0/24')
        self.assertTrue(self.rules.ip_is_blocked('192.168.1.9'))
        self.assertFalse(self.rules.ip_is_blocked('192.168.2.9'))
        self.rules.add_ip_block('10.0.0.5')
        self.assertTrue(self.rules.remove_ip_block('10.0.0.5/32'))  # same rule, different spelling
        self.assertFalse(self.rules.ip_is_blocked('10.0.0.5'))

    def test_temporary_block_expires(self):
        self.rules.add_ip_block('10.1.1.1', duration=1)
        self.assertTrue(self.rules.ip_is_blocked('10.1.1.1'))
        time.sleep(1.1)
        self.assertFalse(self.rules.ip_is_blocked('10.1.1.1'))
        self.assertEqual(self.rules.snapshot()['blocked_ips'], [])

    def test_temporary_block_never_downgrades_permanent(self):
        self.rules.add_ip_block('10.2.2.2')
        self.assertEqual(self.rules.add_ip_block('10.2.2.2', duration=5), 'exists')
        self.assertIsNone(self.rules.snapshot()['blocked_ips'][0]['expires_in'])

    def test_allowlist_mode(self):
        self.assertEqual(self.rules.connection_allowed('8.8.8.8'), (True, ''))
        self.rules.add_allowed('192.168.1.0/24')
        self.rules.set_allowlist(True)
        self.assertTrue(self.rules.connection_allowed('192.168.1.5')[0])
        self.assertFalse(self.rules.connection_allowed('8.8.8.8')[0])
        self.rules.add_ip_block('192.168.1.5')  # a block still wins over the allowlist
        self.assertEqual(self.rules.connection_allowed('192.168.1.5'), (False, 'blocked'))

    def test_persistence_and_legacy_config(self):
        self.rules.add_keyword('x1', 'regex', 'warn')
        self.rules.add_ip_block('10.9.9.0/24')
        self.rules.add_ip_block('10.8.8.8', duration=3600)
        self.rules.add_allowed('1.2.3.4')
        self.rules.set_allowlist(True)
        again = core.Rules(self.path)
        again.load()
        self.assertEqual(again.snapshot()['keywords'], [{'pattern': 'x1', 'kind': 'regex', 'action': 'warn'}])
        self.assertTrue(again.ip_is_blocked('10.9.9.1') and again.ip_is_blocked('10.8.8.8'))
        self.assertTrue(again.allowlist_enabled)

        with open(self.path, 'w') as f:  # the original config format: plain strings
            f.write('{"blocked_keywords": ["blocked", "malware"], "blocked_ips": ["10.0.0.5", "bogus"]}')
        again.load()
        self.assertFalse(again.check_message('this is unblocked').allowed)  # legacy = substring
        self.assertTrue(again.ip_is_blocked('10.0.0.5'))  # and the bogus entry was skipped, not fatal


if __name__ == '__main__':
    unittest.main()
