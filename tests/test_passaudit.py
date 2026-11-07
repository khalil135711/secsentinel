import unittest

from secsentinel import passaudit


class PasswordTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(passaudit.audit_password("password123").rating, "very weak")

    def test_leetspeak_variant_caught(self):
        self.assertEqual(passaudit.audit_password("P@ssw0rd").rating, "very weak")

    def test_empty(self):
        self.assertEqual(passaudit.audit_password("").rating, "very weak")

    def test_keyboard_pattern_flagged(self):
        result = passaudit.audit_password("qwertyuiop")
        self.assertTrue(any("keyboard" in i for i in result.issues))
        self.assertIn(result.rating, ("very weak", "weak"))

    def test_sequence_and_repeat_flagged(self):
        issues = " ".join(passaudit.audit_password("Xk9aaaa1234!").issues)
        self.assertIn("repeated", issues)
        self.assertIn("sequence", issues)

    def test_strong_random_password(self):
        result = passaudit.audit_password("v9#Lq2!xT7mZ$eR4wB")
        self.assertEqual(result.rating, "strong")
        self.assertEqual(result.issues, [])

    def test_short_password_capped_at_fair(self):
        result = passaudit.audit_password("aB3$xY9!")
        self.assertIn(result.rating, ("very weak", "weak", "fair"))

    def test_mask_never_reveals_content(self):
        self.assertEqual(passaudit.mask("secret"), "******")
        self.assertNotIn("a", passaudit.mask("abcdefghijklmnop"))
        self.assertEqual(len(passaudit.mask("abcdefghijklmnop")), 12)


if __name__ == "__main__":
    unittest.main()
