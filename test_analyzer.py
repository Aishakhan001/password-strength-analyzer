
import unittest

from password_analyzer import StrengthLevel, analyze_password


class TestPasswordAnalyzer(unittest.TestCase):
    def test_empty_password(self):
        result = analyze_password("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.strength, StrengthLevel.WEAK)

    def test_common_password(self):
        result = analyze_password("password")
        self.assertLess(result.score, 40)
        self.assertEqual(result.strength, StrengthLevel.WEAK)

    def test_short_password(self):
        result = analyze_password("Ab1!")
        failed_length = any(
            c.name.startswith("Length") and not c.passed for c in result.criteria
        )
        self.assertTrue(failed_length)

    def test_medium_password(self):
        result = analyze_password("Hello123")
        self.assertGreaterEqual(result.score, 30)
        self.assertIn(
            result.strength,
            (StrengthLevel.FAIR, StrengthLevel.GOOD, StrengthLevel.STRONG),
        )

    def test_strong_password(self):
        result = analyze_password("Tr0ub4dor&3Xtra!")
        self.assertGreaterEqual(result.score, 70)
        self.assertIn(
            result.strength,
            (StrengthLevel.STRONG, StrengthLevel.VERY_STRONG),
        )

    def test_all_criteria_present(self):
        result = analyze_password("Test123!@#")
        names = {c.name for c in result.criteria}
        self.assertTrue(any("Uppercase" in n for n in names))
        self.assertTrue(any("Lowercase" in n for n in names))
        self.assertTrue(any("Numeric" in n for n in names))
        self.assertTrue(any("Special" in n for n in names))

    def test_recommendations_for_weak(self):
        result = analyze_password("abc")
        self.assertGreater(len(result.recommendations), 0)

    def test_numbers_only_penalty(self):
        result = analyze_password("123456789012")
        self.assertTrue(any("numbers" in r.lower() for r in result.recommendations))


if __name__ == "__main__":
    unittest.main()
