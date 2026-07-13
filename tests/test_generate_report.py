import unittest

import generate_report


class DateFormattingTests(unittest.TestCase):
    def test_strip_leading_zero_preserves_minutes(self) -> None:
        self.assertEqual(
            generate_report.strip_leading_zero("03 Jul 2026, 09:05"),
            "3 Jul 2026, 9:05",
        )

    def test_strip_leading_zero_preserves_other_punctuated_values(self) -> None:
        self.assertEqual(
            generate_report.strip_leading_zero("Mon 06 Jul - Sun 12 Jul 2026, 14:01"),
            "Mon 6 Jul - Sun 12 Jul 2026, 14:01",
        )


if __name__ == "__main__":
    unittest.main()
