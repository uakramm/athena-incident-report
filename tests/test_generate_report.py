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


class IncidentSeverityTests(unittest.TestCase):
    def test_standard_sev_2_is_high(self) -> None:
        fields = {"summary": "[HIGH] [Office 365] Suspicious email", "severity": {"value": "Sev-2"}}
        self.assertEqual(generate_report.incident_severity_label(fields, "severity"), "High")

    def test_suricata_sev_2_is_critical(self) -> None:
        fields = {"summary": "[CRITICAL] [SURICATA] ET SCAN", "severity": {"value": "Sev-2"}}
        self.assertEqual(generate_report.incident_severity_label(fields, "severity"), "Critical")

    def test_suricata_marker_is_case_insensitive(self) -> None:
        fields = {"summary": "[critical] [suricata] ET SCAN", "severity": "Sev-3"}
        self.assertEqual(generate_report.incident_severity_label(fields, "severity"), "High")

    def test_non_suricata_sev_3_is_medium(self) -> None:
        fields = {"summary": "[MEDIUM] [WAZUH] Alert", "severity": "Sev-3"}
        self.assertEqual(generate_report.incident_severity_label(fields, "severity"), "Medium")


if __name__ == "__main__":
    unittest.main()
