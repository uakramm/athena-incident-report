import os
import unittest
from unittest import mock

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


class LifecycleMetricTests(unittest.TestCase):
    def test_duration_field_takes_precedence(self) -> None:
        fields = {
            "duration": 3,
            "start": "2026-07-20T10:00:00-04:00",
            "end": "2026-07-20T10:10:00-04:00",
        }
        self.assertEqual(
            generate_report.lifecycle_seconds(fields, "duration", "start", "end", "minutes"),
            180,
        )

    def test_mttc_uses_incident_to_resolution_when_duration_is_unavailable(self) -> None:
        fields = {
            "incident_time": "2026-07-20T10:00:00-04:00",
            "resolutiondate": "2026-07-20T10:12:30-04:00",
        }
        self.assertEqual(
            generate_report.lifecycle_seconds(fields, None, "incident_time", "resolutiondate"),
            750,
        )

    def test_negative_timestamp_interval_is_rejected(self) -> None:
        fields = {
            "start": "2026-07-20T10:01:00-04:00",
            "end": "2026-07-20T10:00:00-04:00",
        }
        self.assertIsNone(generate_report.lifecycle_seconds(fields, None, "start", "end"))


class OpenSearchClientTests(unittest.TestCase):
    def _client(self, documents):
        return generate_report.OpenSearchClient(
            "https://indexer.example.com:9200",
            "admin",
            "password",
            documents=documents,
            browse_base="https://example.atlassian.net",
        )

    def test_translates_mirrored_lifecycle_and_jira_state(self) -> None:
        client = self._client([{
            "jira_ticket_id": "NSO-1000",
            "jira_created_at": "2026-07-13T12:00:00Z",
            "jira_status": "Open",
            "jira_status_category": "In Progress",
            "severity": "high",
            "alert_source": "office365",
            "rule_description": "Suspicious email",
            "mttd_minutes": 3.5,
            "mttt_minutes": 1.25,
            "mttr_minutes": 6,
            "mttc_minutes": None,
        }])

        issue = client.search(
            'issuetype in ("Security Alert", "Security Incident") AND created >= "2026-07-13"',
            [],
        )[0]

        self.assertEqual(issue["key"], "NSO-1000")
        self.assertEqual(issue["fields"]["severity"]["value"], "Sev-2")
        self.assertEqual(issue["fields"]["mttd_minutes"], 3.5)
        self.assertEqual(issue["fields"]["status"]["statusCategory"]["name"], "In Progress")

    def test_suricata_critical_uses_nids_sev_2(self) -> None:
        client = self._client([{
            "jira_ticket_id": "NSO-928",
            "jira_created_at": "2026-07-03T10:00:00Z",
            "severity": "critical",
            "alert_source": "suricata",
            "rule_groups": ["suricata"],
            "rule_description": "ET SCAN",
        }])
        issue = client.search('issuetype in ("Security Alert", "Security Incident")', [])[0]
        self.assertEqual(issue["fields"]["severity"]["value"], "Sev-2")
        self.assertIn("[SURICATA]", issue["fields"]["summary"])

    def test_open_at_excludes_ticket_resolved_before_boundary(self) -> None:
        client = self._client([
            {
                "jira_ticket_id": "NSO-1",
                "jira_created_at": "2026-07-01T00:00:00Z",
                "jira_resolved_at": "2026-07-10T00:00:00Z",
                "severity": "high",
            },
            {
                "jira_ticket_id": "NSO-2",
                "jira_created_at": "2026-07-01T00:00:00Z",
                "severity": "high",
            },
        ])
        issues = client.search(
            'issuetype in ("Security Alert", "Security Incident") AND created < "2026-07-20" '
            'AND (resolutiondate is EMPTY OR resolutiondate >= "2026-07-20")',
            [],
        )
        self.assertEqual([issue["key"] for issue in issues], ["NSO-2"])

    def test_from_env_requires_password(self) -> None:
        with mock.patch.dict(os.environ, {
            "OPENSEARCH_URL": "https://indexer.example.com:9200",
            "OPENSEARCH_USERNAME": "admin",
            "OPENSEARCH_PASSWORD": "",
        }, clear=False):
            with self.assertRaisesRegex(generate_report.OpenSearchError, "OPENSEARCH_PASSWORD"):
                generate_report.OpenSearchClient.from_env()


if __name__ == "__main__":
    unittest.main()
