import os
import unittest
from unittest import mock
import datetime as dt

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


class AgentStatusTests(unittest.TestCase):
    def test_heartbeat_snapshot_matches_agent_summary_buckets(self) -> None:
        now = dt.datetime(2026, 8, 17, 12, 0, tzinfo=dt.timezone.utc)

        def agent(name: str, age: dt.timedelta, agent_id: str) -> dict:
            return {
                "id": agent_id,
                "name": name,
                "lastKeepAlive": (now - age).isoformat().replace("+00:00", "Z"),
                "os": {"name": "Windows 11"},
            }

        agents = [
            agent("manager", dt.timedelta(hours=1), "000"),
            agent("active", dt.timedelta(hours=12), "001"),
            agent("short", dt.timedelta(hours=48), "002"),
            agent("week", dt.timedelta(days=5), "003"),
            agent("fortnight", dt.timedelta(days=10), "004"),
            agent("stale", dt.timedelta(days=15), "005"),
        ]
        with mock.patch.object(generate_report, "_wazuh_manager_agents", return_value=agents):
            result = generate_report.agent_status_snapshot(None, now)

        self.assertEqual(result["total"], 4)
        self.assertEqual(result["active"], 1)
        self.assertEqual(result["inactive"], 3)
        self.assertEqual(result["inactive_24_72"], 1)
        self.assertEqual(result["inactive_3_7d"], 1)
        self.assertEqual(result["inactive_7_14d"], 1)
        self.assertEqual([row["name"] for row in result["inactive_agents"]], ["fortnight", "week", "short"])
        self.assertEqual(result["source"], "wazuh-manager")

    def test_manager_client_authenticates_and_paginates(self) -> None:
        class Response:
            def __init__(self, status_code: int, payload: dict) -> None:
                self.status_code = status_code
                self._payload = payload

            def json(self) -> dict:
                return self._payload

        class Session:
            def __init__(self) -> None:
                self.headers = {}
                self.offsets = []
                self.closed = False

            def post(self, url: str, **kwargs) -> Response:
                self.auth_url = url
                self.auth_kwargs = kwargs
                return Response(200, {"data": {"token": "test-token"}})

            def get(self, url: str, **kwargs) -> Response:
                self.offsets.append(kwargs["params"]["offset"])
                offset = kwargs["params"]["offset"]
                item = {"id": f"{offset + 1:03d}", "name": f"agent-{offset + 1}"}
                return Response(200, {"data": {"affected_items": [item], "total_affected_items": 2}})

            def close(self) -> None:
                self.closed = True

        session = Session()
        env = {
            "WAZUH_HOST": "manager.internal",
            "WAZUH_USER": "report-user",
            "WAZUH_PASS": "secret",
            "WAZUH_VERIFY_SSL": "false",
            "WAZUH_AGENT_PAGE_SIZE": "1",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            generate_report.requests, "Session", return_value=session
        ):
            agents = generate_report._wazuh_manager_agents()

        self.assertEqual(session.auth_url, "https://manager.internal:55000/security/user/authenticate")
        self.assertEqual(session.offsets, [0, 1])
        self.assertEqual([item["id"] for item in agents], ["001", "002"])
        self.assertEqual(session.headers["Authorization"], "Bearer test-token")
        self.assertTrue(session.closed)


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

    def test_zero_mttd_fallback_is_not_reportable(self) -> None:
        self.assertFalse(generate_report.lifecycle_value_is_usable("mttd", 0))
        self.assertTrue(generate_report.lifecycle_value_is_usable("mttt", 0))
        self.assertTrue(generate_report.lifecycle_value_is_usable("mttd", 0.2))

    def test_duration_display_rounds_to_nearest_minute(self) -> None:
        self.assertEqual(generate_report.fmt_duration(59), "<1m")
        self.assertEqual(generate_report.fmt_duration(103), "2m")
        self.assertEqual(generate_report.fmt_duration(3860), "1h 04m")


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
            "jira_assignee": "Shelly Peralta",
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
        self.assertEqual(issue["fields"]["assignee"]["displayName"], "Shelly Peralta")

    def test_precise_lifecycle_seconds_override_rounded_minutes(self) -> None:
        client = self._client([{
            "jira_ticket_id": "NSO-1001",
            "jira_created_at": "2026-07-13T12:00:00Z",
            "severity": "high",
            "mttd_seconds": 0.24,
            "mttd_minutes": 0,
            "mttt_seconds": 90,
            "mttt_minutes": 1.5,
        }])
        issue = client.search('issuetype in ("Security Alert", "Security Incident")', [])[0]
        self.assertAlmostEqual(issue["fields"]["mttd_minutes"], 0.004)
        self.assertEqual(issue["fields"]["mttt_minutes"], 1.5)

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

    def test_cve_mention_does_not_turn_an_incident_into_a_vulnerability(self) -> None:
        client = self._client([{
            "jira_ticket_id": "SECOPS-1",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "severity": "high",
            "alert_source": "wazuh",
            "rule_groups": ["sysmon", "windows"],
            "rule_description": "Exploit attempt involving CVE-2026-12345",
        }])
        issues = client.search('issuetype in ("Security Alert", "Security Incident")', [])
        self.assertEqual([issue["key"] for issue in issues], ["SECOPS-1"])
        self.assertEqual(issues[0]["fields"]["issuetype"]["name"], "Security Alert")

    def test_explicit_vulnerability_detector_group_is_a_vulnerability(self) -> None:
        client = self._client([{
            "jira_ticket_id": "SECOPS-2",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "severity": "critical",
            "alert_source": "wazuh",
            "rule_groups": ["vulnerability-detector"],
            "rule_description": "CVE-2026-12345 affects linux-aws",
        }])
        issues = client.search("issuetype = Vulnerability", [])
        self.assertEqual([issue["key"] for issue in issues], ["SECOPS-2"])

    def test_structured_vulnerability_context_alone_does_not_override_jira_routing(self) -> None:
        client = self._client([{
            "jira_ticket_id": "SECOPS-3",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "severity": "high",
            "alert_source": "defender",
            "rule_groups": ["vulnerability-detector"],
            "alert_data": {
                "source": "wazuh",
                "description": "CVE-2026-12345 affects Windows Defender",
                "data": {"vulnerability": {"cve": "CVE-2026-12345"}},
            },
        }])
        self.assertEqual(client.count("issuetype = Vulnerability"), 0)
        self.assertEqual(
            client.count('issuetype in ("Security Alert", "Security Incident")'), 1
        )

    def test_legacy_cve_affects_rule_is_a_vulnerability(self) -> None:
        client = self._client([{
            "jira_ticket_id": "SECOPS-31",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "severity": "high",
            "alert_source": "wazuh",
            "rule_description": "CVE-2026-12345 affects linux-aws",
        }])
        self.assertEqual(client.count("issuetype = Vulnerability"), 1)

    def test_github_security_finding_is_a_vulnerability(self) -> None:
        client = self._client([{
            "jira_ticket_id": "SECOPS-32",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "severity": "high",
            "alert_source": "github",
            "alert_data": {"source": "wazuh"},
            "rule_description": "Repository security advisory GHSA-1234",
        }])
        self.assertEqual(client.count("issuetype = Vulnerability"), 1)

    def test_generic_wazuh_source_is_replaced_with_detected_vendor(self) -> None:
        client = self._client([{
            "jira_ticket_id": "SECOPS-4",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "severity": "high",
            "alert_source": "wazuh",
            "rule_description": "AWS GuardDuty High anomalous API activity",
        }, {
            "jira_ticket_id": "SECOPS-5",
            "jira_created_at": "2026-08-03T10:01:00Z",
            "severity": "high",
            "alert_source": "wazuh",
            "rule_description": "Office 365 phishing and malware event",
        }])
        issues = client.search('issuetype in ("Security Alert", "Security Incident")', [])
        self.assertEqual(
            [issue["fields"]["source"] for issue in issues],
            ["GuardDuty", "Office 365"],
        )
        self.assertIn("[GuardDuty]", issues[0]["fields"]["summary"])
        self.assertIn("[Office 365]", issues[1]["fields"]["summary"])

    def test_internal_rule_groups_are_mapped_to_readable_incident_types(self) -> None:
        client = self._client([{
            "jira_ticket_id": "SECOPS-6",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "severity": "high",
            "alert_source": "wazuh",
            "alert_data": {"category": "sysmon, sysmon_eid11_detections, windows"},
        }])
        issue = client.search('issuetype in ("Security Alert", "Security Incident")', [])[0]
        self.assertEqual(issue["fields"]["incident_type"], "Endpoint detection")

    def test_defender_vendor_label_maps_to_endpoint_detection(self) -> None:
        client = self._client([{
            "jira_ticket_id": "SECOPS-61",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "severity": "high",
            "alert_source": "defender",
            "alert_data": {"incident_type": "Defender"},
        }])
        issue = client.search('issuetype in ("Security Alert", "Security Incident")', [])[0]
        self.assertEqual(issue["fields"]["incident_type"], "Endpoint detection")

    def test_duplicate_mirrors_use_the_freshest_jira_state(self) -> None:
        client = self._client([{
            "jira_ticket_id": "SECOPS-7",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "jira_updated_at": "2026-08-03T11:00:00Z",
            "jira_status": "Open",
            "severity": "high",
        }, {
            "jira_ticket_id": "SECOPS-7",
            "jira_created_at": "2026-08-03T10:00:00Z",
            "jira_updated_at": "2026-08-03T12:00:00Z",
            "jira_status": "Closed",
            "jira_status_category": "Done",
            "jira_resolved_at": "2026-08-03T11:59:00Z",
            "severity": "high",
        }])
        issues = client.search('issuetype in ("Security Alert", "Security Incident")', [])
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["fields"]["status"]["statusCategory"]["name"], "Done")

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

    def test_open_at_historical_boundary_includes_later_resolution(self) -> None:
        client = self._client([{
            "jira_ticket_id": "NSO-3",
            "jira_created_at": "2026-07-01T00:00:00Z",
            "jira_resolved_at": "2026-07-15T00:00:00Z",
            "severity": "high",
        }])
        prior_week_end = dt.date(2026, 7, 13)
        issues = client.search(
            'issuetype in ("Security Alert", "Security Incident") '
            f'AND created < "{prior_week_end}" '
            f'AND (resolutiondate is EMPTY OR resolutiondate >= "{prior_week_end}")',
            [],
        )
        self.assertEqual([issue["key"] for issue in issues], ["NSO-3"])

    def test_done_ticket_uses_status_change_as_resolution_fallback(self) -> None:
        client = self._client([{
            "jira_ticket_id": "NSO-4",
            "jira_created_at": "2026-07-01T00:00:00Z",
            "jira_status": "Canceled",
            "jira_status_category": "Done",
            "jira_status_category_changed_at": "2026-07-10T00:00:00Z",
            "severity": "high",
        }])
        issues = client.search(
            'issuetype in ("Security Alert", "Security Incident") '
            'AND created < "2026-07-20" '
            'AND (resolutiondate is EMPTY OR resolutiondate >= "2026-07-20")',
            [],
        )
        self.assertEqual(issues, [])

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
