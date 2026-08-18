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


class Soc2ComplianceTests(unittest.TestCase):
    def test_snapshot_aggregates_tsc_mapped_alerts(self) -> None:
        class Client:
            def query_index(self, index: str, body: dict) -> dict:
                self.index = index
                self.body = body
                return {
                    "hits": {"total": {"value": 21}},
                    "aggregations": {
                        "unique_controls": {"value": 4},
                        "affected_agents": {"value": 3},
                        "top_controls": {
                            "buckets": [
                                {"key": "CC6.1", "doc_count": 9},
                                {"key": "CC7.2", "doc_count": 5},
                            ]
                        },
                        "severity": {
                            "buckets": [
                                {"key": "Low", "doc_count": 10},
                                {"key": "Medium", "doc_count": 6},
                                {"key": "High", "doc_count": 4},
                                {"key": "Critical", "doc_count": 1},
                            ]
                        },
                    },
                }

        client = Client()
        with mock.patch.dict(os.environ, {"REPORT_TIMEZONE": "America/New_York"}):
            result = generate_report.soc2_compliance_snapshot(
                client, dt.date(2026, 8, 3), dt.date(2026, 8, 10)
            )

        self.assertEqual(client.index, "wazuh-alerts-*")
        filters = client.body["query"]["bool"]["filter"]
        self.assertIn({"exists": {"field": "rule.tsc"}}, filters)
        self.assertIn(
            {"range": {"timestamp": {"gte": "2026-08-03T00:00:00-04:00",
                                     "lt": "2026-08-10T00:00:00-04:00"}}},
            filters,
        )
        self.assertEqual(result["total_alerts"], 21)
        self.assertEqual(result["critical_high"], 5)
        self.assertEqual(result["unique_controls"], 4)
        self.assertEqual(result["affected_agents"], 3)
        self.assertEqual(result["status"], "Attention required")
        self.assertEqual(result["severity"][0], ("Critical", 1))
        self.assertEqual(result["top_controls"][0], ("CC6.1", 9))

    def test_snapshot_reports_no_mapped_alerts_without_claiming_compliance(self) -> None:
        class Client:
            def query_index(self, _index: str, _body: dict) -> dict:
                return {"hits": {"total": 0}, "aggregations": {}}

        result = generate_report.soc2_compliance_snapshot(
            Client(), dt.date(2026, 8, 3), dt.date(2026, 8, 10)
        )

        self.assertEqual(result["status"], "No mapped alerts")
        self.assertEqual(result["status_kind"], "green")
        self.assertNotIn("compliant", result["status_note"].lower())


class Soc2CriteriaTests(unittest.TestCase):
    def _data(self, **overrides: dict) -> dict:
        data = {
            "_sections_enabled": {"agent_status": True, "vuln": True, "availability": True, "soc2": True},
            "exec": {"opened": 100, "closed": 96, "open": 4, "mttd": "14 min", "mttt": "2 min", "mttc": "3h 42m"},
            "sla": {"met": 98, "total": 100, "overall": 98},
            "soc2": {"total_alerts": 42, "critical_high": 3, "unique_controls": 8, "affected_agents": 12},
            "agent_status": {"total": 84, "active": 82},
            "vuln": {"total_open": 271, "crit_open": 4, "high_open": 31, "resolved": 47,
                     "sla": {"overall": 97}},
            "availability": {"uptime": "99.98%", "sla": "99.9%", "outages": 0},
        }
        data.update(overrides)
        return data

    def _row(self, rows: list, control_starts_with: str) -> dict:
        return next(r for r in rows if r["control"].startswith(control_starts_with))

    def test_a_clean_week_evidences_every_criterion(self) -> None:
        rows = generate_report.soc2_criteria(self._data())

        self.assertEqual([r["criterion"] for r in rows],
                         ["CC7.1", "CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5", "A1.2"])
        self.assertTrue(all(r["status"] == generate_report.SOC2_MET for r in rows), rows)

    def test_detection_stays_met_when_it_surfaces_critical_alerts(self) -> None:
        rows = generate_report.soc2_criteria(self._data())
        detection = self._row(rows, "Threat")

        self.assertEqual(detection["status"], generate_report.SOC2_MET)
        self.assertIn("3 at critical/high Wazuh rule level", detection["evidence"])

    def test_sla_miss_and_monitoring_gap_are_flagged_for_attention(self) -> None:
        rows = generate_report.soc2_criteria(self._data(
            sla={"met": 80, "total": 100, "overall": 80},
            agent_status={"total": 84, "active": 60},
        ))

        self.assertEqual(self._row(rows, "Incident response")["status"], generate_report.SOC2_ATTENTION)
        monitoring = self._row(rows, "Continuous")
        self.assertEqual(monitoring["status"], generate_report.SOC2_ATTENTION)
        self.assertIn("60 of 84 agents reporting within 24h (71%)", monitoring["evidence"])

    def test_recovery_tracks_closure_rate_not_an_empty_queue(self) -> None:
        rows = generate_report.soc2_criteria(self._data(
            exec={"opened": 100, "closed": 95, "open": 17, "mttc": "3h"},
        ))

        recovery = self._row(rows, "Incident resolution")
        self.assertEqual(recovery["status"], generate_report.SOC2_MET)
        self.assertIn("17 open at the reporting cut-off", recovery["evidence"])

    def test_open_exposure_with_no_remediation_is_not_a_pass(self) -> None:
        rows = generate_report.soc2_criteria(self._data(
            vuln={"total_open": 545, "crit_open": 13, "high_open": 532, "resolved": 0, "sla": {}},
        ))

        vulnerability = self._row(rows, "Vulnerability")
        self.assertEqual(vulnerability["status"], generate_report.SOC2_ATTENTION)
        self.assertIn("none remediated this period", vulnerability["evidence"])

    def test_nothing_open_and_nothing_to_remediate_is_met(self) -> None:
        rows = generate_report.soc2_criteria(self._data(
            vuln={"total_open": 0, "crit_open": 0, "high_open": 0, "resolved": 0, "sla": {}},
        ))

        self.assertEqual(self._row(rows, "Vulnerability")["status"], generate_report.SOC2_MET)

    def test_unreadable_sources_are_not_evidenced_rather_than_passed(self) -> None:
        rows = generate_report.soc2_criteria(self._data(
            soc2={"unavailable": True},
            agent_status={"unavailable": True},
            sla={},
        ))

        for control in ("Threat", "Continuous", "Incident response"):
            self.assertEqual(self._row(rows, control)["status"], generate_report.SOC2_NO_DATA)
        self.assertNotIn("Met", [r["status"] for r in rows if r["control"].startswith("Threat")])

    def test_disabled_sections_are_left_out_entirely(self) -> None:
        rows = generate_report.soc2_criteria(self._data(
            _sections_enabled={"agent_status": False, "vuln": False, "availability": False, "soc2": True},
        ))

        self.assertEqual([r["criterion"] for r in rows], ["CC7.1", "CC7.3", "CC7.4", "CC7.5"])

    def test_targets_are_env_tunable(self) -> None:
        data = self._data(sla={"met": 90, "total": 100, "overall": 90})

        with mock.patch.dict(os.environ, {"REPORT_SOC2_SLA_TARGET_PCT": "90"}):
            rows = generate_report.soc2_criteria(data)

        self.assertEqual(self._row(rows, "Incident response")["status"], generate_report.SOC2_MET)


class ReportTimezoneTests(unittest.TestCase):
    def test_utc_moments_display_in_the_configured_zone(self) -> None:
        moment = dt.datetime(2026, 8, 4, 15, 40, tzinfo=dt.timezone.utc)

        with mock.patch.dict(os.environ, {"REPORT_TIMEZONE": "America/New_York"}):
            self.assertEqual(generate_report.fmt_report_dt(moment), "4 Aug 2026, 11:40 ET")
        with mock.patch.dict(os.environ, {"REPORT_TIMEZONE": "Asia/Karachi"}):
            self.assertEqual(generate_report.fmt_report_dt(moment), "4 Aug 2026, 20:40 PKT")

    def test_an_unknown_zone_falls_back_to_utc_rather_than_failing(self) -> None:
        moment = dt.datetime(2026, 8, 4, 15, 40, tzinfo=dt.timezone.utc)

        with mock.patch.dict(os.environ, {"REPORT_TIMEZONE": "Mars/Olympus_Mons"}):
            self.assertEqual(generate_report.fmt_report_dt(moment), "4 Aug 2026, 15:40 UTC")

    def test_agent_last_seen_is_reported_in_the_configured_zone(self) -> None:
        now = dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.timezone.utc)
        agents = [{"id": "108", "name": "dev-promachos-windows",
                   "lastKeepAlive": "2026-08-04T15:40:00Z", "os": {"name": "Windows Server 2025"}}]

        with mock.patch.object(generate_report, "_wazuh_manager_agents", return_value=agents), \
                mock.patch.dict(os.environ, {"REPORT_TIMEZONE": "America/New_York"}):
            result = generate_report.agent_status_snapshot(None, now)

        self.assertEqual(result["inactive_agents"][0]["last_seen"], "4 Aug 2026, 11:40 ET")


class ReportingWeekBoundaryTests(unittest.TestCase):
    """The week runs on the client's calendar day, so late-Sunday-local tickets
    stay in that week even though UTC has already rolled over."""

    WEEK = 'created >= "2026-08-10" AND created < "2026-08-17"'

    def _in_week(self, created: str, tz: str = "America/New_York") -> bool:
        issue = {"fields": {"created": created, "issuetype": {"name": "Security Incident"}}}
        with mock.patch.dict(os.environ, {"REPORT_TIMEZONE": tz}):
            return generate_report.OpenSearchClient._matches(issue, self.WEEK)

    def test_late_sunday_local_belongs_to_the_week_it_was_raised_in(self) -> None:
        # 02:00Z Mon 10 Aug is 22:00 ET Sun 9 Aug — the prior week, not this one.
        self.assertFalse(self._in_week("2026-08-10T02:00:00.000+0000"))
        # 02:00Z Mon 17 Aug is 22:00 ET Sun 16 Aug — still inside this week.
        self.assertTrue(self._in_week("2026-08-17T02:00:00.000+0000"))

    def test_the_first_local_moment_of_the_week_is_included(self) -> None:
        self.assertTrue(self._in_week("2026-08-10T04:00:00.000+0000"))  # 00:00 ET Mon
        self.assertFalse(self._in_week("2026-08-10T03:59:00.000+0000"))  # 23:59 ET Sun

    def test_the_same_ticket_lands_differently_under_a_different_zone(self) -> None:
        moment = "2026-08-17T02:00:00.000+0000"  # 22:00 ET Sun 16th, 07:00 PKT Mon 17th

        self.assertTrue(self._in_week(moment, tz="America/New_York"))
        self.assertFalse(self._in_week(moment, tz="Asia/Karachi"))

    def test_utc_tenants_keep_the_old_boundaries(self) -> None:
        self.assertTrue(self._in_week("2026-08-10T02:00:00.000+0000", tz="UTC"))
        self.assertFalse(self._in_week("2026-08-17T02:00:00.000+0000", tz="UTC"))


class CommentaryTests(unittest.TestCase):
    def _commentary(self, mttc: float, prev_mttc: object) -> str:
        return generate_report.auto_commentary(
            opened_n=156, closed_n=144, open_n=48, prev_open=36,
            mttc_secs=mttc, prev_mttc_secs=prev_mttc, inc_sla=None,
            type_breakdown=[], open_rows=[], include_vuln=False,
            v_resolved=0, v_new=0, vuln_sla=None,
        )

    def test_a_climbing_time_to_close_is_not_described_as_held(self) -> None:
        text = self._commentary(42300, 10500)  # 11h 45m, up from 2h 55m

        self.assertNotIn("held at", text)
        self.assertIn("rose to 11h 45m from 2h 55m the week prior", text)

    def test_a_falling_time_to_close_reads_as_an_improvement(self) -> None:
        self.assertIn("improved to 2h 55m", self._commentary(10500, 42300))

    def test_a_steady_time_to_close_still_reads_as_held(self) -> None:
        self.assertIn("held at 11h 45m", self._commentary(42300, 41000))

    def test_no_prior_week_falls_back_to_the_plain_figure(self) -> None:
        self.assertIn("held at 11h 45m", self._commentary(42300, None))


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
