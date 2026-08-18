import unittest

import generate_report
import render
import render_email


class LifecycleRenderingTests(unittest.TestCase):
    def test_both_renderers_show_four_metrics_in_lifecycle_order(self) -> None:
        data = generate_report.sample_data()
        expected = [
            "Mean time to detect",
            "Mean time to ticket",
            "Mean time to respond",
            "Mean time to close",
        ]

        for output in (render.render_report(data, css=""), render_email.render_email(data)):
            positions = [output.index(label) for label in expected]
            self.assertEqual(positions, sorted(positions))
            self.assertNotIn("Mean time to resolve", output)

    def test_both_renderers_omit_incident_detail_tables(self) -> None:
        data = generate_report.sample_data()

        for output in (render.render_report(data, css=""), render_email.render_email(data)):
            self.assertNotIn("Closed this week (", output)
            self.assertNotIn("Current status", output)
            self.assertNotIn("Time to close", output)
            self.assertNotIn("Assignee", output)

    def test_agent_status_precedes_vulnerabilities_and_metrics_link_out(self) -> None:
        data = generate_report.sample_data()

        for output in (render.render_report(data, css=""), render_email.render_email(data)):
            self.assertLess(output.index("Agent status"), output.index("Vulnerability status"))
            self.assertIn("View agent details", output)
            self.assertIn("View in Jira", output)
            self.assertIn("https://example.atlassian.net/issues/?jql=project%3DNSO", output)

    def test_incident_aggregate_cards_use_one_section_level_jira_link(self) -> None:
        data = generate_report.sample_data()

        for output in (render.render_report(data, css=""), render_email.render_email(data)):
            incident_section = output[output.index("Incident management"):output.index("Agent status")]
            self.assertEqual(incident_section.count("View incidents in Jira"), 1)
            self.assertEqual(incident_section.count("Open in Jira"), 1)
            self.assertNotIn(">View in Jira", incident_section)
            self.assertNotIn("View open items in Jira", incident_section)

    def test_lifecycle_values_remain_linked_without_visible_ctas(self) -> None:
        data = generate_report.sample_data()

        for output in (render.render_report(data, css=""), render_email.render_email(data)):
            executive_section = output[output.index("Executive summary"):output.index("From your SOC team")]
            self.assertEqual(executive_section.count("View in Jira"), 3)
            for label in (
                "Mean time to detect",
                "Mean time to ticket",
                "Mean time to respond",
                "Mean time to close",
            ):
                start = executive_section.index(label)
                tile_tail = executive_section[start:start + 1200]
                self.assertIn("<a href=", tile_tail)

    def test_soc2_status_is_the_final_section_and_has_audit_disclaimer(self) -> None:
        data = generate_report.sample_data()

        for output in (render.render_report(data, css=""), render_email.render_email(data)):
            self.assertGreater(output.index("SOC 2 Compliance Status"), output.index("Vulnerability status"))
            self.assertLess(output.index("SOC 2 Compliance Status"), output.index("Prepared by the Athena SOC team"))
            self.assertIn("Operational monitoring evidence only", output)
            self.assertIn("not an audit opinion", output)
            self.assertIn("CC6.1", output)

    def test_soc2_renders_a_criterion_row_per_control_with_its_evidence(self) -> None:
        data = generate_report.sample_data()

        for output in (render.render_report(data, css=""), render_email.render_email(data)):
            self.assertIn("Evidence (this period)", output)
            for row in data["soc2"]["criteria"]:
                self.assertIn(row["control"], output)
                self.assertIn(row["evidence"], output)
            self.assertIn("Met", output)
            self.assertIn("Attention", output)

    def test_soc2_section_still_renders_when_the_wazuh_read_fails(self) -> None:
        data = generate_report.sample_data()
        data["soc2"] = {"unavailable": True}
        data["soc2"]["criteria"] = generate_report.soc2_criteria(data)

        for output in (render.render_report(data, css=""), render_email.render_email(data)):
            self.assertNotIn("SOC 2 monitoring data unavailable", output)
            self.assertIn("Not evidenced", output)
            self.assertIn("Incident response within SLA", output)


if __name__ == "__main__":
    unittest.main()
