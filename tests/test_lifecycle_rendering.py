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


if __name__ == "__main__":
    unittest.main()
