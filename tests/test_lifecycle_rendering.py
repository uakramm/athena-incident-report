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
            self.assertIn("Time to close", output)
            self.assertNotIn("Mean time to resolve", output)

    def test_both_incident_tables_show_assignees(self) -> None:
        data = generate_report.sample_data()

        for output in (render.render_report(data, css=""), render_email.render_email(data)):
            self.assertEqual(output.count("Assignee"), 2)
            self.assertIn("Shelly Peralta", output)
            self.assertIn("Joseph Khoury", output)
            self.assertIn("Unassigned", output)


if __name__ == "__main__":
    unittest.main()
