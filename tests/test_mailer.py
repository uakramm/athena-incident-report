import argparse
import os
import unittest
from unittest import mock

import mailer


class EmailSenderConfigTests(unittest.TestCase):
    def test_sender_comes_from_environment(self) -> None:
        with mock.patch.dict(os.environ, {"REPORT_EMAIL_FROM": "Shelly <shelly@example.com>"}, clear=True):
            config = mailer.resolve_email_config(argparse.Namespace(), {})

        self.assertEqual(config["from_addr"], "shelly@example.com")

    def test_sender_does_not_fall_back_to_report_data(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            config = mailer.resolve_email_config(
                argparse.Namespace(),
                {"support_email": "support@example.com"},
            )

        self.assertEqual(config["from_addr"], "")


if __name__ == "__main__":
    unittest.main()
