import json
import os
import sys
import types
import unittest
from unittest import mock

import lambda_handler


class _Context:
    aws_request_id = "dispatch-request-123"


def _event(body: str) -> dict:
    return {
        "httpMethod": "POST",
        "path": "/run",
        "headers": {
            "content-type": "application/x-www-form-urlencoded",
            "x-report-token": "secret-token",
        },
        "queryStringParameters": None,
        "body": body,
        "isBase64Encoded": False,
    }


class DispatchHandlerTests(unittest.TestCase):
    def test_valid_request_is_queued_asynchronously(self) -> None:
        client = mock.Mock()
        client.invoke.return_value = {"StatusCode": 202}
        boto3 = types.SimpleNamespace(client=mock.Mock(return_value=client))
        event = _event("tenant=athena&email_to=to%40example.com&email_cc=&dry_run=false")

        with (
            mock.patch.object(lambda_handler, "_load_secret_env", return_value=[]),
            mock.patch.object(lambda_handler, "_authorize", return_value=True),
            mock.patch.dict(os.environ, {"REPORT_WORKER_FUNCTION_NAME": "report-worker"}, clear=False),
            mock.patch.dict(sys.modules, {"boto3": boto3}),
        ):
            response = lambda_handler.dispatch_handler(event, _Context())

        self.assertEqual(response["statusCode"], 202)
        self.assertEqual(json.loads(response["body"])["status"], "accepted")
        client.invoke.assert_called_once()
        invoke = client.invoke.call_args.kwargs
        self.assertEqual(invoke["FunctionName"], "report-worker")
        self.assertEqual(invoke["InvocationType"], "Event")
        worker_event = json.loads(invoke["Payload"])
        self.assertEqual(worker_event["reportDispatchRequestId"], "dispatch-request-123")

    def test_email_cc_must_be_present_even_when_empty_is_allowed(self) -> None:
        event = _event("tenant=athena&email_to=to%40example.com")

        with (
            mock.patch.object(lambda_handler, "_load_secret_env", return_value=[]),
            mock.patch.object(lambda_handler, "_authorize", return_value=True),
        ):
            response = lambda_handler.dispatch_handler(event, _Context())

        self.assertEqual(response["statusCode"], 400)
        self.assertIn("email_cc", json.loads(response["body"])["error"])

    def test_bad_token_is_rejected_before_queueing(self) -> None:
        event = _event("tenant=nbs&email_to=to%40example.com&email_cc=")

        with (
            mock.patch.object(lambda_handler, "_load_secret_env", return_value=[]),
            mock.patch.object(lambda_handler, "_authorize", return_value=False),
        ):
            response = lambda_handler.dispatch_handler(event, _Context())

        self.assertEqual(response["statusCode"], 401)
        self.assertEqual(json.loads(response["body"])["error"], "Unauthorized.")


if __name__ == "__main__":
    unittest.main()
