"""Facts cannot cross account boundaries or convert uncertainty into a passing answer."""

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime

import httpx

from authrail import (
    AuthRailError,
    CustomerReadResult,
    CustomerSource,
    DecisionsQuestion,
    ExtractionResult,
    ExtractionSource,
    extract_context_fact,
    lookup_customer_fact,
    lookup_quickbooks_invoice_balance,
    lookup_stripe_invoice_status,
    new_customer_api_reader,
    new_openai_decisions_extractor,
    openai_decisions_config_sha256,
)

VERSION = "00000000-0000-4000-8000-000000000031"


def source():
    return CustomerSource(
        source_version_id=VERSION,
        source_identity="invoices-api",
        account_boundary="tenant_123",
        lookup="invoice.read",
        timeout_ms=500,
    )


def extraction(question):
    return ExtractionSource(
        source_version_id=VERSION,
        source_identity="document-reader",
        account_boundary="tenant_123",
        lookup="document.read",
        timeout_ms=500,
        result_path=("sensitive",),
        value_type={"predicate": "boolean", "choice": "string", "score": "number"}[question.type],
        model_id="gpt-6-luna",
        model_config_sha256=openai_decisions_config_sha256(question),
        prompt_version="reviewed-v1",
        max_input_bytes=65536,
        max_output_bytes=4096,
    )


class FactTests(unittest.IsolatedAsyncioTestCase):
    def test_reviewed_question_fingerprint_matches_the_existing_go_vector(self):
        question = DecisionsQuestion(
            type="predicate",
            instructions="Does the message contain a payment card number?",
            min_confidence=0.8,
        )
        self.assertEqual(
            openai_decisions_config_sha256(question),
            "60df13567aaa08f8132106c431a80a0923af5d6d126b83565cfdf37d284fc27f",
        )

    async def test_existing_node_fingerprint_preserves_the_exact_same_reviewed_question(self):
        question = DecisionsQuestion(
            type="predicate",
            instructions="Does the text contain <secret> & credentials?",
            min_confidence=0.8,
        )
        reviewed = replace(
            extraction(question),
            model_config_sha256="d61843d222ccbd3d634db8bf01220e146007213a08313603d1d0c884383c8a76",
        )

        def response(req):
            return httpx.Response(
                200,
                json={
                    "model": "gpt-6-luna",
                    "answers": [{"type": "predicate", "name": "fact", "probability": 0.95}],
                },
            )

        extractor = new_openai_decisions_extractor(
            source=reviewed,
            question=question,
            api_key="secret",
            transport=httpx.MockTransport(response),
        )
        self.assertEqual(
            (await extractor(b"safe sample")).model_config_sha256, reviewed.model_config_sha256
        )
        with self.assertRaises(AuthRailError):
            new_openai_decisions_extractor(
                source=reviewed,
                question=replace(question, instructions="A different question"),
                api_key="secret",
            )

    async def test_customer_fact_is_bound_to_account_resource_and_read_time(self):
        expected = CustomerReadResult(
            source_identity="invoices-api",
            account_boundary="tenant_123",
            lookup="invoice.read",
            lookup_key="invoice_123",
            observed_at=datetime.now(UTC).isoformat(),
            value={"status": "open"},
        )
        for response, status in [
            (expected, "ok"),
            (replace(expected, account_boundary="tenant_other"), "untrusted"),
            (replace(expected, lookup_key="invoice_other"), "untrusted"),
            (replace(expected, observed_at="not-a-time"), "untrusted"),
        ]:

            async def read(key, answer=response):
                return answer

            self.assertEqual(
                (await lookup_customer_fact(source(), "invoice_123", read))["status"], status
            )

    async def test_reader_error_does_not_leak_or_become_a_default_value(self):
        async def unavailable(key):
            raise RuntimeError("private provider body")

        fact = await lookup_customer_fact(source(), "invoice_123", unavailable)
        self.assertEqual(fact["status"], "unavailable")
        self.assertNotIn("value", fact)
        self.assertNotIn("private", json.dumps(fact))

    async def test_fixed_api_reader_does_not_follow_redirects_with_credentials(self):
        requests = []

        def redirect(req):
            requests.append(str(req.url))
            return httpx.Response(302, headers={"Location": "https://other.example/steal"})

        reader = new_customer_api_reader(
            endpoint="https://invoices.example/records",
            bearer_token="secret",
            source_identity="invoices-api",
            account_boundary="tenant_123",
            lookup="invoice.read",
            transport=httpx.MockTransport(redirect),
        )
        fact = await lookup_customer_fact(source(), "invoice_123", reader)
        self.assertEqual(fact["status"], "unavailable")
        self.assertEqual(requests, ["https://invoices.example/records/invoice_123"])

    async def test_stripe_account_mismatch_stops_before_invoice_read(self):
        paths = []

        def request(req):
            paths.append(req.url.path)
            self.assertEqual(req.headers["Stripe-Account"], "acct_12345678")
            return httpx.Response(200, json={"object": "account", "id": "acct_other123"})

        fact = await lookup_stripe_invoice_status(
            source_version_id=VERSION,
            provider_account_id="acct_12345678",
            invoice_id="in_1234",
            timeout_ms=500,
            secret_key="sk_test_example",
            connected_account=True,
            transport=httpx.MockTransport(request),
        )
        self.assertEqual(fact["status"], "untrusted")
        self.assertEqual(paths, ["/v1/account"])

    async def test_quickbooks_rejects_wrong_invoice_and_boolean_balance(self):
        for invoice in [
            {"Id": "other", "Balance": 80},
            {"Id": "123", "Balance": True},
            {"Id": "123", "Balance": -1},
        ]:
            transport = httpx.MockTransport(
                lambda req, value=invoice: httpx.Response(200, json={"Invoice": value})
            )
            fact = await lookup_quickbooks_invoice_balance(
                source_version_id=VERSION,
                provider_account_id="realm123",
                invoice_id="123",
                access_token="secret",
                sandbox=True,
                timeout_ms=500,
                transport=transport,
            )
            self.assertEqual(fact["status"], "untrusted")

    async def test_contextual_predicate_thresholds_and_refusal_remain_distinct(self):
        question = DecisionsQuestion(
            type="predicate", instructions="Does the document contain secrets?", min_confidence=0.8
        )
        reviewed = extraction(question)
        for answer, status, expected in [
            ({"type": "predicate", "probability": 0.95}, "ok", True),
            ({"type": "predicate", "probability": 0.05}, "ok", False),
            ({"type": "predicate", "probability": 0.5}, "uncertain", None),
            ({"type": "refusal"}, "uncertain", None),
        ]:
            requests = []

            def respond(req, item=answer, captured=requests):
                body = json.loads(req.content)
                captured.append(body)
                return httpx.Response(
                    200, json={"model": "gpt-6-luna", "answers": [{**item, "name": "fact"}]}
                )

            extractor = new_openai_decisions_extractor(
                source=reviewed,
                question=question,
                api_key="private-model-key",
                transport=httpx.MockTransport(respond),
            )
            fact = await extract_context_fact(
                reviewed,
                "document_123",
                "record:document_123",
                datetime.now(UTC).isoformat(),
                b"selected source text",
                extractor,
            )
            self.assertEqual(fact["status"], status)
            self.assertEqual(requests[0]["input"], "selected source text")
            if status == "ok":
                self.assertIs(fact["value"]["sensitive"], expected)
            else:
                self.assertNotIn("value", fact)
            self.assertNotIn("private-model-key", json.dumps(fact))
            self.assertNotIn("selected source text", json.dumps(fact))

    async def test_wrong_extraction_provenance_and_invalid_type_are_untrusted(self):
        question = DecisionsQuestion(
            type="predicate", instructions="Sensitive?", min_confidence=0.8
        )
        reviewed = extraction(question)
        for model, value in [("wrong-model", True), ("gpt-6-luna", "false")]:

            async def extract(doc, model_id=model, answer=value):
                return ExtractionResult(
                    value=answer,
                    uncertain=False,
                    model_id=model_id,
                    model_config_sha256=reviewed.model_config_sha256,
                    prompt_version="reviewed-v1",
                )

            fact = await extract_context_fact(
                reviewed,
                "doc",
                "record:doc",
                datetime.now(UTC).isoformat(),
                b"safe sample",
                extract,
            )
            self.assertEqual(fact["status"], "untrusted")
            self.assertNotIn("value", fact)

    async def test_contextual_choice_and_score_are_bounded(self):
        for question, answer, expected in [
            (
                DecisionsQuestion(
                    type="choice",
                    instructions="Classify this request",
                    min_confidence=0.8,
                    choices=("ordinary", "sensitive"),
                ),
                {"type": "choice", "choice": "sensitive", "confidence": 0.95},
                "sensitive",
            ),
            (
                DecisionsQuestion(
                    type="score",
                    instructions="Rate the risk",
                    min_confidence=0.8,
                    levels=("low", "high"),
                ),
                {"type": "score", "score": 0.75, "confidence": 0.95},
                0.75,
            ),
        ]:
            reviewed = extraction(question)
            transport = httpx.MockTransport(
                lambda req, item=answer: httpx.Response(
                    200, json={"model": "gpt-6-luna", "answers": [{**item, "name": "fact"}]}
                )
            )
            extractor = new_openai_decisions_extractor(
                source=reviewed, question=question, api_key="secret", transport=transport
            )
            result = await extractor(b"safe sample")
            self.assertEqual(result.value, expected)
