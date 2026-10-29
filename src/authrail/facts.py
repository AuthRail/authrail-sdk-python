"""Read bounded business facts in the protected application, never provider writes."""

from __future__ import annotations

import base64
import hashlib
import math
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

import httpx

from ._async import with_deadline
from ._http import InvalidProviderPayload, provider_json, valid_secret
from ._protocol import MAX_VALUE, parse_object, snapshot
from .observe import _UUID, _matches
from .types import AuthRailError, JSONObject, JSONValue

_SOURCE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{2,159}\Z")
_ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")
_RECORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{1,159}\Z")
_LOCATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")
_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _observed_at(value: str) -> str:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None or moment.timestamp() > datetime.now(UTC).timestamp() + 5:
            raise ValueError("timestamp")
        return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise AuthRailError("Invalid fact observation time") from None


def _timeout(value: int) -> bool:
    return type(value) is int and 100 <= value <= 10_000


@dataclass(frozen=True, kw_only=True)
class CustomerSource:
    """Identity and account fixed by an exact reviewed Context Source Version."""

    source_version_id: str
    source_identity: str
    account_boundary: str
    lookup: str
    timeout_ms: int


@dataclass(frozen=True, kw_only=True)
class CustomerReadResult:
    """Authenticated application lookup; identity must match before its value is usable."""

    source_identity: str
    account_boundary: str
    lookup: str
    lookup_key: str
    observed_at: str
    value: JSONObject = field(repr=False)


CustomerRead = Callable[[str], Awaitable[CustomerReadResult]]


def _validate_source(source: CustomerSource, lookup_key: str) -> None:
    if (
        not _matches(_UUID, source.source_version_id)
        or not _matches(_SOURCE, source.source_identity)
        or not _matches(_ACCOUNT, source.account_boundary)
        or not _matches(_SOURCE, source.lookup)
        or not _timeout(source.timeout_ms)
        or type(lookup_key) is not str
        or not lookup_key
        or len(lookup_key.encode()) > 256
    ):
        raise AuthRailError("Invalid fact source configuration")


def _base(source: CustomerSource, lookup_key: str) -> JSONObject:
    return {
        "sourceVersionId": source.source_version_id,
        "sourceIdentity": source.source_identity,
        "accountBoundary": source.account_boundary,
        "lookup": source.lookup,
        "lookupKey": lookup_key,
        "authenticatedExecutor": True,
        "status": "unavailable",
    }


async def lookup_customer_fact(
    source: CustomerSource,
    lookup_key: str,
    read: CustomerRead,
) -> JSONObject:
    """Validate account/resource identity and return a typed fact, never permission."""
    _validate_source(source, lookup_key)
    if not callable(read):
        raise AuthRailError("Application fact reader is required")
    resolution = _base(source, lookup_key)
    try:
        result = await with_deadline(read(lookup_key), source.timeout_ms / 1000)
    except Exception:
        return resolution
    try:
        if (
            result.source_identity != source.source_identity
            or result.account_boundary != source.account_boundary
            or result.lookup != source.lookup
            or result.lookup_key != lookup_key
            or type(result.value) is not dict
        ):
            raise AuthRailError("Fact source identity mismatch")
        observed = _observed_at(result.observed_at)
        value = parse_object(snapshot(result.value, 16 * 1024))
    except Exception:
        return {**resolution, "status": "untrusted"}
    return {**resolution, "status": "ok", "observedAt": observed, "value": value}


def new_customer_api_reader(
    *,
    endpoint: str,
    bearer_token: str,
    source_identity: str,
    account_boundary: str,
    lookup: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CustomerRead:
    """Build a fixed HTTPS GET reader. Credentials and endpoint never come from the agent."""
    url = urlsplit(endpoint)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or "?" in endpoint
        or "#" in endpoint
        or any(ord(c) < 33 for c in endpoint)
        or not valid_secret(bearer_token)
        or not _matches(_SOURCE, source_identity)
        or not _matches(_SOURCE, lookup)
        or not _matches(_ACCOUNT, account_boundary)
    ):
        raise AuthRailError("Invalid customer API reader configuration")

    async def read(lookup_key: str) -> CustomerReadResult:
        if not _matches(_RECORD, lookup_key) or lookup_key in (".", ".."):
            raise AuthRailError("Invalid customer record key")
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
            value = await provider_json(
                client,
                "GET",
                endpoint.rstrip("/") + "/" + lookup_key,
                {"Authorization": "Bearer " + bearer_token, "Accept": "application/json"},
                limit=32 * 1024,
                seconds=10,
            )
        if (
            set(value) != {"accountId", "recordId", "observedAt", "data"}
            or type(value["accountId"]) is not str
            or type(value["recordId"]) is not str
            or type(value["observedAt"]) is not str
            or type(value["data"]) is not dict
        ):
            raise AuthRailError("Invalid customer API response")
        return CustomerReadResult(
            source_identity=source_identity,
            account_boundary=value["accountId"],
            lookup=lookup,
            lookup_key=value["recordId"],
            observed_at=value["observedAt"],
            value=value["data"],
        )

    return read


async def lookup_stripe_invoice_status(
    *,
    source_version_id: str,
    provider_account_id: str,
    invoice_id: str,
    secret_key: str,
    timeout_ms: int,
    connected_account: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
) -> JSONObject:
    """Read the exact Stripe account and invoice; a wrong account is untrusted context."""
    if (
        not _matches(_UUID, source_version_id)
        or not re.fullmatch(r"acct_[A-Za-z0-9]{8,80}", provider_account_id)
        or not re.fullmatch(r"in_[A-Za-z0-9]{4,100}", invoice_id)
        or not valid_secret(secret_key)
        or not _timeout(timeout_ms)
        or type(connected_account) is not bool
    ):
        raise AuthRailError("Invalid Stripe fact configuration")
    resolution: JSONObject = {
        "sourceVersionId": source_version_id,
        "providerAccountId": provider_account_id,
        "lookup": "invoice.retrieve",
        "lookupKey": invoice_id,
        "authenticatedExecutor": True,
        "status": "unavailable",
    }
    headers = {"Authorization": "Basic " + base64.b64encode((secret_key + ":").encode()).decode()}
    if connected_account:
        headers["Stripe-Account"] = provider_account_id
    try:
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:

            async def read() -> JSONObject:
                account = await provider_json(
                    client,
                    "GET",
                    "https://api.stripe.com/v1/account",
                    headers,
                    limit=MAX_VALUE,
                    seconds=timeout_ms / 1000,
                )
                if account.get("object") != "account" or account.get("id") != provider_account_id:
                    return {**resolution, "status": "untrusted"}
                invoice = await provider_json(
                    client,
                    "GET",
                    "https://api.stripe.com/v1/invoices/" + invoice_id,
                    headers,
                    limit=MAX_VALUE,
                    seconds=timeout_ms / 1000,
                )
                if (
                    invoice.get("object") != "invoice"
                    or invoice.get("id") != invoice_id
                    or invoice.get("status")
                    not in ("draft", "open", "paid", "uncollectible", "void")
                ):
                    return {**resolution, "status": "untrusted"}
                return {
                    **resolution,
                    "status": "ok",
                    "observedAt": _now(),
                    "value": {"status": invoice["status"]},
                }

            return await with_deadline(read(), timeout_ms / 1000)
    except Exception:
        return resolution


async def lookup_quickbooks_invoice_balance(
    *,
    source_version_id: str,
    provider_account_id: str,
    invoice_id: str,
    access_token: str,
    timeout_ms: int,
    sandbox: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
) -> JSONObject:
    """Read Invoice.Balance in one reviewed realm. Currency needs its own source."""
    if (
        not _matches(_UUID, source_version_id)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", provider_account_id)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", invoice_id)
        or not valid_secret(access_token)
        or not _timeout(timeout_ms)
        or type(sandbox) is not bool
    ):
        raise AuthRailError("Invalid QuickBooks fact configuration")
    resolution: JSONObject = {
        "sourceVersionId": source_version_id,
        "providerAccountId": provider_account_id,
        "lookup": "invoice.read",
        "lookupKey": invoice_id,
        "authenticatedExecutor": True,
        "status": "unavailable",
    }
    host = "sandbox-quickbooks.api.intuit.com" if sandbox else "quickbooks.api.intuit.com"
    try:
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
            value = await provider_json(
                client,
                "GET",
                f"https://{host}/v3/company/{provider_account_id}/invoice/{invoice_id}",
                {"Authorization": "Bearer " + access_token, "Accept": "application/json"},
                limit=MAX_VALUE,
                seconds=timeout_ms / 1000,
            )
        invoice = value.get("Invoice")
        if (
            type(invoice) is not dict
            or invoice.get("Id") != invoice_id
            or type(invoice.get("Balance")) not in (int, float)
        ):
            return {**resolution, "status": "untrusted"}
        balance = invoice["Balance"]
        if not isinstance(balance, (int, float)) or not math.isfinite(balance) or balance < 0:
            return {**resolution, "status": "untrusted"}
        return {
            **resolution,
            "status": "ok",
            "observedAt": _now(),
            "value": {"Invoice": {"Balance": balance}},
        }
    except InvalidProviderPayload:
        return {**resolution, "status": "untrusted"}
    except Exception:
        return resolution


@dataclass(frozen=True, kw_only=True)
class ExtractionSource(CustomerSource):
    """The reviewed model reading configuration, independent from the agent's model."""

    result_path: tuple[str, ...]
    value_type: Literal["string", "number", "boolean"]
    model_id: str
    model_config_sha256: str
    prompt_version: str
    max_input_bytes: int
    max_output_bytes: int


@dataclass(frozen=True, kw_only=True)
class ExtractionResult:
    """A bounded model assertion; uncertainty is explicit and never permission."""

    value: JSONValue = field(repr=False)
    uncertain: bool
    model_id: str
    model_config_sha256: str
    prompt_version: str


Extractor = Callable[[bytes], Awaitable[ExtractionResult]]


async def extract_context_fact(
    source: ExtractionSource,
    lookup_key: str,
    source_location: str,
    observed_at: str,
    document: bytes,
    extractor: Extractor,
) -> JSONObject:
    """Validate a selected model reading and retain provenance without reporting source bytes."""
    _validate_source(source, lookup_key)
    observed = _observed_at(observed_at)
    if (
        not _matches(_LOCATION, source_location)
        or not _matches(_VERSION, source.model_id)
        or not _matches(_DIGEST, source.model_config_sha256)
        or not _matches(_VERSION, source.prompt_version)
        or not 1 <= len(source.result_path) <= 8
        or any(not _matches(_FIELD, part) for part in source.result_path)
        or source.value_type not in ("string", "number", "boolean")
        or type(source.max_input_bytes) is not int
        or not 1 <= source.max_input_bytes <= MAX_VALUE
        or type(source.max_output_bytes) is not int
        or not 1 <= source.max_output_bytes <= 4096
        or not callable(extractor)
    ):
        raise AuthRailError("Invalid contextual extraction configuration")
    resolution = _base(source, lookup_key)
    if type(document) is not bytes or not 1 <= len(document) <= source.max_input_bytes:
        return resolution
    try:
        result = await with_deadline(extractor(document), source.timeout_ms / 1000)
    except Exception:
        return resolution
    if (
        not isinstance(result, ExtractionResult)
        or result.model_id != source.model_id
        or result.model_config_sha256 != source.model_config_sha256
        or result.prompt_version != source.prompt_version
        or type(result.uncertain) is not bool
    ):
        return {**resolution, "status": "untrusted"}
    provenance: JSONObject = {
        **resolution,
        "observedAt": observed,
        "extraction": {
            "sourceSha256": hashlib.sha256(document).hexdigest(),
            "sourceBytes": len(document),
            "sourceLocation": source_location,
            "modelId": result.model_id,
            "modelConfigSha256": result.model_config_sha256,
            "promptVersion": result.prompt_version,
            "extractedAt": _now(),
        },
    }
    if result.uncertain:
        return {**provenance, "status": "uncertain"}
    expected = {"string": (str,), "boolean": (bool,), "number": (int, float)}[source.value_type]
    if type(result.value) not in expected:
        return {**resolution, "status": "untrusted"}
    value: JSONValue = result.value
    for part in reversed(source.result_path):
        value = {part: value}
    try:
        bounded = parse_object(snapshot(value, source.max_output_bytes))
    except AuthRailError:
        return {**resolution, "status": "untrusted"}
    return {**provenance, "status": "ok", "value": bounded}
