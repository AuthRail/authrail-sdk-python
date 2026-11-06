"""Resolve reviewed Data requirements with private, once-bound application readers."""

from __future__ import annotations

import asyncio
import inspect
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, cast

import httpx

from ._async import with_deadline
from ._http import response_object, valid_secret
from .types import AuthRailError, JSONObject, JSONValue, Phase, PreparedCall

if TYPE_CHECKING:
    from .facts import CustomerRead

_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_SOURCE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{2,159}\Z")
_ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")
_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,79}\Z")
_FORBIDDEN = {"__proto__", "prototype", "constructor"}


@dataclass(frozen=True, kw_only=True)
class DataResourceContext:
    """Trusted application identity for resolving a target, excluding agent arguments."""

    principal_id: str
    session_id: str
    resource_id: str | None
    operation_version_id: str


@dataclass(frozen=True, kw_only=True)
class DataSourceBinding:
    """Private reader binding for one exact source version; never expose it to the agent."""

    source_version_id: str
    kind: Literal["stripe", "quickbooks", "customer_api", "database", "mcp", "sdk"]
    resolve_resource: Callable[[DataResourceContext], str | Awaitable[str]] = field(repr=False)
    provider_account_id: str = ""
    source_identity: str = ""
    account_boundary: str = ""
    lookup: str = ""
    read: CustomerRead | None = field(default=None, repr=False)
    secret_key: str | Callable[[], str | Awaitable[str]] = field(default="", repr=False)
    access_token: str | Callable[[], str | Awaitable[str]] = field(default="", repr=False)
    connected_account: bool = False
    sandbox: bool = False
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)


def _invalid() -> None:
    raise AuthRailError("Invalid Data requirements or source bindings")


def registered_data_sources(
    bindings: Sequence[DataSourceBinding] | None,
) -> tuple[DataSourceBinding, ...] | None:
    if bindings is None:
        return None
    if len(bindings) > 32:
        _invalid()
    seen: set[str] = set()
    for binding in bindings:
        if (
            not isinstance(binding, DataSourceBinding)
            or not _UUID.fullmatch(binding.source_version_id)
            or binding.source_version_id in seen
            or not callable(binding.resolve_resource)
        ):
            _invalid()
        seen.add(binding.source_version_id)
        if binding.kind == "stripe":
            if (
                not re.fullmatch(r"acct_[A-Za-z0-9]{8,80}", binding.provider_account_id)
                or (not callable(binding.secret_key) and not valid_secret(binding.secret_key))
                or type(binding.connected_account) is not bool
            ):
                _invalid()
        elif binding.kind == "quickbooks":
            if (
                not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", binding.provider_account_id)
                or (not callable(binding.access_token) and not valid_secret(binding.access_token))
                or type(binding.sandbox) is not bool
            ):
                _invalid()
        elif (
            binding.kind not in ("customer_api", "database", "mcp", "sdk")
            or not _SOURCE.fullmatch(binding.source_identity)
            or not _ACCOUNT.fullmatch(binding.account_boundary)
            or not _SOURCE.fullmatch(binding.lookup)
            or not callable(binding.read)
        ):
            _invalid()
    return tuple(bindings)


def _source(raw: JSONValue) -> tuple[str, JSONObject]:
    if (
        type(raw) is not dict
        or set(raw) != {"sourceVersionId", "contract"}
        or type(raw.get("sourceVersionId")) is not str
        or not _UUID.fullmatch(cast(str, raw["sourceVersionId"]))
        or type(raw.get("contract")) is not dict
    ):
        _invalid()
    item = cast(JSONObject, raw)
    c = cast(JSONObject, item["contract"])
    common = {"formatVersion", "queryField", "factKey", "maxAgeSeconds", "timeoutMs", "failure"}
    query = c.get("queryField")
    if (
        type(query) is not dict
        or set(query) != {"root", "path"}
        or query.get("root") != "arguments"
        or type(query.get("path")) is not list
        or not 1 <= len(cast(list[JSONValue], query["path"])) <= 12
        or any(
            type(p) is not str or not p or len(p) > 80 or p in _FORBIDDEN
            for p in cast(list[JSONValue], query["path"])
        )
        or type(c.get("factKey")) is not str
        or not _FIELD.fullmatch(cast(str, c["factKey"]))
        or type(c.get("maxAgeSeconds")) is not int
        or not 1 <= cast(int, c["maxAgeSeconds"]) <= 3600
        or type(c.get("timeoutMs")) is not int
        or not 100 <= cast(int, c["timeoutMs"]) <= 10000
        or c.get("failure") != "unavailable"
    ):
        _invalid()
    version = c.get("formatVersion")
    if type(version) is not int:
        _invalid()
    if version in (1, 3):
        if set(c) != common | {"provider", "lookup", "providerAccountId", "resultField"}:
            _invalid()
        if type(c.get("providerAccountId")) is not str:
            _invalid()
        if version == 1:
            if (
                c.get("provider") != "stripe"
                or c.get("lookup") != "invoice.retrieve"
                or c.get("resultField") != "status"
                or not re.fullmatch(r"acct_[A-Za-z0-9]{8,80}", cast(str, c["providerAccountId"]))
            ):
                _invalid()
        elif (
            c.get("provider") != "quickbooks"
            or c.get("lookup") != "invoice.read"
            or c.get("resultField") != "Balance"
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", cast(str, c["providerAccountId"]))
        ):
            _invalid()
    elif version == 4:
        if (
            set(c)
            != common
            | {"kind", "sourceIdentity", "lookup", "accountBoundary", "resultPath", "valueType"}
            or c.get("kind") not in ("customer_api", "database", "mcp", "sdk")
            or type(c.get("sourceIdentity")) is not str
            or not _SOURCE.fullmatch(cast(str, c["sourceIdentity"]))
            or type(c.get("accountBoundary")) is not str
            or not _ACCOUNT.fullmatch(cast(str, c["accountBoundary"]))
            or type(c.get("lookup")) is not str
            or not _SOURCE.fullmatch(cast(str, c["lookup"]))
            or c.get("valueType") not in ("string", "number", "boolean")
            or type(c.get("resultPath")) is not list
            or not 1 <= len(cast(list[JSONValue], c["resultPath"])) <= 8
            or any(
                type(p) is not str or not _FIELD.fullmatch(p) or p in _FORBIDDEN
                for p in cast(list[JSONValue], c["resultPath"])
            )
        ):
            _invalid()
    else:
        _invalid()
    return cast(str, item["sourceVersionId"]), c


async def resolve_data(
    client: httpx.AsyncClient,
    endpoint: str,
    token: str,
    bindings: tuple[DataSourceBinding, ...] | None,
    call: PreparedCall,
    phase: Phase,
) -> tuple[PreparedCall, str | None, int | None]:
    if bindings is None:
        return call, None, None
    body = call.as_dict()
    headers = {"Authorization": "Bearer " + token}
    if call.traceparent:
        headers["traceparent"] = call.traceparent
    try:
        async with asyncio.timeout(4):
            async with client.stream(
                "GET",
                endpoint + "/data-requirements",
                params={"operationVersionId": str(body["operationVersionId"]), "phase": phase},
                headers=headers,
                timeout=4,
            ) as response:
                if response.status_code != 200:
                    raise AuthRailError("Data requirements unavailable")
                plan = await response_object(response, 128 * 1024)
    except (httpx.HTTPError, TimeoutError):
        raise AuthRailError("Data requirements unavailable") from None
    if (
        set(plan)
        != {
            "formatVersion",
            "operationVersionId",
            "phase",
            "bundleId",
            "sequence",
            "coverage",
            "requirements",
        }
        or type(plan.get("formatVersion")) is not int
        or plan.get("formatVersion") != 1
        or plan.get("operationVersionId") != body["operationVersionId"]
        or plan.get("phase") != phase
        or plan.get("coverage") != "evaluated"
        or type(plan.get("bundleId")) is not str
        or not _UUID.fullmatch(cast(str, plan["bundleId"]))
        or type(plan.get("sequence")) is not int
        or cast(int, plan["sequence"]) < 1
        or type(plan.get("requirements")) is not list
        or len(cast(list[JSONValue], plan["requirements"])) > 32
    ):
        _invalid()
    sources = [_source(raw) for raw in cast(list[JSONValue], plan["requirements"])]
    ids = [source_id for source_id, _ in sources]
    if len(set(ids)) != len(ids):
        _invalid()
    manual = cast(list[JSONObject], body.get("factResolutions", []))
    manual_ids = [str(fact.get("sourceVersionId")) for fact in manual]
    if len(set(manual_ids)) != len(manual_ids) or (
        phase == "tool_call" and set(ids).intersection(manual_ids)
    ):
        _invalid()
    identity = cast(JSONObject, body["attribution"])
    context = DataResourceContext(
        principal_id=str(identity["principalId"]),
        session_id=str(identity["sessionId"]),
        resource_id=cast(str | None, identity.get("resourceId")),
        operation_version_id=str(body["operationVersionId"]),
    )

    semaphore = asyncio.Semaphore(4)
    deadline = asyncio.get_running_loop().time() + 10

    async def read_one(source_id: str, c: JSONObject) -> JSONObject:
        source_deadline = asyncio.get_running_loop().time() + cast(int, c["timeoutMs"]) / 1000
        from .facts import (
            CustomerSource,
            lookup_customer_fact,
            lookup_quickbooks_invoice_balance,
            lookup_stripe_invoice_status,
        )

        base: JSONObject = {
            "sourceVersionId": source_id,
            "lookup": c["lookup"],
            "lookupKey": "",
            "authenticatedExecutor": True,
            "status": "unavailable",
        }
        if c["formatVersion"] == 4:
            base.update(sourceIdentity=c["sourceIdentity"], accountBoundary=c["accountBoundary"])
        else:
            base["providerAccountId"] = c["providerAccountId"]
        lookup: JSONValue = body["arguments"]
        for part in cast(list[str], cast(JSONObject, c["queryField"])["path"]):
            lookup = lookup.get(part) if type(lookup) is dict else None
        if type(lookup) is not str or not lookup or len(lookup.encode()) > 256:
            return base
        base["lookupKey"] = lookup
        binding = next((b for b in bindings if b.source_version_id == source_id), None)
        if binding is None or asyncio.get_running_loop().time() >= min(deadline, source_deadline):
            return base
        matches = (
            (
                binding.kind == c["kind"]
                and binding.source_identity == c["sourceIdentity"]
                and binding.account_boundary == c["accountBoundary"]
                and binding.lookup == c["lookup"]
            )
            if c["formatVersion"] == 4
            else binding.kind == c["provider"]
            and binding.provider_account_id == c["providerAccountId"]
        )
        if not matches:
            return {**base, "status": "untrusted"}
        try:

            async def resolve() -> str:
                result = binding.resolve_resource(context)
                return await result if inspect.isawaitable(result) else result

            trusted_key = await with_deadline(resolve(), cast(int, c["timeoutMs"]) / 1000)
            if type(trusted_key) is not str or trusted_key != lookup:
                return {**base, "status": "untrusted"}
            if asyncio.get_running_loop().time() >= min(deadline, source_deadline):
                return base

            async def credential(value: str | Callable[[], str | Awaitable[str]]) -> str:
                if callable(value):
                    selected = value()
                    value = await selected if inspect.isawaitable(selected) else selected
                if not valid_secret(value) or asyncio.get_running_loop().time() >= min(
                    deadline, source_deadline
                ):
                    raise AuthRailError("Data credential unavailable")
                return value

            if binding.kind == "stripe":
                return await lookup_stripe_invoice_status(
                    source_version_id=source_id,
                    provider_account_id=binding.provider_account_id,
                    invoice_id=lookup,
                    secret_key=await credential(binding.secret_key),
                    timeout_ms=cast(int, c["timeoutMs"]),
                    connected_account=binding.connected_account,
                    transport=binding.transport,
                )
            if binding.kind == "quickbooks":
                return await lookup_quickbooks_invoice_balance(
                    source_version_id=source_id,
                    provider_account_id=binding.provider_account_id,
                    invoice_id=lookup,
                    access_token=await credential(binding.access_token),
                    timeout_ms=cast(int, c["timeoutMs"]),
                    sandbox=binding.sandbox,
                    transport=binding.transport,
                )
            if binding.read is None:
                return base
            return await lookup_customer_fact(
                CustomerSource(
                    source_version_id=source_id,
                    source_identity=binding.source_identity,
                    account_boundary=binding.account_boundary,
                    lookup=binding.lookup,
                    timeout_ms=cast(int, c["timeoutMs"]),
                ),
                lookup,
                binding.read,
            )
        except Exception:
            return base

    async def bounded_read(source_id: str, c: JSONObject) -> JSONObject:
        async with semaphore:
            return await with_deadline(read_one(source_id, c), cast(int, c["timeoutMs"]) / 1000)

    try:
        facts = await with_deadline(
            asyncio.gather(*(bounded_read(source_id, c) for source_id, c in sources)), 10
        )
    except Exception:
        facts = []
        for source_id, c in sources:
            lookup_value: JSONValue = body["arguments"]
            for part in cast(list[str], cast(JSONObject, c["queryField"])["path"]):
                lookup_value = lookup_value.get(part) if type(lookup_value) is dict else None
            facts.append(
                {
                    "sourceVersionId": source_id,
                    "lookup": c["lookup"],
                    "lookupKey": lookup_value if type(lookup_value) is str else "",
                    "authenticatedExecutor": True,
                    "status": "unavailable",
                    **(
                        {
                            "sourceIdentity": c["sourceIdentity"],
                            "accountBoundary": c["accountBoundary"],
                        }
                        if c["formatVersion"] == 4
                        else {"providerAccountId": c["providerAccountId"]}
                    ),
                }
            )
    from ._protocol import canonical

    body["factResolutions"] = cast(
        list[JSONValue], [fact for fact in manual if fact.get("sourceVersionId") not in ids] + facts
    )
    fresh = PreparedCall(
        call.request_id, call.action_key, call.traceparent, canonical(body).encode()
    )
    return fresh, cast(str, plan["bundleId"]), cast(int, plan["sequence"])
