"""Application identities and advisory results for the local Runtime protocol."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Generic, Literal, TypeAlias, TypeVar

JSONValue: TypeAlias = "None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]"
JSONObject: TypeAlias = dict[str, JSONValue]
Phase: TypeAlias = Literal["tool_call", "tool_result"]
T = TypeVar("T")


class AuthRailError(Exception):
    """A safe configuration, protocol or availability error without customer payloads."""


@dataclass(frozen=True, kw_only=True)
class Operation:
    """One reviewed action bound to application-authenticated caller and resource IDs."""

    version_id: str
    action_key: str
    principal_id: str
    session_id: str
    principal_source: Literal["application_session", "service_identity"]
    resource_source: Literal["application_lookup", "not_applicable"]
    resource_id: str | None = None
    fact_resolutions: list[JSONObject] = field(default_factory=list, repr=False)
    trajectory: JSONObject | None = field(default=None, repr=False)
    traceparent: str | None = None


@dataclass(frozen=True)
class PreparedCall:
    """Immutable snapshot; call and result checks share this exact request identity."""

    request_id: str
    action_key: str
    traceparent: str | None
    _encoded: bytes = field(repr=False)

    def as_dict(self) -> JSONObject:
        """Return a detached copy so caller mutation cannot alter a prepared proof."""
        from ._protocol import parse_object

        return parse_object(self._encoded)


@dataclass(frozen=True)
class Decision:
    """Advisory rule outcome; it neither enforces a boundary nor proves execution."""

    request_id: str
    outcome: str
    coverage: str
    recording_status: str | None
    action_id: str | None
    _encoded: bytes = field(repr=False)

    def as_dict(self) -> JSONObject:
        """Return all protocol fields, including certificates and rule reasons."""
        from ._protocol import parse_object

        return parse_object(self._encoded)


@dataclass(frozen=True)
class Observation:
    """Independent call/result decisions or safe errors; never a tool result replacement."""

    call_decision: Decision | None
    call_error: AuthRailError | None
    result_decision: Decision | None
    result_error: AuthRailError | None


@dataclass(frozen=True)
class ObserveRun(Generic[T]):
    """Await result for business work and observation for advisory recording separately."""

    result: asyncio.Task[T]
    observation: asyncio.Task[Observation]
    call: PreparedCall | None
