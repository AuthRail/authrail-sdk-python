"""Bounded provider reads with credentials kept out of error messages."""

from __future__ import annotations

import asyncio

import httpx

from ._protocol import parse_object
from .types import AuthRailError, JSONObject


class InvalidProviderPayload(AuthRailError):
    """The dependency answered, but its body could not establish a trusted value."""


async def response_object(response: httpx.Response, limit: int) -> JSONObject:
    data = bytearray()
    async for chunk in response.aiter_bytes():
        if len(data) + len(chunk) > limit:
            raise AuthRailError("Provider response exceeds its size limit")
        data.extend(chunk)
    try:
        return parse_object(bytes(data))
    except AuthRailError:
        raise InvalidProviderPayload("Invalid provider JSON body") from None


async def provider_json(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    *,
    limit: int,
    seconds: float,
    body: bytes | None = None,
    expected_status: int = 200,
) -> JSONObject:
    try:
        async with (
            asyncio.timeout(seconds),
            client.stream(
                method,
                url,
                headers=headers,
                content=body,
                follow_redirects=False,
                timeout=seconds,
            ) as response,
        ):
            if response.status_code != expected_status:
                raise AuthRailError("Provider request unavailable")
            return await response_object(response, limit)
    except (httpx.HTTPError, TimeoutError, ValueError):
        raise AuthRailError("Provider request unavailable") from None


def valid_secret(value: str) -> bool:
    return type(value) is str and bool(value.strip()) and all(32 <= ord(c) < 127 for c in value)
