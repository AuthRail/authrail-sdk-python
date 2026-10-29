"""Resolve an AI Inventory identity during setup; this never grants execution permission."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from ._http import provider_json, valid_secret
from ._protocol import snapshot
from .observe import _REF, _UUID, _matches
from .types import AuthRailError, JSONObject


async def discover(
    *,
    control_plane_url: str,
    setup_key: str,
    agent_key: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> JSONObject:
    """Use a short-lived tenant setup key to discover an item, never to authorize a tool."""
    try:
        url = urlsplit(control_plane_url)
        valid = (
            bool(url.hostname)
            and url.username is None
            and url.password is None
            and url.path in ("", "/")
            and not url.query
            and not url.fragment
            and "?" not in control_plane_url
            and "#" not in control_plane_url
            and not any(ord(c) < 33 for c in control_plane_url)
            and (
                url.scheme == "https"
                or (url.scheme == "http" and url.hostname in ("127.0.0.1", "::1"))
            )
        )
        if not valid or not _matches(_REF, agent_key) or not valid_secret(setup_key):
            raise ValueError("configuration")
    except (ValueError, TypeError, AttributeError):
        raise AuthRailError("Invalid discovery configuration") from None
    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        value = await provider_json(
            client,
            "POST",
            control_plane_url.rstrip("/") + "/runtime/discovery",
            {"Authorization": "Bearer " + setup_key, "Content-Type": "application/json"},
            body=snapshot({"agentKey": agent_key}),
            limit=8192,
            seconds=5,
            expected_status=201,
        )
    if any(
        not _matches(_UUID, value.get(k))
        for k in ("inventoryItemId", "inventoryRevisionId", "deploymentId")
    ) or value.get("confirmationStatus") not in ("discovered", "confirmed"):
        raise AuthRailError("Invalid discovery response")
    return value
