"""Bound application callbacks without waiting for cancellation-resistant tasks."""

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

from .types import AuthRailError

T = TypeVar("T")


def _consume(task: asyncio.Task[T]) -> None:
    if not task.cancelled():
        task.exception()


async def with_deadline(work: Awaitable[T], seconds: float) -> T:
    """Reject a late answer even if trusted application code ignores cancellation."""
    task = asyncio.ensure_future(work)
    try:
        done, _ = await asyncio.wait([task], timeout=seconds)
        if not done:
            raise AuthRailError("Application reader or handler deadline exceeded")
        return task.result()
    finally:
        if not task.done():
            task.cancel()
            task.add_done_callback(_consume)
