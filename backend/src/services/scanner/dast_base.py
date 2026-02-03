from __future__ import annotations

from typing import Any, Awaitable, Callable, List, Optional


class AttackFindingsList(list):
    """List-like callable used for attack_findings compatibility."""

    def __init__(
        self,
        iterable: Optional[List[Any]] = None,
        call: Optional[Callable[..., Awaitable[List[Any]]]] = None,
    ) -> None:
        super().__init__(iterable or [])
        self._call = call

    async def __call__(self, *args: Any, **kwargs: Any) -> List[Any]:  # noqa: ANN401
        if not self._call:
            return list(self)
        return await self._call(*args, **kwargs)


class BaseDASTRunner:
    """Shared interface for DAST runners."""

    def __init__(self) -> None:
        self.attack_findings: AttackFindingsList = AttackFindingsList()

    async def scan(self, *args: Any, **kwargs: Any) -> List[Any]:  # noqa: ANN401
        return []

    async def get_attack_findings(self) -> List[Any]:
        return list(self.attack_findings)
