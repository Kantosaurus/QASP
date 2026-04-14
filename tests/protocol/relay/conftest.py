"""Fixtures shared by the relay-manager tests."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest


@dataclass
class StubWSManager:
    """In-memory stand-in for scripts.qasp_server.ConnectionManager."""

    connected: set[str] = field(default_factory=set)
    sent: list[tuple[str, bytes]] = field(default_factory=list)

    def is_connected(self, did_str: str) -> bool:
        return did_str in self.connected

    async def send_bytes(self, did_str: str, payload: bytes) -> bool:
        if did_str not in self.connected:
            return False
        self.sent.append((did_str, payload))
        return True

    def connect(self, did_str: str) -> None:
        self.connected.add(did_str)

    def disconnect(self, did_str: str) -> None:
        self.connected.discard(did_str)


@pytest.fixture
def stub_ws():
    ws = StubWSManager()
    ws.connect("did:qasp:alice")
    ws.connect("did:qasp:bob")
    return ws
