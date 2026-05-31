"""Tests for the registry-client boundary.

We don't deploy a real contract; instead we monkey-patch the contract-call
methods on a constructed RegistryClient and assert the bot logic survives
the value shapes the live contract will return (raw 20-byte addresses,
ABI-padded 32-byte addresses, reverts).
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def bot(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "verifications.db"))
    monkeypatch.setenv("DISCORD_TOKEN", "fake")
    monkeypatch.setenv("REGISTRY_ADDR", "0x" + "00" * 19 + "01")
    import eth_agent_verify_bot

    importlib.reload(eth_agent_verify_bot)
    return eth_agent_verify_bot


class _FakeClient:
    """Stand-in that satisfies the same surface RegistryClient exposes."""

    def __init__(self, owner=None, wallet=None, uri=None, owner_raises=False):
        self._owner = owner
        self._wallet = wallet
        self._uri = uri
        self._owner_raises = owner_raises
        self.chain_id = 8453

    def owner_of(self, agent_id):
        if self._owner_raises:
            raise RuntimeError("RPC down")
        return self._owner

    def agent_wallet(self, agent_id):
        return self._wallet

    def token_uri(self, agent_id):
        return self._uri


def _install_fake(bot, fake):
    bot._registry_client = fake


def test_still_controlled_owner_match(bot):
    _install_fake(bot, _FakeClient(owner="0xAaA0000000000000000000000000000000000001"))
    ref = bot.AgentRef(8453, "0xAaA0000000000000000000000000000000000001", 1)
    assert bot._still_controlled(ref, "0xAaA0000000000000000000000000000000000001") is True


def test_still_controlled_agent_wallet_match(bot):
    _install_fake(
        bot,
        _FakeClient(
            owner="0xAaA0000000000000000000000000000000000099",
            wallet="0xBbB0000000000000000000000000000000000002",
        ),
    )
    ref = bot.AgentRef(8453, "0xAaA0000000000000000000000000000000000001", 1)
    assert bot._still_controlled(ref, "0xBbB0000000000000000000000000000000000002") is True


def test_still_controlled_signer_no_longer_matches(bot):
    """User sold the NFT and never set agentWallet — sync should drop the
    binding (False) so the role gets removed."""
    _install_fake(
        bot,
        _FakeClient(
            owner="0xAaA0000000000000000000000000000000000099",
            wallet=None,
        ),
    )
    ref = bot.AgentRef(8453, "0xAaA0000000000000000000000000000000000001", 1)
    assert bot._still_controlled(ref, "0xCcC0000000000000000000000000000000000003") is False


def test_still_controlled_keeps_binding_on_rpc_failure(bot):
    """RPC blip MUST NOT trigger role removal — keep the binding live, let
    the next sync resolve it. Same safety net Tapseal has."""
    _install_fake(bot, _FakeClient(owner_raises=True))
    ref = bot.AgentRef(8453, "0xAaA0000000000000000000000000000000000001", 1)
    assert bot._still_controlled(ref, "0xCcC0000000000000000000000000000000000003") is True


def test_agent_wallet_decodes_20_byte(monkeypatch):
    """RegistryClient.agent_wallet must accept raw 20-byte address returns."""
    from web3 import Web3
    from registry_client import RegistryClient

    # Build instance without touching the network
    inst = RegistryClient.__new__(RegistryClient)
    inst.chain_id = 8453
    raw = b"\xaa" * 20

    class _C:
        class functions:
            @staticmethod
            def getMetadata(agent_id, key):
                class _Call:
                    @staticmethod
                    def call():
                        return raw
                return _Call()

    inst.contract = _C
    out = inst.agent_wallet(1)
    assert out == Web3.to_checksum_address(raw)
    # Mixed-case checksum, not all-lower
    assert out != out.lower()


def test_agent_wallet_decodes_32_byte_padded(monkeypatch):
    """And ABI-encoded 32-byte left-padded addresses (the more common shape)."""
    from web3 import Web3
    from registry_client import RegistryClient

    inst = RegistryClient.__new__(RegistryClient)
    inst.chain_id = 8453
    raw20 = b"\xbb" * 20

    class _C:
        class functions:
            @staticmethod
            def getMetadata(agent_id, key):
                class _Call:
                    @staticmethod
                    def call():
                        return b"\x00" * 12 + raw20
                return _Call()

    inst.contract = _C
    out = inst.agent_wallet(1)
    assert out == Web3.to_checksum_address(raw20)


def test_agent_wallet_returns_none_on_empty(monkeypatch):
    from registry_client import RegistryClient

    inst = RegistryClient.__new__(RegistryClient)
    inst.chain_id = 8453

    class _C:
        class functions:
            @staticmethod
            def getMetadata(agent_id, key):
                class _Call:
                    @staticmethod
                    def call():
                        return b""
                return _Call()

    inst.contract = _C
    assert inst.agent_wallet(1) is None


def test_agent_wallet_returns_none_on_revert(monkeypatch):
    from registry_client import RegistryClient

    inst = RegistryClient.__new__(RegistryClient)
    inst.chain_id = 8453

    class _C:
        class functions:
            @staticmethod
            def getMetadata(agent_id, key):
                class _Call:
                    @staticmethod
                    def call():
                        raise RuntimeError("execution reverted")
                return _Call()

    inst.contract = _C
    assert inst.agent_wallet(1) is None


def test_agent_wallet_returns_none_on_weird_length(monkeypatch):
    """If on-chain metadata is some unexpected length, ignore rather than
    assert — admin-set metadata is free-form."""
    from registry_client import RegistryClient

    inst = RegistryClient.__new__(RegistryClient)
    inst.chain_id = 8453

    class _C:
        class functions:
            @staticmethod
            def getMetadata(agent_id, key):
                class _Call:
                    @staticmethod
                    def call():
                        return b"\xab\xcd\xef"
                return _Call()

    inst.contract = _C
    assert inst.agent_wallet(1) is None
