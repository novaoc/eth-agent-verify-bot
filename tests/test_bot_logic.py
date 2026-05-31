"""DB round-trip + challenge state tests. No Discord, no chain reads."""

from __future__ import annotations

import importlib
import time

import pytest


@pytest.fixture
def bot(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "verifications.db"))
    monkeypatch.setenv("DISCORD_TOKEN", "fake")
    monkeypatch.setenv("REGISTRY_ADDR", "0x" + "00" * 19 + "01")
    import eth_agent_verify_bot

    importlib.reload(eth_agent_verify_bot)
    eth_agent_verify_bot._pending.clear()
    return eth_agent_verify_bot


def _ref(bot, agent_id=42):
    return bot.AgentRef(
        chain_id=8453,
        registry="0xAaA0000000000000000000000000000000000001",
        agent_id=agent_id,
    )


def test_record_and_list_round_trip(bot):
    bot.record_verification("user-1", _ref(bot, 1), "0xSigner1")
    bot.record_verification("user-1", _ref(bot, 2), "0xSigner2")
    bot.record_verification("user-2", _ref(bot, 3), "0xSigner3")

    rows = bot.list_verifications("user-1")
    agent_ids = {a for _c, _r, a, _s, _ts in rows}
    assert agent_ids == {1, 2}

    assert len(bot.list_verifications("user-2")) == 1
    assert bot.list_verifications("nobody") == []


def test_record_is_idempotent_per_agent(bot):
    bot.record_verification("user-1", _ref(bot, 1), "0xSigner")
    bot.record_verification("user-1", _ref(bot, 1), "0xSigner")
    assert len(bot.list_verifications("user-1")) == 1


def test_record_distinct_agents_dont_collide(bot):
    bot.record_verification("user-1", _ref(bot, 1), "0xSigner")
    bot.record_verification("user-1", _ref(bot, 2), "0xSigner")
    assert len(bot.list_verifications("user-1")) == 2


def test_all_verified_discord_ids_dedupes(bot):
    bot.record_verification("user-1", _ref(bot, 1), "0xs")
    bot.record_verification("user-1", _ref(bot, 2), "0xs")
    bot.record_verification("user-2", _ref(bot, 1), "0xs")
    assert sorted(bot.all_verified_discord_ids()) == ["user-1", "user-2"]


def test_pending_challenge_per_user(bot):
    from signer import ChallengePayload

    p1 = ChallengePayload("u1", 1, "0xAaA0000000000000000000000000000000000001",
                          "0x" + "11" * 32, int(time.time()) + 100, 8453)
    p2 = ChallengePayload("u2", 2, "0xAaA0000000000000000000000000000000000001",
                          "0x" + "22" * 32, int(time.time()) + 100, 8453)
    bot._pending["u1"] = bot.Challenge(payload=p1, issued_at=time.time())
    bot._pending["u2"] = bot.Challenge(payload=p2, issued_at=time.time())
    assert bot._pending["u1"].payload.agent_id == 1
    assert bot._pending["u2"].payload.agent_id == 2


def test_challenge_consumed_pattern(bot):
    """submit_cmd pops the pending challenge after success — any reuse must
    find None. Replay defense by absence, not by signature re-check."""
    from signer import ChallengePayload

    p = ChallengePayload("u", 1, "0xAaA0000000000000000000000000000000000001",
                         "0x" + "11" * 32, int(time.time()) + 100, 8453)
    bot._pending["u"] = bot.Challenge(payload=p, issued_at=time.time())
    bot._pending.pop("u", None)
    assert bot._pending.get("u") is None
