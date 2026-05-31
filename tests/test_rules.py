"""Tests for the role-rule storage layer + evaluator.

Pure-Python; no Discord, no network, no contract reads. Exercises rule
matching against synthesized AgentFacts.
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


def _facts(
    bot,
    *,
    chain_id=8453,
    registry="0xAaA0000000000000000000000000000000000001",
    agent_id=1,
    agent_type=None,
    trust_models=(),
    service_protos=(),
):
    return bot.AgentFacts(
        chain_id=chain_id,
        registry=registry,
        agent_id=agent_id,
        agent_type=agent_type,
        trust_models=frozenset(trust_models),
        service_protos=frozenset(service_protos),
    )


# ---- storage layer --------------------------------------------------------


def test_add_then_list_round_trip(bot):
    rid = bot.add_role_rule("g", "trust_model", "tee-attestation", "role-A")
    rules = bot.list_role_rules("g")
    assert len(rules) == 1
    rid2, mtype, mvalue, role_id = rules[0]
    assert rid2 == rid
    assert (mtype, mvalue, role_id) == ("trust_model", "tee-attestation", "role-A")


def test_add_is_idempotent(bot):
    a = bot.add_role_rule("g", "registry", "8453:0xabc", "r")
    b = bot.add_role_rule("g", "registry", "8453:0xabc", "r")
    assert a == b
    assert len(bot.list_role_rules("g")) == 1


def test_invalid_match_type_rejected(bot):
    with pytest.raises(ValueError):
        bot.add_role_rule("g", "not-a-real-type", "v", "r")


def test_remove_only_within_guild(bot):
    rid = bot.add_role_rule("guild-1", "trust_model", "reputation", "r")
    assert bot.remove_role_rule(rid, "guild-2") is False
    assert bot.remove_role_rule(rid, "guild-1") is True
    assert bot.list_role_rules("guild-1") == []


# ---- evaluator ------------------------------------------------------------


def test_no_rules_returns_empty(bot):
    assert bot.evaluate_rules("g", [_facts(bot, agent_type="foo")]) == []


def test_no_agents_returns_empty(bot):
    bot.add_role_rule("g", "trust_model", "reputation", "r")
    assert bot.evaluate_rules("g", []) == []


def test_registry_rule_match(bot):
    bot.add_role_rule("g", "registry", "8453:0xAaA0000000000000000000000000000000000001", "role-A")
    f = _facts(bot, registry="0xAaA0000000000000000000000000000000000001")
    assert bot.evaluate_rules("g", [f]) == ["role-A"]


def test_registry_rule_case_insensitive(bot):
    """Addresses are case-insensitive at the protocol level; rule eval matches
    that so admins don't get burned by EIP-55 mixed-case copy-paste."""
    bot.add_role_rule("g", "registry", "8453:0xaaa0000000000000000000000000000000000001", "role-A")
    f = _facts(bot, registry="0xAaA0000000000000000000000000000000000001")
    assert bot.evaluate_rules("g", [f]) == ["role-A"]


def test_registry_rule_wrong_chain_doesnt_match(bot):
    bot.add_role_rule("g", "registry", "1:0xAaA0000000000000000000000000000000000001", "role-A")
    f = _facts(bot, chain_id=8453, registry="0xAaA0000000000000000000000000000000000001")
    assert bot.evaluate_rules("g", [f]) == []


def test_trust_model_match(bot):
    bot.add_role_rule("g", "trust_model", "tee-attestation", "role-tee")
    f = _facts(bot, trust_models=("tee-attestation", "reputation"))
    assert bot.evaluate_rules("g", [f]) == ["role-tee"]


def test_trust_model_case_insensitive(bot):
    bot.add_role_rule("g", "trust_model", "TEE-Attestation", "role-tee")
    f = _facts(bot, trust_models=("tee-attestation",))
    assert bot.evaluate_rules("g", [f]) == ["role-tee"]


def test_trust_model_miss(bot):
    bot.add_role_rule("g", "trust_model", "zkml", "role-zkml")
    f = _facts(bot, trust_models=("reputation",))
    assert bot.evaluate_rules("g", [f]) == []


def test_agent_type_match(bot):
    bot.add_role_rule("g", "agent_type", "Validator", "role-val")
    f = _facts(bot, agent_type="Validator")
    assert bot.evaluate_rules("g", [f]) == ["role-val"]


def test_agent_type_is_case_sensitive(bot):
    """`type` is a free-form spec field; we preserve case in matching since
    that's how the agent author chose to declare it."""
    bot.add_role_rule("g", "agent_type", "Validator", "role-val")
    f = _facts(bot, agent_type="validator")
    assert bot.evaluate_rules("g", [f]) == []


def test_service_proto_match(bot):
    bot.add_role_rule("g", "service_proto", "mcp", "role-mcp")
    f = _facts(bot, service_protos=("mcp", "a2a"))
    assert bot.evaluate_rules("g", [f]) == ["role-mcp"]


def test_evaluate_dedupes_when_multiple_rules_target_same_role(bot):
    bot.add_role_rule("g", "trust_model", "reputation", "role-A")
    bot.add_role_rule("g", "service_proto", "mcp", "role-A")
    f = _facts(bot, trust_models=("reputation",), service_protos=("mcp",))
    assert bot.evaluate_rules("g", [f]) == ["role-A"]


def test_evaluate_isolated_per_guild(bot):
    bot.add_role_rule("guild-A", "trust_model", "reputation", "role-A")
    bot.add_role_rule("guild-B", "trust_model", "reputation", "role-B")
    f = _facts(bot, trust_models=("reputation",))
    assert bot.evaluate_rules("guild-A", [f]) == ["role-A"]
    assert bot.evaluate_rules("guild-B", [f]) == ["role-B"]


def test_evaluate_aggregates_across_multiple_agents(bot):
    """A member can have multiple verified agents; matching any of them is
    enough to grant the role."""
    bot.add_role_rule("g", "trust_model", "zkml", "role-zk")
    a1 = _facts(bot, agent_id=1, trust_models=("reputation",))
    a2 = _facts(bot, agent_id=2, trust_models=("zkml",))
    assert bot.evaluate_rules("g", [a1, a2]) == ["role-zk"]


# ---- facts builder --------------------------------------------------------


def test_facts_from_registration_handles_missing_fields(bot):
    ref = bot.AgentRef(chain_id=8453, registry="0xAaa", agent_id=7)
    f = bot.facts_from_registration(ref, None)
    assert f.agent_type is None
    assert f.trust_models == frozenset()
    assert f.service_protos == frozenset()


def test_facts_from_registration_normalizes_case(bot):
    ref = bot.AgentRef(chain_id=8453, registry="0xAaa", agent_id=7)
    f = bot.facts_from_registration(
        ref,
        {
            "type": "Oracle",
            "supportedTrustModels": ["TEE-Attestation", "Reputation"],
            "services": [
                {"protocol": "MCP", "endpoint": "https://x"},
                {"protocol": "a2a", "endpoint": "https://y"},
            ],
        },
    )
    assert f.agent_type == "Oracle"
    assert f.trust_models == frozenset({"tee-attestation", "reputation"})
    assert f.service_protos == frozenset({"mcp", "a2a"})


def test_facts_from_registration_skips_malformed_services(bot):
    ref = bot.AgentRef(chain_id=8453, registry="0xAaa", agent_id=7)
    f = bot.facts_from_registration(
        ref,
        {
            "services": [
                {"protocol": "mcp"},
                {"endpoint": "https://no-proto"},
                "not-a-dict",
            ]
        },
    )
    assert f.service_protos == frozenset({"mcp"})


# ---- role sync diff -------------------------------------------------------


def test_managed_role_ids_includes_all_rules(bot):
    bot.add_role_rule("g", "registry", "8453:0xa", "role-A")
    bot.add_role_rule("g", "trust_model", "reputation", "role-B")
    assert bot.managed_role_ids("g") == {"role-A", "role-B"}


def test_managed_role_ids_includes_verified_role(bot, monkeypatch):
    monkeypatch.setattr(bot, "VERIFIED_ROLE_ID", 999)
    bot.add_role_rule("g", "registry", "8453:0xa", "role-A")
    assert bot.managed_role_ids("g") == {"role-A", "999"}


def test_role_diff_adds_target_roles(bot):
    add, remove = bot.compute_role_diff(
        member_role_ids={"existing"},
        target_role_ids={"existing", "new"},
        managed={"new"},
    )
    assert add == {"new"}
    assert remove == set()


def test_role_diff_removes_only_managed(bot):
    add, remove = bot.compute_role_diff(
        member_role_ids={"managed-stale", "other-bot-role"},
        target_role_ids=set(),
        managed={"managed-stale"},
    )
    assert remove == {"managed-stale"}
    assert add == set()


def test_role_diff_idempotent(bot):
    add, remove = bot.compute_role_diff(
        member_role_ids={"r"},
        target_role_ids={"r"},
        managed={"r"},
    )
    assert add == set() and remove == set()


# ---- agent ref parsing ----------------------------------------------------


def test_parse_composite_form(bot):
    ref = bot.parse_agent_ref(
        "eip155:8453:0x000000000000000000000000000000000000bEEF:42"
    )
    assert ref is not None
    assert ref.chain_id == 8453
    assert ref.agent_id == 42
    assert ref.registry.lower() == "0x000000000000000000000000000000000000beef"


def test_parse_bare_integer_uses_configured_registry(bot):
    ref = bot.parse_agent_ref("99")
    assert ref is not None
    assert ref.chain_id == 8453
    assert ref.agent_id == 99


def test_parse_rejects_garbage(bot):
    assert bot.parse_agent_ref("not-an-id") is None
    assert bot.parse_agent_ref("eip155:8453:notaddr:42") is None


def test_composite_round_trips(bot):
    s = "eip155:8453:0x000000000000000000000000000000000000bEEF:42"
    ref = bot.parse_agent_ref(s)
    assert ref is not None
    # Re-emit normalizes the registry to checksum form
    assert ref.composite() == "eip155:8453:0x000000000000000000000000000000000000bEEF:42"
