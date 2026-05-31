"""End-to-end tests of the EIP-712 challenge build + recover round-trip."""

from __future__ import annotations

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from signer import ChallengePayload, build_typed_data, recover_signer


def _payload(addr: str) -> ChallengePayload:
    return ChallengePayload(
        discord_id="999000",
        agent_id=42,
        registry="0x000000000000000000000000000000000000bEEF",
        nonce_hex="0x" + "ab" * 32,
        deadline=1_999_999_999,
        chain_id=8453,
    )


def _sign(p: ChallengePayload, priv_key: str) -> str:
    typed = build_typed_data(p)
    msg = encode_typed_data(full_message=typed)
    return Account.sign_message(msg, private_key=priv_key).signature.hex()


def test_round_trip(owner_wallet):
    p = _payload(owner_wallet.address)
    sig = _sign(p, owner_wallet.key)
    recovered = recover_signer(p, sig)
    assert recovered == owner_wallet.address


def test_recover_returns_eip55(owner_wallet):
    p = _payload(owner_wallet.address)
    sig = _sign(p, owner_wallet.key)
    recovered = recover_signer(p, sig)
    # Mixed-case checksum is the canonical form
    assert recovered == owner_wallet.address
    assert recovered != owner_wallet.address.lower()


def test_tampered_discord_id_recovers_to_different_address(owner_wallet):
    """The challenge binds discord_id — re-running recover against a payload
    with a different discord_id MUST recover to a different (random-ish)
    address, not to the original signer."""
    p = _payload(owner_wallet.address)
    sig = _sign(p, owner_wallet.key)
    p2 = ChallengePayload(**{**p.__dict__, "discord_id": "different-id"})
    recovered = recover_signer(p2, sig)
    assert recovered != owner_wallet.address


def test_tampered_nonce_recovers_to_different_address(owner_wallet):
    p = _payload(owner_wallet.address)
    sig = _sign(p, owner_wallet.key)
    p2 = ChallengePayload(**{**p.__dict__, "nonce_hex": "0x" + "cd" * 32})
    recovered = recover_signer(p2, sig)
    assert recovered != owner_wallet.address


def test_wrong_chain_id_recovers_to_different_address(owner_wallet):
    """The chainId is in the domain separator — same nonce signed under chain
    A cannot be replayed against the registry on chain B."""
    p = _payload(owner_wallet.address)
    sig = _sign(p, owner_wallet.key)
    p2 = ChallengePayload(**{**p.__dict__, "chain_id": 1})
    recovered = recover_signer(p2, sig)
    assert recovered != owner_wallet.address


def test_signature_from_different_key_recovers_to_different_address(
    owner_wallet, stranger_wallet
):
    p = _payload(owner_wallet.address)
    sig = _sign(p, stranger_wallet.key)
    recovered = recover_signer(p, sig)
    assert recovered == stranger_wallet.address
    assert recovered != owner_wallet.address


def test_garbage_signature_rejected(owner_wallet):
    p = _payload(owner_wallet.address)
    with pytest.raises(Exception):
        recover_signer(p, "0xAA")


def test_typed_data_shape_matches_eip712(owner_wallet):
    """Sanity check the structure the signer page must build in JS — these
    field names and types are part of the contract with the front-end."""
    p = _payload(owner_wallet.address)
    typed = build_typed_data(p)
    assert typed["primaryType"] == "AgentChallenge"
    assert typed["domain"]["chainId"] == 8453
    assert typed["domain"]["name"] == "EthAgentVerifyBot"
    fields = {f["name"]: f["type"] for f in typed["types"]["AgentChallenge"]}
    assert fields == {
        "discordId": "string",
        "agentId": "uint256",
        "registry": "address",
        "nonce": "bytes32",
        "deadline": "uint256",
    }
