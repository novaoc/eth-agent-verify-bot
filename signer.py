"""
EIP-712 typed-data challenge for ERC-8004 agent verification.

The signer is whichever wallet currently controls the agent — that's either
the NFT owner (ownerOf(agentId) on the Identity Registry) or the address
stored under the reserved `agentWallet` metadata key. We accept either.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data


PRIMARY_TYPE = "AgentChallenge"

# EIP-712 type definitions. `name` and `version` go in the domain; the message
# itself carries the rest. `chainId` in the domain pins the signature to the
# registry's chain so a sig from chain A can't be replayed against chain B.
TYPES: dict[str, list[dict[str, str]]] = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
    ],
    PRIMARY_TYPE: [
        {"name": "discordId", "type": "string"},
        {"name": "agentId", "type": "uint256"},
        {"name": "registry", "type": "address"},
        {"name": "nonce", "type": "bytes32"},
        {"name": "deadline", "type": "uint256"},
    ],
}


@dataclass
class ChallengePayload:
    """All the inputs that go into the EIP-712 message. Stored alongside the
    pending challenge so /submit can rebuild the exact payload to recover from."""

    discord_id: str
    agent_id: int
    registry: str
    nonce_hex: str  # 0x-prefixed bytes32
    deadline: int
    chain_id: int


def build_typed_data(p: ChallengePayload) -> dict[str, Any]:
    """The exact dict passed to eth_signTypedData_v4 on the client side, and
    to encode_typed_data on the verify side. Identical bytes both ways — that
    invariant is what makes recover safe."""
    return {
        "types": TYPES,
        "primaryType": PRIMARY_TYPE,
        "domain": {
            "name": "EthAgentVerifyBot",
            "version": "1",
            "chainId": p.chain_id,
        },
        "message": {
            "discordId": p.discord_id,
            "agentId": p.agent_id,
            "registry": p.registry,
            "nonce": p.nonce_hex,
            "deadline": p.deadline,
        },
    }


def recover_signer(p: ChallengePayload, signature: str) -> str:
    """Recover the address that signed this EIP-712 payload. Returns the
    canonical EIP-55 checksum form. Raises on any decoding error — callers
    treat that as 'invalid signature', same as a wrong recovery."""
    typed = build_typed_data(p)
    message = encode_typed_data(full_message=typed)
    return Account.recover_message(message, signature=signature)
