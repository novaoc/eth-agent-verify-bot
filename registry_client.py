"""
Thin wrapper around the ERC-8004 Identity Registry contract.

Isolated behind a small class so tests can stub it without touching web3
or an RPC endpoint — the bot's logic only depends on the three methods
defined here.
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from pathlib import Path

import httpx
from eth_account import Account  # noqa: F401  (re-exported for tests)
from web3 import Web3

log = logging.getLogger(__name__)

ABI_PATH = Path(__file__).parent / "abi" / "identity_registry.json"
AGENT_WALLET_KEY = "agentWallet"


@lru_cache(maxsize=1)
def _abi() -> list[dict]:
    return json.loads(ABI_PATH.read_text())


class RegistryClient:
    """Read-only client. Construct once at bot startup and reuse — Web3
    instances are cheap but ABI parsing is not."""

    def __init__(self, rpc_url: str, registry_addr: str, chain_id: int):
        self.chain_id = chain_id
        self.registry_addr = Web3.to_checksum_address(registry_addr)
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 15}))
        self.contract = self.w3.eth.contract(address=self.registry_addr, abi=_abi())

    def owner_of(self, agent_id: int) -> str:
        """Returns EIP-55 checksum address. Raises if the token doesn't exist
        (web3 surfaces this as ContractLogicError)."""
        addr = self.contract.functions.ownerOf(agent_id).call()
        return Web3.to_checksum_address(addr)

    def agent_wallet(self, agent_id: int) -> str | None:
        """The address stored under the reserved `agentWallet` metadata key.
        ERC-8004 stores metadata as `bytes`; for an address this is 32-byte
        ABI-padded. Returns None if unset or undecodable — caller falls back
        to ownerOf."""
        try:
            raw = self.contract.functions.getMetadata(agent_id, AGENT_WALLET_KEY).call()
        except Exception:
            log.debug("getMetadata(%s, agentWallet) reverted — treating as unset", agent_id)
            return None
        if not raw:
            return None
        # Two common encodings: 20-byte address raw, or 32-byte left-padded
        # (ABI-encoded `address`). Handle both — anything else is treated as
        # unset rather than asserting, since metadata is admin-set free-form.
        if len(raw) == 20:
            return Web3.to_checksum_address(raw)
        if len(raw) == 32:
            return Web3.to_checksum_address(raw[-20:])
        log.warning("agentWallet metadata length=%d on agent=%s — ignoring", len(raw), agent_id)
        return None

    def token_uri(self, agent_id: int) -> str | None:
        try:
            uri = self.contract.functions.tokenURI(agent_id).call()
        except Exception:
            log.debug("tokenURI(%s) reverted", agent_id)
            return None
        return uri or None


async def fetch_agent_registration(token_uri: str) -> dict | None:
    """Fetch the ERC-8004 agent registration JSON. Handles `data:` URIs (some
    contracts inline metadata) and HTTPS — anything else returns None.

    Failures fall through to None so callers can degrade to 'no rules match'
    instead of erroring on a flaky pin."""
    if not token_uri:
        return None
    if token_uri.startswith("data:"):
        # `data:application/json;base64,...` or `data:application/json,...`
        try:
            header, _, body = token_uri.partition(",")
            if "base64" in header:
                import base64

                body = base64.b64decode(body).decode()
            return json.loads(body)
        except Exception:
            log.exception("Failed to decode data: URI")
            return None
    if token_uri.startswith("ipfs://"):
        # Public gateway. Slow and unreliable but doesn't require a pinning
        # service env var. Operators can override by running their own gateway.
        gw = os.getenv("IPFS_GATEWAY", "https://cloudflare-ipfs.com/ipfs/")
        token_uri = gw.rstrip("/") + "/" + token_uri[len("ipfs://") :]
    if not token_uri.startswith(("http://", "https://")):
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(token_uri, headers={"Accept": "application/json"})
            r.raise_for_status()
            return r.json()
    except Exception:
        log.exception("Agent registration fetch failed: %s", token_uri)
        return None
