"""
Deterministic eth_account fixtures.

Two fixed accounts derived from constant private keys so signatures are
reproducible across machines. Nothing here touches a real chain — tests
that need contract reads stub `RegistryClient` instead.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

import pytest
from eth_account import Account

# make the bot module importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class Wallet:
    key: str  # hex priv key
    address: str  # EIP-55 checksum


@pytest.fixture(scope="session")
def owner_wallet() -> Wallet:
    key = "0x" + "11" * 32
    acct = Account.from_key(key)
    return Wallet(key=key, address=acct.address)


@pytest.fixture(scope="session")
def agent_wallet() -> Wallet:
    key = "0x" + "22" * 32
    acct = Account.from_key(key)
    return Wallet(key=key, address=acct.address)


@pytest.fixture(scope="session")
def stranger_wallet() -> Wallet:
    key = "0x" + "33" * 32
    acct = Account.from_key(key)
    return Wallet(key=key, address=acct.address)
