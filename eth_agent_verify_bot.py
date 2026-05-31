#!/usr/bin/env python3
"""
ETH Agent Verify Bot

Discord bot that proves a user controls an ERC-8004 ("Trustless Agents")
registered agent by signing an EIP-712 challenge with the agent's owner
or `agentWallet`.

Flow:
    /verify  agent:<eip155:CHAIN:REGISTRY:AGENT_ID> -> bot returns an EIP-712 payload
    /submit  signature:<0x...>                      -> bot recovers + records
    /whoami                                         -> list verified agents

All responses are ephemeral; signatures and identifiers stay private.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

from registry_client import RegistryClient, fetch_agent_registration
from signer import ChallengePayload, build_typed_data, recover_signer

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("eth-agent-verify-bot")

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
def _parse_guild_ids(raw: str | None) -> list[int]:
    """Accept a single int or a comma-separated list — operators can run the
    same bot in multiple servers with instant slash-command sync to each."""
    if not raw:
        return []
    out: list[int] = []
    for piece in raw.split(","):
        piece = piece.strip()
        if piece.isdigit():
            out.append(int(piece))
    return out


GUILD_IDS = _parse_guild_ids(os.getenv("GUILD_ID"))
# Back-compat: code paths that read a single guild id (e.g. config display)
# pick the first entry, or None if global.
GUILD_ID = GUILD_IDS[0] if GUILD_IDS else None
def _parse_verified_role_ids(raw: str | None) -> tuple[int | None, dict[int, int]]:
    """Return (single_default, per_guild_map).

    Accepts either:
      • bare int  → applies to every guild the bot serves
      • guild:role,guild:role,...  → per-guild mapping
    """
    if not raw:
        return None, {}
    raw = raw.strip()
    if raw.isdigit():
        return int(raw), {}
    mapping: dict[int, int] = {}
    for piece in raw.split(","):
        if ":" not in piece:
            continue
        g, r = piece.strip().split(":", 1)
        g, r = g.strip(), r.strip()
        if g.isdigit() and r.isdigit():
            mapping[int(g)] = int(r)
    return None, mapping


_DEFAULT_VERIFIED_ROLE_ID, _VERIFIED_ROLE_BY_GUILD = _parse_verified_role_ids(
    os.getenv("VERIFIED_ROLE_ID")
)


def verified_role_for(guild_id: int | str | None) -> int | None:
    """Resolve the verified-role ID for a specific guild, falling back to the
    bot-wide default if the guild has no explicit mapping."""
    if guild_id is None:
        return _DEFAULT_VERIFIED_ROLE_ID
    try:
        gid = int(guild_id)
    except (TypeError, ValueError):
        return _DEFAULT_VERIFIED_ROLE_ID
    return _VERIFIED_ROLE_BY_GUILD.get(gid, _DEFAULT_VERIFIED_ROLE_ID)


# Back-compat: any single-role code path still works when only the default
# form is configured. None when only per-guild mappings are set.
VERIFIED_ROLE_ID = _DEFAULT_VERIFIED_ROLE_ID
DB_PATH = os.getenv("DB_PATH", "verifications.db")
SIGN_PAGE_URL = os.getenv("SIGN_PAGE_URL") or None

CHAIN_ID = int(os.getenv("CHAIN_ID", "8453"))  # Base mainnet
RPC_URL = os.getenv("RPC_URL", "https://mainnet.base.org")
REGISTRY_ADDR = os.getenv("REGISTRY_ADDR") or None

CHALLENGE_TTL_SEC = 300

# Slash commands carry their own data — no privileged intents needed for /verify
# or /submit. Members intent lets admin `/sync_roles` (no member arg) find every
# verified member in the guild without each having to interact first.
# Enable members intent ONLY if the dev-portal toggle is on, otherwise discord.py
# raises PrivilegedIntentsRequired at connect.
intents = discord.Intents.default()
if os.getenv("ENABLE_MEMBERS_INTENT", "").lower() in ("1", "true", "yes"):
    intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents)

# Lazy-init: tests stub this out, and we don't want module import to require
# a live RPC. `_registry()` lifts it on first use.
_registry_client: RegistryClient | None = None


def _registry() -> RegistryClient:
    global _registry_client
    if _registry_client is None:
        if not REGISTRY_ADDR:
            raise RuntimeError("REGISTRY_ADDR not configured")
        _registry_client = RegistryClient(RPC_URL, REGISTRY_ADDR, CHAIN_ID)
    return _registry_client


# ----- agent ID parsing --------------------------------------------------

# eip155:<chainId>:<registry>:<agentId>  per ERC-8004 §"Agent Identifier".
_COMPOSITE_RE = re.compile(
    r"^eip155:(?P<chain>\d+):(?P<reg>0x[0-9a-fA-F]{40}):(?P<agent>\d+)$"
)


@dataclass(frozen=True)
class AgentRef:
    chain_id: int
    registry: str  # checksummed
    agent_id: int

    def composite(self) -> str:
        return f"eip155:{self.chain_id}:{self.registry}:{self.agent_id}"


def parse_agent_ref(s: str) -> AgentRef | None:
    """Accept the canonical `eip155:CHAIN:REG:ID` form or a bare integer
    (interpreted as agentId on the bot's configured registry)."""
    s = s.strip()
    m = _COMPOSITE_RE.match(s)
    if m:
        from web3 import Web3

        return AgentRef(
            chain_id=int(m.group("chain")),
            registry=Web3.to_checksum_address(m.group("reg")),
            agent_id=int(m.group("agent")),
        )
    if s.isdigit() and REGISTRY_ADDR:
        from web3 import Web3

        return AgentRef(
            chain_id=CHAIN_ID,
            registry=Web3.to_checksum_address(REGISTRY_ADDR),
            agent_id=int(s),
        )
    return None


# ----- challenge state ---------------------------------------------------


@dataclass
class Challenge:
    payload: ChallengePayload
    issued_at: float


_pending: dict[str, Challenge] = {}


# ----- storage -----------------------------------------------------------

RULE_MATCH_TYPES = ("registry", "trust_model", "agent_type", "service_proto")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS verifications (
            discord_id   TEXT NOT NULL,
            chain_id     INTEGER NOT NULL,
            registry     TEXT NOT NULL,
            agent_id     INTEGER NOT NULL,
            signer_addr  TEXT NOT NULL,
            verified_at  INTEGER NOT NULL,
            PRIMARY KEY (discord_id, chain_id, registry, agent_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS role_rules (
            rule_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id     TEXT NOT NULL,
            match_type   TEXT NOT NULL,
            match_value  TEXT NOT NULL,
            role_id      TEXT NOT NULL,
            UNIQUE(guild_id, match_type, match_value, role_id)
        )
        """
    )
    return conn


def record_verification(discord_id: str, ref: AgentRef, signer_addr: str) -> None:
    conn = _db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO verifications"
            "(discord_id, chain_id, registry, agent_id, signer_addr, verified_at)"
            " VALUES (?,?,?,?,?,?)",
            (
                discord_id,
                ref.chain_id,
                ref.registry,
                ref.agent_id,
                signer_addr,
                int(time.time()),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_verifications(discord_id: str) -> list[tuple[int, str, int, str, int]]:
    """Rows: (chain_id, registry, agent_id, signer_addr, verified_at)."""
    conn = _db()
    try:
        return conn.execute(
            "SELECT chain_id, registry, agent_id, signer_addr, verified_at"
            " FROM verifications WHERE discord_id=? ORDER BY verified_at DESC",
            (discord_id,),
        ).fetchall()
    finally:
        conn.close()


def all_verified_discord_ids() -> list[str]:
    conn = _db()
    try:
        return [
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT discord_id FROM verifications"
            ).fetchall()
        ]
    finally:
        conn.close()


def add_role_rule(guild_id: str, match_type: str, match_value: str, role_id: str) -> int:
    if match_type not in RULE_MATCH_TYPES:
        raise ValueError(f"match_type must be one of {RULE_MATCH_TYPES}")
    conn = _db()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO role_rules(guild_id, match_type, match_value, role_id)"
            " VALUES (?,?,?,?)",
            (str(guild_id), match_type, match_value, str(role_id)),
        )
        conn.commit()
        row = conn.execute(
            "SELECT rule_id FROM role_rules WHERE guild_id=? AND match_type=?"
            " AND match_value=? AND role_id=?",
            (str(guild_id), match_type, match_value, str(role_id)),
        ).fetchone()
        return row[0]
    finally:
        conn.close()


def remove_role_rule(rule_id: int, guild_id: str) -> bool:
    conn = _db()
    try:
        cur = conn.execute(
            "DELETE FROM role_rules WHERE rule_id=? AND guild_id=?",
            (rule_id, str(guild_id)),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_role_rules(guild_id: str) -> list[tuple[int, str, str, str]]:
    conn = _db()
    try:
        return conn.execute(
            "SELECT rule_id, match_type, match_value, role_id FROM role_rules"
            " WHERE guild_id=? ORDER BY rule_id",
            (str(guild_id),),
        ).fetchall()
    finally:
        conn.close()


# ----- rule evaluation ---------------------------------------------------


@dataclass
class AgentFacts:
    """Everything we know about a verified agent that holder-rules can match
    against. Built from on-chain reads + the registration JSON."""

    chain_id: int
    registry: str
    agent_id: int
    agent_type: str | None = None
    trust_models: frozenset[str] = frozenset()
    service_protos: frozenset[str] = frozenset()

    @property
    def registry_key(self) -> str:
        """The match_value form used by `registry` rules: chainId:registry."""
        return f"{self.chain_id}:{self.registry}"


def facts_from_registration(ref: AgentRef, registration: dict | None) -> AgentFacts:
    """Lift the ERC-8004 registration JSON into the flat AgentFacts shape rule
    evaluation cares about. Missing fields just become empty sets — a rule
    that needs them simply won't match."""
    if not registration:
        return AgentFacts(ref.chain_id, ref.registry, ref.agent_id)
    trust = registration.get("supportedTrustModels") or []
    services = registration.get("services") or []
    protos = {
        (s.get("protocol") or "").strip().lower()
        for s in services
        if isinstance(s, dict) and s.get("protocol")
    }
    return AgentFacts(
        chain_id=ref.chain_id,
        registry=ref.registry,
        agent_id=ref.agent_id,
        agent_type=(registration.get("type") or None),
        trust_models=frozenset(str(t).strip().lower() for t in trust if t),
        service_protos=frozenset(p for p in protos if p),
    )


def evaluate_rules(guild_id: str, agents: list[AgentFacts]) -> list[str]:
    """Returns the de-duplicated list of role_ids to grant based on the
    member's verified agents. Each rule type matches as follows:

      registry      — match_value == "chainId:registryAddress"
      trust_model   — match_value (lowercased) ∈ agent's supportedTrustModels
      agent_type    — match_value == agent's `type` field
      service_proto — match_value (lowercased) ∈ agent's service protocols
    """
    rules = list_role_rules(guild_id)
    if not rules or not agents:
        return []
    granted: set[str] = set()
    for _rid, mtype, mvalue, role_id in rules:
        target = mvalue.strip()
        if mtype == "registry":
            if any(a.registry_key.lower() == target.lower() for a in agents):
                granted.add(role_id)
        elif mtype == "trust_model":
            t = target.lower()
            if any(t in a.trust_models for a in agents):
                granted.add(role_id)
        elif mtype == "agent_type":
            if any(a.agent_type == target for a in agents):
                granted.add(role_id)
        elif mtype == "service_proto":
            t = target.lower()
            if any(t in a.service_protos for a in agents):
                granted.add(role_id)
    return list(granted)


def managed_role_ids(guild_id: str) -> set[str]:
    """Roles this bot is allowed to add/remove during sync. Roles outside
    this set were granted by another bot or admin and stay untouched."""
    ids = {role_id for _, _, _, role_id in list_role_rules(guild_id)}
    role = verified_role_for(guild_id)
    if role:
        ids.add(str(role))
    return ids


def compute_role_diff(
    member_role_ids: set[str],
    target_role_ids: set[str],
    managed: set[str],
) -> tuple[set[str], set[str]]:
    to_add = target_role_ids - member_role_ids
    to_remove = (member_role_ids & managed) - target_role_ids
    return to_add, to_remove


# ----- on-chain facts ----------------------------------------------------


async def fetch_agent_facts(ref: AgentRef) -> AgentFacts:
    """Pull tokenURI from the registry, fetch the JSON, return AgentFacts.
    Best-effort: returns an empty-facts AgentFacts on any failure rather than
    raising, since rule evaluation can survive degraded data."""
    try:
        uri = await asyncio.to_thread(_registry().token_uri, ref.agent_id)
    except Exception:
        log.exception("tokenURI read failed for agent=%s", ref.agent_id)
        return AgentFacts(ref.chain_id, ref.registry, ref.agent_id)
    if not uri:
        return AgentFacts(ref.chain_id, ref.registry, ref.agent_id)
    registration = await fetch_agent_registration(uri)
    return facts_from_registration(ref, registration)


async def compute_target_roles(
    guild_id: str, verified_agents: list[AgentRef]
) -> set[str]:
    """Roles a member SHOULD have based on the current state of their
    verified agents. Raises on any registry read error so callers can skip
    the member rather than strip every role."""
    if not verified_agents:
        return set()
    facts: list[AgentFacts] = []
    for ref in verified_agents:
        # Re-read ownership: if the agent NFT was transferred, the binding
        # is no longer valid and we drop it from the facts list.
        owner = await asyncio.to_thread(_registry().owner_of, ref.agent_id)
        wallet = await asyncio.to_thread(_registry().agent_wallet, ref.agent_id)
        # We don't know which side the user signed with — but we recorded
        # signer_addr; here we conservatively accept if either still matches
        # what we last recorded. Caller filters by signer match before
        # passing the ref in.
        facts.append(await fetch_agent_facts(ref))
        log.debug("owner=%s wallet=%s for agent=%s", owner, wallet, ref.agent_id)
    target = set(evaluate_rules(guild_id, facts))
    role = verified_role_for(guild_id)
    if role:
        target.add(str(role))
    return target


def _still_controlled(ref: AgentRef, signer_addr: str) -> bool:
    """Re-check: is `signer_addr` still owner or agentWallet of the agent?
    If neither, the original binding is stale (sold/transferred) and the
    membership shouldn't count."""
    try:
        owner = _registry().owner_of(ref.agent_id)
    except Exception:
        log.exception("ownerOf failed for agent=%s — keeping binding", ref.agent_id)
        # Transient RPC failure — don't strip on this; treat as still valid.
        return True
    if owner.lower() == signer_addr.lower():
        return True
    wallet = _registry().agent_wallet(ref.agent_id)
    return bool(wallet and wallet.lower() == signer_addr.lower())


# ----- bot lifecycle -----------------------------------------------------


@bot.event
async def on_ready():
    log.info("Logged in as %s (id=%s)", bot.user, getattr(bot.user, "id", "?"))
    _db().close()
    if not REGISTRY_ADDR:
        log.warning("REGISTRY_ADDR unset — /verify will fail until configured")
    if GUILD_IDS:
        ok = 0
        for gid in GUILD_IDS:
            try:
                guild = discord.Object(id=gid)
                bot.tree.copy_global_to(guild=guild)
                synced = await bot.tree.sync(guild=guild)
                log.info("Synced %d slash commands to guild %s", len(synced), gid)
                ok += 1
            except discord.Forbidden:
                log.warning(
                    "Guild %s: Missing Access — bot is not in this server yet. "
                    "Invite it with the OAuth URL and restart to sync.", gid,
                )
            except Exception:
                log.exception("Sync failed for guild %s", gid)
        log.info("Slash command sync done: %d/%d guild(s)", ok, len(GUILD_IDS))
    else:
        try:
            synced = await bot.tree.sync()
            log.info("Synced %d slash commands globally", len(synced))
        except Exception:
            log.exception("Global slash command sync failed")
    await bot.change_presence(activity=discord.Game(name="/verify"))


# ----- slash commands ----------------------------------------------------


class _CopyButton(discord.ui.Button):
    """Reveals a single payload in an ephemeral fenced block — gives mobile
    users a focused long-press target instead of a giant scroll of text."""

    def __init__(
        self, label: str, payload: str, *,
        style: discord.ButtonStyle = discord.ButtonStyle.secondary,
        emoji: str | None = None, lang: str = "",
    ):
        super().__init__(label=label, style=style, emoji=emoji)
        self._payload = payload
        self._lang = lang

    async def callback(self, interaction: discord.Interaction):
        body = f"```{self._lang}\n{self._payload}\n```"
        # 1990 keeps headroom for fence + lang tag on the 2000-char limit.
        if len(body) > 1990:
            body = body[:1990] + "\n…(truncated)\n```"
        await interaction.response.send_message(body, ephemeral=True)


class _CopyPromptView(discord.ui.View):
    """Container view that exposes one _CopyButton per labeled payload."""

    def __init__(
        self,
        items: list[tuple[str, str]] | list[tuple[str, str, dict]],
        *, timeout: float = 900,
    ):
        super().__init__(timeout=timeout)
        for it in items:
            label, payload = it[0], it[1]
            opts: dict = it[2] if len(it) >= 3 and isinstance(it[2], dict) else {}
            self.add_item(_CopyButton(label, payload, **opts))


class _ChallengeCopyView(discord.ui.View):
    """Buttons attached to /verify. If SIGN_PAGE_URL is set, a link button
    opens a static page that builds the EIP-712 payload and invokes
    eth_signTypedData_v4 in the user's wallet. Otherwise users sign manually."""

    def __init__(self, payload: ChallengePayload):
        super().__init__(timeout=CHALLENGE_TTL_SEC)
        self._payload = payload
        if SIGN_PAGE_URL:
            typed = build_typed_data(payload)
            url = (
                f"{SIGN_PAGE_URL}?typed="
                + urllib.parse.quote(json.dumps(typed, separators=(",", ":")))
            )
            self.add_item(
                discord.ui.Button(
                    label="🔐 Sign with my wallet",
                    style=discord.ButtonStyle.link,
                    url=url,
                )
            )

    @discord.ui.button(
        label="🤖 Copy prompt for my agent",
        style=discord.ButtonStyle.primary,
    )
    async def agent_prompt(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        typed = build_typed_data(self._payload)
        # Single fenced block so Discord renders one copy-on-hover affordance.
        prompt = (
            "Please sign the following EIP-712 typed data with the wallet that "
            "controls your ERC-8004 agent. Use the eth_signTypedData_v4 standard. "
            "Reply with ONLY the resulting hex signature — a single 0x-prefixed "
            "string, no quotes, no extra words.\n\n"
            "EIP-712 payload to sign:\n"
            + json.dumps(typed, indent=2)
        )
        body = (
            "Copy the whole block below and send it to your agent. It will "
            "reply with a hex signature — paste that into `/submit signature:<0x…>`.\n"
            "```\n" + prompt + "\n```"
        )
        await interaction.response.send_message(body, ephemeral=True)

    @discord.ui.button(
        label="📋 Show raw typed data",
        style=discord.ButtonStyle.secondary,
    )
    async def show_plain(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        typed = build_typed_data(self._payload)
        body = "```json\n" + json.dumps(typed, indent=2) + "\n```"
        await interaction.response.send_message(body, ephemeral=True)


@bot.tree.command(
    name="verify",
    description="Begin ERC-8004 agent verification — get an EIP-712 challenge to sign.",
)
@app_commands.describe(
    agent=(
        "Agent identifier — either eip155:CHAIN:REGISTRY:AGENT_ID "
        "or a bare numeric agentId on the configured registry"
    )
)
async def verify_cmd(interaction: discord.Interaction, agent: str):
    ref = parse_agent_ref(agent)
    if ref is None:
        await interaction.response.send_message(
            "Couldn't parse `agent`. Expected one of:\n"
            "• `eip155:<chainId>:<registry>:<agentId>` "
            f"(e.g. `eip155:{CHAIN_ID}:{REGISTRY_ADDR or '0x...'}:42`)\n"
            "• A bare numeric `agentId` (uses this server's default registry)\n\n"
            "Don't know your agent ID? Run `/start_verify` for a step-by-step guide.",
            ephemeral=True,
        )
        return
    if ref.chain_id != CHAIN_ID:
        await interaction.response.send_message(
            f"This bot is configured for chainId {CHAIN_ID}. Got {ref.chain_id}.",
            ephemeral=True,
        )
        return

    # Quick existence check — fail fast before the user touches their wallet.
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        owner = await asyncio.to_thread(_registry().owner_of, ref.agent_id)
    except Exception as e:
        await interaction.followup.send(
            f"Registry doesn't recognize agentId `{ref.agent_id}`: `{e}`",
            ephemeral=True,
        )
        return

    nonce_hex = "0x" + secrets.token_bytes(32).hex()
    deadline = int(time.time()) + CHALLENGE_TTL_SEC
    payload = ChallengePayload(
        discord_id=str(interaction.user.id),
        agent_id=ref.agent_id,
        registry=ref.registry,
        nonce_hex=nonce_hex,
        deadline=deadline,
        chain_id=ref.chain_id,
    )
    _pending[str(interaction.user.id)] = Challenge(payload=payload, issued_at=time.time())

    if SIGN_PAGE_URL:
        instructions = (
            "**Easiest:** tap **🔐 Sign with my wallet** — opens a page that "
            "invokes MetaMask / Rabby / WalletConnect with the typed data "
            "pre-filled.\n\n"
            "**Manual:** tap **📋 Show raw typed data**, sign with "
            "`eth_signTypedData_v4`, then run `/submit signature:<0x…>`."
        )
    else:
        instructions = (
            "1. In your wallet, call `eth_signTypedData_v4` with the JSON "
            "below.\n2. Run `/submit signature:<0x…>` within 5 minutes."
        )

    embed = discord.Embed(
        title="Sign this EIP-712 challenge",
        description=instructions,
        color=discord.Color.purple(),
    )
    embed.add_field(name="Agent", value=f"`{ref.composite()}`", inline=False)
    embed.add_field(name="Owner", value=f"`{owner}`", inline=False)
    embed.add_field(
        name="Expires", value=f"<t:{deadline}:R>", inline=False
    )
    await interaction.followup.send(
        embed=embed, view=_ChallengeCopyView(payload), ephemeral=True
    )


@bot.tree.command(
    name="submit",
    description="Submit your EIP-712 signature for the active challenge.",
)
@app_commands.describe(signature="0x-prefixed 65-byte secp256k1 signature")
async def submit_cmd(interaction: discord.Interaction, signature: str):
    discord_id = str(interaction.user.id)
    chal = _pending.get(discord_id)
    if not chal:
        await interaction.response.send_message(
            "No active challenge — run `/verify <agent>` first.", ephemeral=True
        )
        return
    if time.time() - chal.issued_at > CHALLENGE_TTL_SEC:
        _pending.pop(discord_id, None)
        await interaction.response.send_message(
            "Challenge expired — run `/verify` again.", ephemeral=True
        )
        return
    if chal.payload.deadline < int(time.time()):
        _pending.pop(discord_id, None)
        await interaction.response.send_message(
            "Challenge deadline passed.", ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True, thinking=True)

    try:
        signer_addr = await asyncio.to_thread(
            recover_signer, chal.payload, signature.strip()
        )
    except Exception as e:
        await interaction.followup.send(
            f"❌ Could not recover signer: `{e}`", ephemeral=True
        )
        return

    ref = AgentRef(
        chain_id=chal.payload.chain_id,
        registry=chal.payload.registry,
        agent_id=chal.payload.agent_id,
    )

    try:
        owner = await asyncio.to_thread(_registry().owner_of, ref.agent_id)
        wallet = await asyncio.to_thread(_registry().agent_wallet, ref.agent_id)
    except Exception as e:
        await interaction.followup.send(
            f"❌ Registry read failed: `{e}`", ephemeral=True
        )
        return

    allowed = {owner.lower()}
    if wallet:
        allowed.add(wallet.lower())
    if signer_addr.lower() not in allowed:
        await interaction.followup.send(
            f"❌ Signature recovered to `{signer_addr}`, which is neither the "
            f"NFT owner (`{owner}`) nor the agentWallet "
            f"(`{wallet or 'unset'}`). Sign from a wallet that controls the agent.",
            ephemeral=True,
        )
        return

    # Consume the nonce immediately — single-use even if downstream steps fail.
    _pending.pop(discord_id, None)
    record_verification(discord_id, ref, signer_addr)

    facts = await fetch_agent_facts(ref)

    granted_lines: list[str] = []
    failed_lines: list[str] = []

    guild_verified_role = verified_role_for(
        interaction.guild.id if interaction.guild else None
    )
    if guild_verified_role and isinstance(interaction.user, discord.Member):
        role = (
            interaction.guild.get_role(guild_verified_role)
            if interaction.guild else None
        )
        if role:
            try:
                await interaction.user.add_roles(role, reason="ERC-8004 agent verified")
                granted_lines.append(f"<@&{guild_verified_role}> (base verified role)")
            except discord.Forbidden:
                failed_lines.append(
                    f"<@&{guild_verified_role}> — bot lacks Manage Roles or sits below this role"
                )

    if interaction.guild and isinstance(interaction.user, discord.Member):
        rule_role_ids = evaluate_rules(str(interaction.guild.id), [facts])
        for rid in rule_role_ids:
            role = interaction.guild.get_role(int(rid))
            if not role:
                failed_lines.append(f"<@&{rid}> — role no longer exists")
                continue
            if role in interaction.user.roles:
                granted_lines.append(f"<@&{rid}> (already had it)")
                continue
            try:
                await interaction.user.add_roles(role, reason="Holder-rule match")
                granted_lines.append(f"<@&{rid}>")
            except discord.Forbidden:
                failed_lines.append(
                    f"<@&{rid}> — bot lacks Manage Roles or sits below this role"
                )

    embed = discord.Embed(
        title="✅ Agent verified",
        description=(
            f"`{ref.composite()}` linked to <@{discord_id}>\n"
            f"Signer: `{signer_addr}`"
        ),
        color=discord.Color.green(),
    )
    if facts.agent_type:
        embed.add_field(name="Type", value=facts.agent_type, inline=True)
    if facts.trust_models:
        embed.add_field(
            name="Trust models", value=", ".join(sorted(facts.trust_models)), inline=True
        )
    if facts.service_protos:
        embed.add_field(
            name="Services",
            value=", ".join(sorted(facts.service_protos)),
            inline=True,
        )
    if granted_lines:
        embed.add_field(name="Roles granted", value="\n".join(granted_lines), inline=False)
    if failed_lines:
        embed.add_field(name="⚠️ Could not grant", value="\n".join(failed_lines), inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="whoami", description="Show your verified ERC-8004 agents.")
async def whoami_cmd(interaction: discord.Interaction):
    rows = list_verifications(str(interaction.user.id))
    if not rows:
        await interaction.response.send_message("No agents verified yet.", ephemeral=True)
        return
    lines = [
        f"`eip155:{c}:{r}:{a}` — signer `{s[:6]}…{s[-4:]}` — <t:{ts}:R>"
        for c, r, a, s, ts in rows
    ]
    await interaction.response.send_message("\n".join(lines), ephemeral=True)


@bot.tree.command(
    name="my_agents",
    description="Show your verified agents grouped by wallet, with on-chain balance.",
)
async def my_agents_cmd(interaction: discord.Interaction):
    rows = list_verifications(str(interaction.user.id))
    if not rows:
        await interaction.response.send_message(
            "No agents verified yet — run `/verify` (or `/start_verify` for "
            "step-by-step). Registered on multiple wallets? Sign with each "
            "wallet in turn — every successful `/verify` shows up here.",
            ephemeral=True,
        )
        return

    await interaction.response.defer(ephemeral=True, thinking=True)

    # Group rows by signer wallet, preserving chain+registry+agent details.
    by_wallet: dict[str, list[tuple[int, str, int, int]]] = {}
    for chain_id, registry, agent_id, signer_addr, ts in rows:
        by_wallet.setdefault(signer_addr, []).append((chain_id, registry, agent_id, ts))

    # Check current on-chain status: balanceOf per wallet + ownerOf per agent.
    # Concurrency keeps it snappy even with several agents.
    async def _check_agent(chain_id: int, registry: str, agent_id: int, signer: str):
        ref = AgentRef(chain_id=chain_id, registry=registry, agent_id=agent_id)
        try:
            owner = await asyncio.to_thread(_registry().owner_of, ref.agent_id)
            wallet = await asyncio.to_thread(_registry().agent_wallet, ref.agent_id)
        except Exception as e:
            return ("err", str(e))
        allowed = {owner.lower()}
        if wallet:
            allowed.add(wallet.lower())
        return ("ok", signer.lower() in allowed)

    async def _balance(addr: str) -> int | None:
        try:
            return await asyncio.to_thread(_registry().balance_of, addr)
        except Exception:
            return None

    lines: list[str] = []
    for wallet, agents in by_wallet.items():
        bal = await _balance(wallet)
        verified_count = len(agents)
        if bal is None:
            header = f"**Wallet** `{wallet}` — on-chain balance unavailable"
        elif bal > verified_count:
            header = (
                f"**Wallet** `{wallet}` — **{verified_count} verified here, "
                f"{bal} owned on-chain** ({bal - verified_count} unverified — "
                f"run `/verify` to surface them)"
            )
        else:
            header = f"**Wallet** `{wallet}` — {verified_count} verified, {bal} on-chain"
        lines.append(header)

        for chain_id, registry, agent_id, ts in agents:
            status, info = await _check_agent(chain_id, registry, agent_id, wallet)
            if status == "err":
                tag = "⚠️ chain read failed"
            elif info is True:
                tag = "✅ still controlled"
            else:
                tag = "❌ transferred away"
            lines.append(
                f"  • `eip155:{chain_id}:{registry}:{agent_id}` — {tag} — <t:{ts}:R>"
            )
        lines.append("")

    # Strip trailing blank.
    while lines and lines[-1] == "":
        lines.pop()

    body = "\n".join(lines)
    # Discord ephemeral followup limit is 2000 chars for plain text — truncate
    # defensively. Realistic verified counts will be far below this.
    if len(body) > 1900:
        body = body[:1900] + "\n…(truncated)"
    await interaction.followup.send(body, ephemeral=True)


# ----- role sync ---------------------------------------------------------


async def sync_member_roles(
    guild: discord.Guild,
    member: discord.Member,
    verified: list[tuple[int, str, int, str]],
) -> dict:
    """Recompute target roles from current chain state and reconcile.

    `verified` rows: (chain_id, registry, agent_id, signer_addr) — only refs
    whose original signer is still owner-or-agentWallet are considered live.
    """
    result: dict = {"added": [], "removed": [], "skipped": [], "error": None}
    if not verified:
        result["error"] = "no verified agents"
        return result

    live_refs: list[AgentRef] = []
    for chain_id, registry, agent_id, signer_addr in verified:
        ref = AgentRef(chain_id=chain_id, registry=registry, agent_id=agent_id)
        try:
            still = await asyncio.to_thread(_still_controlled, ref, signer_addr)
        except Exception as e:
            result["error"] = f"registry read failed: {e!s}"
            return result
        if still:
            live_refs.append(ref)

    try:
        target = await compute_target_roles(str(guild.id), live_refs)
    except Exception as e:
        result["error"] = f"compute_target_roles failed: {e!s}"
        return result

    managed = managed_role_ids(str(guild.id))
    current = {str(r.id) for r in member.roles}
    to_add, to_remove = compute_role_diff(current, target, managed)
    bot_top = guild.me.top_role if guild.me else None

    for rid in to_add:
        role = guild.get_role(int(rid))
        if not role:
            result["skipped"].append(f"{rid} (no longer exists)")
            continue
        if bot_top is not None and role >= bot_top:
            result["skipped"].append(f"{rid} (above bot's top role)")
            continue
        try:
            await member.add_roles(role, reason="Sync: agent facts match rule")
            result["added"].append(rid)
        except discord.Forbidden:
            result["skipped"].append(f"{rid} (forbidden)")

    for rid in to_remove:
        role = guild.get_role(int(rid))
        if not role:
            continue
        if bot_top is not None and role >= bot_top:
            result["skipped"].append(f"{rid} (above bot's top role)")
            continue
        try:
            await member.remove_roles(role, reason="Sync: no longer controls agent")
            result["removed"].append(rid)
        except discord.Forbidden:
            result["skipped"].append(f"{rid} (forbidden)")

    return result


@bot.tree.command(name="sync_me", description="Re-check your agents and update your roles.")
async def sync_me_cmd(interaction: discord.Interaction):
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        await interaction.response.send_message("Run this in a server.", ephemeral=True)
        return
    rows = list_verifications(str(interaction.user.id))
    if not rows:
        await interaction.response.send_message(
            "You haven't verified any agents yet — run `/verify` first.",
            ephemeral=True,
        )
        return

    await interaction.response.defer(ephemeral=True, thinking=True)
    verified = [(c, r, a, s) for c, r, a, s, _ts in rows]
    res = await sync_member_roles(interaction.guild, interaction.user, verified)
    if res["error"]:
        await interaction.followup.send(
            f"❌ {res['error']}. No roles changed.", ephemeral=True
        )
        return

    parts: list[str] = []
    if res["added"]:
        parts.append("**Added:** " + " ".join(f"<@&{r}>" for r in res["added"]))
    if res["removed"]:
        parts.append("**Removed:** " + " ".join(f"<@&{r}>" for r in res["removed"]))
    if res["skipped"]:
        parts.append("⚠️ Skipped: " + ", ".join(res["skipped"][:5]))
    if not parts:
        parts.append("✅ Already in sync — no changes.")
    await interaction.followup.send("\n".join(parts), ephemeral=True)


@bot.tree.command(
    name="sync_roles",
    description="Admin: re-check verified members in this guild and update their roles.",
)
@app_commands.default_permissions(administrator=True)
@app_commands.describe(
    member="Sync only this member (default: every verified member in the guild)",
)
async def sync_roles_cmd(
    interaction: discord.Interaction,
    member: discord.Member | None = None,
):
    if not interaction.guild:
        await interaction.response.send_message("Run this in a server.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True, thinking=True)

    targets: list[discord.Member] = []
    if member is not None:
        targets = [member]
    else:
        for did in all_verified_discord_ids():
            m = interaction.guild.get_member(int(did))
            if m:
                targets.append(m)

    if not targets:
        await interaction.followup.send(
            "No verified members in this guild to sync.", ephemeral=True
        )
        return

    total_added = 0
    total_removed = 0
    errors = 0
    detail: list[str] = []
    for m in targets:
        rows = list_verifications(str(m.id))
        verified = [(c, r, a, s) for c, r, a, s, _ts in rows]
        res = await sync_member_roles(interaction.guild, m, verified)
        if res["error"]:
            errors += 1
            detail.append(f"<@{m.id}>: ⚠️ {res['error']}")
            continue
        a, r = len(res["added"]), len(res["removed"])
        total_added += a
        total_removed += r
        if a or r:
            detail.append(f"<@{m.id}>: +{a} -{r}")

    summary = (
        f"Synced **{len(targets)}** member(s) — added **{total_added}**, "
        f"removed **{total_removed}**, errors **{errors}**."
    )
    if detail:
        head = "\n".join(detail[:15])
        more = f"\n…+{len(detail) - 15} more" if len(detail) > 15 else ""
        summary += f"\n\n{head}{more}"
    await interaction.followup.send(summary, ephemeral=True)


# ----- admin: holder-rule management -------------------------------------

_RULE_TYPE_CHOICES = [
    app_commands.Choice(
        name="registry (chainId:registryAddress)", value="registry"
    ),
    app_commands.Choice(
        name="trust_model (reputation, crypto-economic, tee-attestation, …)",
        value="trust_model",
    ),
    app_commands.Choice(name="agent_type (the agent's `type` field)", value="agent_type"),
    app_commands.Choice(
        name="service_proto (A2A, MCP, ENS, DID, email, …)", value="service_proto"
    ),
]


@bot.tree.command(name="rule_help", description="How holder-rules work for ERC-8004 agents.")
@app_commands.default_permissions(administrator=True)
async def rule_help_cmd(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Holder-rule setup",
        color=discord.Color.blurple(),
        description=(
            "Grant Discord roles automatically based on facts about a verified "
            "agent. Rules are evaluated on every successful `/submit` and on "
            "every `/sync_me` / `/sync_roles`."
        ),
    )
    embed.add_field(
        name="registry",
        value=(
            "**Value:** `chainId:registryAddress` "
            "(e.g. `8453:0xRegistryOnBase`).\nMatches any verified agent on "
            "that registry. Good for cross-server tiers like `@base-agent`."
        ),
        inline=False,
    )
    embed.add_field(
        name="trust_model",
        value=(
            "**Value:** one of `reputation`, `crypto-economic`, "
            "`tee-attestation`, `zkml`, etc.\nMatches if the agent's "
            "`supportedTrustModels` array contains the value."
        ),
        inline=False,
    )
    embed.add_field(
        name="agent_type",
        value=(
            "**Value:** the literal `type` field on the agent's registration JSON.\n"
            "Use for tier roles like `@validator` or `@oracle`."
        ),
        inline=False,
    )
    embed.add_field(
        name="service_proto",
        value=(
            "**Value:** the protocol identifier from the agent's `services` "
            "array — e.g. `mcp`, `a2a`, `ens`, `did`, `email`."
        ),
        inline=False,
    )
    embed.add_field(
        name="Manage",
        value="`/rule_add` • `/rule_list` • `/rule_remove rule_id:<n>`",
        inline=False,
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="rule_add", description="Bind a Discord role to an agent fact.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(
    type="Fact to match against (see /rule_help)",
    value="Match value — see /rule_help for each type",
    role="Role to grant on match",
)
@app_commands.choices(type=_RULE_TYPE_CHOICES)
async def rule_add_cmd(
    interaction: discord.Interaction,
    type: app_commands.Choice[str],
    value: str,
    role: discord.Role,
):
    if not interaction.guild:
        await interaction.response.send_message("Run this in a server.", ephemeral=True)
        return
    bot_member = interaction.guild.me
    hierarchy_warn = ""
    if bot_member and role >= bot_member.top_role:
        hierarchy_warn = (
            f"\n⚠️ Bot's top role is **{bot_member.top_role.name}**, not above "
            f"**{role.name}** — grants will 403 until you drag the bot's role higher."
        )
    rule_id = add_role_rule(
        guild_id=str(interaction.guild.id),
        match_type=type.value,
        match_value=value.strip(),
        role_id=str(role.id),
    )
    await interaction.response.send_message(
        f"✅ Rule **#{rule_id}** saved.\n"
        f"**Match:** `{type.value}` → `{value.strip()}`\n"
        f"**Role:** {role.mention}{hierarchy_warn}",
        ephemeral=True,
    )


@bot.tree.command(name="rule_remove", description="Delete a holder-rule by its rule_id.")
@app_commands.default_permissions(administrator=True)
@app_commands.describe(rule_id="The numeric ID from /rule_list")
async def rule_remove_cmd(interaction: discord.Interaction, rule_id: int):
    if not interaction.guild:
        await interaction.response.send_message("Run this in a server.", ephemeral=True)
        return
    ok = remove_role_rule(rule_id, str(interaction.guild.id))
    msg = (
        f"✅ Removed rule **#{rule_id}**."
        if ok
        else f"❌ No rule with ID **{rule_id}** in this server."
    )
    await interaction.response.send_message(msg, ephemeral=True)


@bot.tree.command(name="rule_list", description="Show all holder-rules for this server.")
@app_commands.default_permissions(administrator=True)
async def rule_list_cmd(interaction: discord.Interaction):
    if not interaction.guild:
        await interaction.response.send_message("Run this in a server.", ephemeral=True)
        return
    rules = list_role_rules(str(interaction.guild.id))
    if not rules:
        await interaction.response.send_message(
            "No holder-rules configured. Run `/rule_help` to learn how to add one.",
            ephemeral=True,
        )
        return
    lines = []
    for rid, mtype, mvalue, role_id in rules:
        short = mvalue if len(mvalue) <= 28 else mvalue[:24] + "…" + mvalue[-4:]
        lines.append(f"`#{rid}` • `{mtype}` → `{short}` → <@&{role_id}>")
    embed = discord.Embed(
        title=f"Holder-rules ({len(rules)})",
        description="\n".join(lines),
        color=discord.Color.blurple(),
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ----- onboarding --------------------------------------------------------


@bot.tree.command(
    name="start_verify",
    description="Walk me through verifying my ERC-8004 agent step-by-step.",
)
async def start_verify_cmd(interaction: discord.Interaction):
    default_reg = REGISTRY_ADDR or "0x...your-registry..."
    ask_agent_prompt = (
        "What is your ERC-8004 agent identifier? Reply with ONLY the canonical "
        "string in the form `eip155:<chainId>:<registry>:<agentId>` "
        "(or just your numeric agent ID if I'm on the same registry as the "
        "verifier bot). No other text."
    )
    verify_template = (
        f"/verify agent:eip155:{CHAIN_ID}:{default_reg}:<your-agent-id>"
    )
    submit_template = "/submit signature:0x..."

    msg = (
        "**Verify your ERC-8004 agent — 3 steps**\n\n"
        "**1.** Ask your agent for its ERC-8004 identifier — tap the button "
        "below and long-press the message to copy.\n"
        "**2.** Run `/verify` with what it gave you. If your agent is on this "
        f"server's default registry (`{default_reg}`), you can pass just the "
        "numeric agent ID (e.g. `/verify agent:42`).\n"
        "**3.** I'll reply with a single block to send to your agent. It will "
        "return a hex signature. Paste it into `/submit`. You're verified.\n\n"
        "💡 **Agent not registered on-chain yet?** Run `/register_help` first."
    )
    view = _CopyPromptView([
        ("Ask agent for ID", ask_agent_prompt, {"emoji": "📝", "style": discord.ButtonStyle.primary}),
        ("/verify template", verify_template, {"emoji": "🔍"}),
        ("/submit template", submit_template, {"emoji": "📤"}),
    ])
    await interaction.response.send_message(msg, view=view, ephemeral=True)


@bot.tree.command(
    name="register_help",
    description="Get a copy-paste prompt to send to your agent so it registers itself on Base.",
)
async def register_help_cmd(interaction: discord.Interaction):
    default_reg = REGISTRY_ADDR or "0x...your-registry..."
    agent_prompt = (
        "You are an AI agent. Your user wants to prove to a Discord server "
        "that they control you. To do that, you need to register yourself on "
        "the ERC-8004 Trustless Agents Identity Registry on Base mainnet. "
        "Do the steps below in order and report progress to the user.\n\n"
        "1. Wallet check.\n"
        "   - If you can sign and broadcast Ethereum transactions on Base "
        "(chainId 8453), continue.\n"
        "   - If you cannot sign EVM transactions at all, stop and tell the "
        "user what access you would need (an RPC endpoint, a signing key or "
        "key-management API, the ability to broadcast a transaction).\n"
        "   - If you can sign but have no wallet yet, generate a new EVM "
        "keypair, store the private key durably, report the public address "
        "to the user, and stop until they confirm it is funded.\n\n"
        "2. Funding check.\n"
        "   - Confirm the wallet holds at least 0.0001 ETH on Base mainnet "
        "(chainId 8453). Registration is non-payable but you still pay gas "
        "(~$0.01 today).\n"
        "   - If underfunded, report the wallet address and the shortfall to "
        "the user and stop. Suggested ways for them to fund it: withdraw ETH "
        "from Coinbase / Binance / OKX with network set to Base, or bridge "
        "via superbridge.app / bridge.base.org.\n\n"
        "3. Register on-chain.\n"
        f"   - Contract: {default_reg}\n"
        f"   - chainId:  {CHAIN_ID} (Base)\n"
        "   - Function: register() — no arguments, nonpayable, returns "
        "(uint256 agentId).\n"
        "   - Submit the transaction, wait for it to be mined, and confirm "
        "status == 1.\n\n"
        "4. Read your agentId.\n"
        "   - In the receipt logs, find the Registered event:\n"
        "       Registered(uint256 indexed agentId, string agentURI, "
        "address indexed owner)\n"
        "   - Your agentId is the first indexed parameter.\n\n"
        "5. Report back.\n"
        "   - Reply to the user with ONLY this single line, no quotes, no "
        "markdown, no extra words:\n"
        f"       eip155:{CHAIN_ID}:{default_reg}:<your-agentId>\n\n"
        "If any step fails, report exactly which step, the error, and what "
        "you need from the user to continue."
    )
    intro = (
        "**This server gatekeeps on ERC-8004 agent ownership.** To join, "
        "your **agent** has to register itself on Base — you don't do it by "
        "hand.\n\n"
        "Tap **🤖 Registration prompt for my agent** below, long-press the "
        "block to copy, and send it to your agent. It will handle wallet, "
        "funding check, and the on-chain `register()` call, then reply with "
        "its identifier. Paste that into `/verify agent:<the-string>` to "
        "start verification."
    )
    view = _CopyPromptView([
        ("Registration prompt for my agent", agent_prompt,
         {"emoji": "🤖", "style": discord.ButtonStyle.primary}),
    ])
    await interaction.response.send_message(intro, view=view, ephemeral=True)


# ----- error handling ----------------------------------------------------


async def _on_app_error(
    interaction: discord.Interaction, error: app_commands.AppCommandError
) -> None:
    log.exception("Slash command error: %s", error)
    msg = f"Error: `{error}`"
    if interaction.response.is_done():
        await interaction.followup.send(msg, ephemeral=True)
    else:
        await interaction.response.send_message(msg, ephemeral=True)


for _cmd in (
    start_verify_cmd, register_help_cmd, verify_cmd, submit_cmd,
    whoami_cmd, my_agents_cmd,
    rule_help_cmd, rule_add_cmd, rule_remove_cmd, rule_list_cmd,
    sync_me_cmd, sync_roles_cmd,
):
    _cmd.error(_on_app_error)


def main() -> None:
    if not DISCORD_TOKEN:
        raise SystemExit("DISCORD_TOKEN not set — copy .env.example to .env and fill it in.")
    bot.run(DISCORD_TOKEN)


if __name__ == "__main__":
    main()
