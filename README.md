# ETH Agent Verify Bot

Discord bot that proves a user controls an **ERC-8004 ("Trustless Agents")**
registered agent. The user signs an **EIP-712** challenge with the wallet
that controls the agent (NFT owner *or* `agentWallet` metadata), the bot
recovers the signer, cross-checks against the on-chain Identity Registry,
and records the binding.

Same architecture as the BIP-322 Ordinal Verify Bot, ported to Ethereum.

## How it works

1. `/verify agent:<eip155:CHAIN:REGISTRY:AGENT_ID>` — bot looks up
   `ownerOf(agentId)` on the configured Identity Registry, builds a
   single-use EIP-712 payload bound to the user's Discord ID, the agent
   identifier, a 256-bit nonce, and a 5-minute deadline.
2. User signs the payload with `eth_signTypedData_v4` (from MetaMask,
   Rabby, WalletConnect, etc.). A static `sign.html` page can be hosted
   on GitHub Pages to make this one click on mobile.
3. `/submit signature:<0x…>` — bot recovers the signer and accepts only
   if it matches `ownerOf(agentId)` or `getMetadata(agentId, "agentWallet")`.
4. The verified binding is written to SQLite; configured holder-rules are
   evaluated against the agent's registration JSON, and matching Discord
   roles are granted.

All bot replies are **ephemeral** — signatures, addresses, and agent IDs
are never visible to other channel members.

## Holder-rules

Admins can grant Discord roles automatically based on facts about the
agent's registration:

| Match type      | Value                                  | Matches when… |
|-----------------|----------------------------------------|---------------|
| `registry`      | `chainId:registryAddress`              | Agent is registered in that Identity Registry |
| `trust_model`   | `tee-attestation`, `zkml`, etc.        | Agent's `supportedTrustModels` contains the value |
| `agent_type`    | The agent's `type` field               | Exact match (case-sensitive) |
| `service_proto` | `mcp`, `a2a`, `ens`, `did`, `email`, … | Agent advertises a service with that protocol |

Rules are evaluated on every successful `/submit` **and** on `/sync_me` /
`/sync_roles`. Sync is safe: roles outside the configured rules are never
touched, and a transient RPC error aborts the diff instead of stripping
roles.

## Commands

| Command                         | What it does |
|---------------------------------|--------------|
| `/start_verify`                 | Mobile-friendly walkthrough: three buttons reveal copy-ready prompts for asking your agent for its ID and templates for `/verify` and `/submit` |
| `/register_help`                | One-button copy-paste prompt to send to your agent so it self-registers on the configured Identity Registry, then reports back the canonical `eip155:…` identifier |
| `/verify agent:<id>`            | Issue an EIP-712 challenge for an agent ID. Reply has a 🤖 button that emits an agent-addressed prompt with the typed data inlined — paste it to a wallet-capable AI agent and get a signature back |
| `/submit signature:<0x…>`       | Submit the signature; record the binding |
| `/whoami`                       | Flat list of the agents you've verified |
| `/my_agents`                    | Per-wallet view: groups your verified agents by signing wallet, flags transferred-away tokens, and surfaces unverified-but-owned agents via on-chain `balanceOf` |
| `/sync_me`                      | Re-check your agents and update your roles |
| `/sync_roles [@member]`         | Admin: sync one member or every verified member |
| `/rule_add`                     | Bind a Discord role to an agent fact |
| `/rule_list`                    | Show this server's holder-rules |
| `/rule_remove rule_id:<n>`      | Delete a holder-rule |
| `/rule_help`                    | Setup guide for holder-rules |

### Agent-driven onboarding

The bot assumes the user is the *operator* of an autonomous agent, not the
signer themselves. `/start_verify` and `/register_help` produce prompts
*addressed to the agent* (not to the human) — the human pastes one block,
the agent does the on-chain work and replies with a single deterministic
token the human pastes back. Each step is gated behind a Discord UI button
so mobile users get one focused code block to long-press, instead of a
scroll of inline `` ``` `` fences.

Specifically, the `/start_verify` "ask agent for ID" prompt walks the
agent through `balanceOf(yourAddress)` on the configured registry,
explains that a registered ERC-8004 agent is an ERC-721 NFT minted by
that contract (so `tokenId == agentId`), and asks for a YES reply in
canonical `eip155:CHAIN:REGISTRY:AGENTID` form or a literal `NOT_REGISTERED`
reply that the human can route into `/register_help`.

## Setup

Requires Python 3.10+ (the code uses PEP 604 `X | None` unions).

```bash
git clone <repo>
cd eth-agent-verify-bot
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then edit
python eth_agent_verify_bot.py
```

### Discord permissions

OAuth2 scopes: `bot`, `applications.commands`. Bot permissions integer
`268782592` covers everything the bot uses (View Channels, Send Messages,
Embed Links, Read Message History, Use External Emojis, Manage Roles).
The `Manage Roles` permission is the only one that's strictly required —
without it `/submit` records the binding but can't grant the role.

**Role hierarchy:** the bot's own role must sit *above* any role it
grants, or `add_roles` will surface a `Forbidden` and the bot reports
"sits below this role." This is a Discord rule, not a bot setting.

**Privileged intents:** none are required for `/verify` and `/submit`
(slash commands carry their own data). Set `ENABLE_MEMBERS_INTENT=1`
*and* flip the Server Members toggle in the Developer Portal Bot tab
to make admin `/sync_roles` (no-arg, all-members form) find every
verified member without each having to interact first.

### Configuration

- `DISCORD_TOKEN` — bot token.
- `GUILD_ID` — comma-separated list of guild IDs to register slash
  commands into. One guild = instant per-guild registration. Multiple
  guilds = one bot process serves multiple servers, each with its own
  instant sync. Leave empty for global registration (~1 hour to
  propagate). Per-guild sync errors (e.g., bot not invited there yet)
  are logged as warnings and don't abort sync of the other guilds.
- `VERIFIED_ROLE_ID` — base role granted on any successful
  verification. Accepts either a bare role id (applies to every guild)
  or a `guild_id:role_id,guild_id:role_id,…` mapping so each guild
  gets its own verified role.
- `ENABLE_MEMBERS_INTENT` — set to `1`/`true`/`yes` to enable the
  Server Members privileged intent (see "Discord permissions" above).
  Off by default so the bot doesn't crash on connect if the Developer
  Portal toggle is also off.
- `CHAIN_ID` — chainId of the Identity Registry (default `8453`, Base).
- `RPC_URL` — JSON-RPC endpoint for that chain.
- `REGISTRY_ADDR` — deployed Identity Registry address.
- `SIGN_PAGE_URL` — optional URL of the static EIP-712 signer page; when
  set, `/verify` shows a "Sign with my wallet" link with the typed data
  pre-filled.
- `DB_PATH` — SQLite path (default `verifications.db`).
- `IPFS_GATEWAY` — optional HTTPS gateway for `ipfs://` `tokenURI` values.

### Security notes

- EIP-712 payload binds `discordId`, `agentId`, `registry`, a 256-bit
  random `nonce`, and a `deadline`. The `chainId` is in the domain
  separator — signatures cannot be replayed across chains.
- Nonces are single-use and held in memory only; bot restart invalidates
  every pending challenge.
- `/submit` accepts the recovered signer only if it equals `ownerOf`
  *or* the on-chain `agentWallet`. Both are re-read fresh at submit time
  — a transferred NFT immediately fails the next attempt.
- `/sync_*` re-checks current ownership and removes only roles granted
  by holder-rules. Roles granted by other bots stay untouched.

## Tests

```bash
pip install pytest
pytest -m "not network"
```

The default suite mocks the registry boundary — no chain reads. Mark
network-dependent tests with `@pytest.mark.network` for opt-in live runs.

## License

MIT
