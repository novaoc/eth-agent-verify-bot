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
| `/verify agent:<id>`            | Issue an EIP-712 challenge for an agent ID |
| `/submit signature:<0x…>`       | Submit the signature; record the binding |
| `/whoami`                       | List the agents you've verified |
| `/sync_me`                      | Re-check your agents and update your roles |
| `/sync_roles [@member]`         | Admin: sync one member or every verified member |
| `/rule_add`                     | Bind a Discord role to an agent fact |
| `/rule_list`                    | Show this server's holder-rules |
| `/rule_remove rule_id:<n>`      | Delete a holder-rule |
| `/rule_help`                    | Setup guide for holder-rules |

## Setup

```bash
git clone <repo>
cd eth-agent-verify-bot
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then edit
python eth_agent_verify_bot.py
```

### Configuration

- `DISCORD_TOKEN` — bot token.
- `GUILD_ID` — register slash commands to one guild for instant updates.
- `VERIFIED_ROLE_ID` — base role granted on any successful verification.
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
