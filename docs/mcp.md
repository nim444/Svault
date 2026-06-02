# MCP server (`svault mcp`)

`svault mcp` runs a local [Model Context Protocol](https://modelcontextprotocol.io)
server that exposes Svault's **gated** secret access to MCP-aware agents — Claude
Code, Cursor, VS Code, and others. It speaks newline-delimited JSON-RPC 2.0 over
**stdio**, the standard transport for local MCP servers.

It is a thin **frontend**, not a new trust model: every secret request runs through
the exact same enforcement path as `svault get` — the daemon's policy + AI-judge
gate when the daemon is up, or the in-process gate against the session-cached key
otherwise. The human unlocks once; the agent then asks through the gate.

## Security model

- **No passphrase ever reaches the server.** `svault mcp` never prompts for and
  never sees the master passphrase. It serves only from already-**unlocked** state
  — keys held in the daemon's memory, or the `0600` session key on disk — exactly
  like the CLI's agent path.
- **A locked vault is a dead end for the agent.** If the vault isn't unlocked, the
  call returns an error telling a human to run `svault unlock`. The agent cannot
  unlock anything itself.
- **The gate decides, the same way it always does.** Low-sensitivity secrets are
  returned directly; medium/high are evaluated by the policy engine and the AI
  judge against the agent's stated `reason`. High-sensitivity secrets are
  **human-only** when no judge is configured.
- **Denials are generic.** A denied request gets a single opaque message
  (`request not authorized for this secret`). The real reason — judge score,
  scope/caller mismatch, rate limit, an out-of-window or wrong-caller
  **condition**, or a **seal** — is recorded only in the audit log, so an agent
  can't probe its way to a passing request, read a time window to wait for it, or
  tell a seal from any other denial.
- **Sealed secrets stay sealed for the agent.** Once a secret is sealed (after
  repeated denials), every MCP `get` returns the same generic denial until a human
  clears it; the agent cannot unseal it. The capability descriptor warns that some
  secrets are restricted by caller/time or may be sealed, and that a denial may be
  final — so a well-behaved agent stops rather than retrying in a loop.
- **Everything is audited**, stamped `source = mcp`, and visible in the activity
  timeline (TUI `v`) so you can see exactly what an agent asked for and when.

What the server *does* touch, in the no-daemon case, is the per-vault session key
(the cached data key, `0600`) — the same key the CLI's local path uses. It never
sees the master passphrase or any other vault's key.

## Tools

The server exposes two tools (see them with an MCP client's tool inspector, or by
sending `tools/list`):

### `svault_get_secret`

Request a secret through the gate.

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | The secret's name. |
| `scope` | yes | The secret's category, e.g. `database`. Must match the secret's classified scope. |
| `reason` | yes | A concise, truthful justification (≥ 10 chars; placeholders are rejected). |
| `vault` | no | Vault name. Required only if more than one vault exists. |
| `caller` | no | The agent's identity. Defaults to `$SVAULT_CALLER`, then `default`. |

Returns the secret **value** on allow. On a tool-level failure it returns
`isError: true` with one of: the generic denial, `secret '…' not found`, or
`vault '…' is locked — a human must run svault unlock`.

### `svault_list_vaults`

Lists the vaults on this machine and whether each is currently unlocked. No
arguments. Returns a JSON array of `{ name, unlocked }`. Needs no keys — it's safe
discovery so the agent knows what exists and what it must ask a human to unlock.

## Capability descriptor

The server's `initialize` response carries an `instructions` string — the
**capability descriptor**. It tells an agent *how to request* a secret (which
fields to send, that high-tier may be human-only, that vague reasons are denied)
**without** revealing the decision criteria: tiers, thresholds, and judge prompts
stay encrypted and server-side. Advertise the interface, never the policy an agent
could game.

## Wiring it into an agent platform

`svault mcp` is a stdio MCP server, configured like any other. The human keeps a
vault unlocked (`svault unlock`, ideally with the daemon running — see
[daemon.md](daemon.md)); the agent then reaches secrets through the server.

**Claude Code** (`.mcp.json` in the project, or `claude mcp add`):

```json
{
  "mcpServers": {
    "svault": {
      "command": "svault",
      "args": ["mcp"],
      "env": { "SVAULT_CALLER": "claude-code" }
    }
  }
}
```

**Cursor / VS Code / others** use the same shape in their MCP config
(`command: "svault"`, `args: ["mcp"]`). Set `SVAULT_CALLER` to a stable identity
per agent so the audit log and rate limits can tell them apart.

The store lives at **`~/.svault`** by default, so the server finds your vaults no
matter which working directory the MCP host launches it from — and it shares that
store with the `svault` CLI/TUI you unlock with. To use a store somewhere other than
home, set **`SVAULT_HOME`** to the base directory that holds `.svault` (it resolves
`$SVAULT_HOME/.svault`) in the server's `env` **and** export the same value in the
shell you unlock from, so both agree. `SVAULT_HOME` governs the whole store — vaults,
master keyslots, keyring, sessions, and the daemon socket — together.

> You can also write this entry from the **TUI**: run `svault`, press `m` for the
> MCP screen, then `w` to drop (and merge) the `svault` server into `./.mcp.json`.
> Full `svault install` auto-config across platforms is still planned.

## Example session

A raw stdio transcript (what a client exchanges with the server):

```jsonc
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"svault","version":"0.9.8"},"instructions":"Svault gates access to secrets…"}}

→ {"jsonrpc":"2.0","method":"notifications/initialized"}        // notification, no reply

→ {"jsonrpc":"2.0","id":2,"method":"tools/list"}
← {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"svault_list_vaults",…},{"name":"svault_get_secret",…}]}}

→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"svault_get_secret","arguments":{"name":"DATABASE_URL","scope":"database","reason":"run the nightly migration"}}}
← {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"postgres://…"}],"isError":false}}   // allowed (low tier)

→ {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"svault_get_secret","arguments":{"name":"ROOT_KEY","scope":"payments","reason":"just exploring"}}}
← {"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"request not authorized for this secret"}],"isError":true}}   // high tier, denied
```

## Verify it from a shell

You can drive the server by hand to confirm it's wired correctly — pipe a couple
of JSON-RPC lines into `svault mcp`:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | svault mcp
# ← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",…,"serverInfo":{"name":"svault","version":"0.9.8"}}}
# ← {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"svault_list_vaults",…},{"name":"svault_get_secret",…}]}}
```

A real `svault_get_secret` call needs an unlocked vault (see the
[walkthrough](walkthrough.md#10-hand-it-to-an-agent-over-mcp)).

## Limitations

- **Unix daemon recommended.** Without the daemon, the server uses the file
  session fallback (same as the CLI). On Windows there is no daemon, so the session
  fallback is the only path.
- **No unlocking from MCP.** By design — unlocking is human-only.
- **One surface at a time.** A process is either the CLI, the TUI, or the MCP
  server; the audit/usage `source` reflects which.

See also: [Architecture](architecture.md) · [Policy engine](policy-engine.md) ·
[Daemon](daemon.md) · [Commands](commands.md).
