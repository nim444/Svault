# End-to-end walkthrough

A complete run-through of Svault's AI-aware flow: create a vault, classify secrets
with descriptions, define callers, turn on the AI judge, and watch a real model
grant or deny agent requests. The judge outputs below are **actual responses** from
`google/gemini-2.5-flash` via OpenRouter.

> **Vaults are addressed by name.** You can keep several (local today, remote on the
> [roadmap](roadmap.md)). The `secret`, `get`, and `settings` commands take
> `-v <vault>`; `unlock` and `lock` take the name as a positional argument. Omit the
> name only when there's a single vault.

## 1. Build

```bash
git clone https://github.com/Soluzy/Svault.git
cd Svault && cargo build --release
alias svault="$PWD/target/release/svault"
```

## 2. Create a vault (with a description)

```bash
svault create
#   Name:           billing-api
#   Description:    production billing service           ← the judge sees this
#   Allow agents:   list  → claude-code, billing-worker
#   Rate limit:     20/hour
#   Default tier:   medium
#   Use AI judge:   yes
#   Master passphrase: ********   ← first run only; one secret unlocks every vault
# → prints a one-time RECOVERY CODE; save it.
```

The vault description is the overall context the judge sees. Storage is `local`
today. There is no per-vault passphrase — the first `create` sets a **master
passphrase** that unlocks every vault; later vaults reuse it.

## 3. Add secrets — classify them and say what they're for

`--description` records the secret's purpose. The judge weighs each request's
*reason* against it, so an off-purpose request is denied even when the caller and
scope check out.

```bash
svault secret add DATABASE_URL -v billing-api --scope database --tier medium \
  --description "production Postgres connection string"

svault secret add STRIPE_KEY -v billing-api --scope payments --tier high --require-reason \
  --description "production Stripe charge key — only for billing/charge flows"
```

Classification lives **AES-256-GCM encrypted inside `vault.enc`**. Without the vault
key, a same-UID process can neither read a tier, scope, or purpose at rest to plan a
passing request nor downgrade one. In the TUI, `a` in the secret browser opens the
same form (name / value / scope / description / tier / require-reason).

## 4. Define who may ask (callers)

Caller rules live encrypted in the vault as well, so there is no committable
`svault.policy.yaml`. Seed the defaults, then edit them in `svault settings`:

```bash
svault policy init                # seed default callers into the vault's encrypted policy
svault policy check claude-code   # what it can reach + recent activity (unlocks the vault)
```

Conceptually a vault's caller rules look like:

```yaml
callers:
  claude-code:
    scopes: [database, api]
    rate_limit: 20/hour
  billing-worker:
    scopes: [payments]
    rate_limit: 60/hour
  default:
    scopes: []
    rate_limit: 5/hour
```

## 5. Turn on the AI judge

There is no plaintext config and no key file. Every judge — its model, thresholds,
free-text **criteria**, and its own API key — lives AES-256-GCM **encrypted** in the
keyring at `.svault/keyring.enc`, opened by your **master passphrase** (no separate
keyring passphrase). Create the keyring, add a named judge (with criteria and key),
enable the judge globally, then unlock once:

```bash
svault keyring init                 # create the keyring under your master (one-time)
svault judge add strict             # prompts: model, thresholds, criteria, then the API key (hidden)
#   Model:               google/gemini-2.5-flash
#   Allow threshold:     60
#   High threshold:      80
#   Criteria:            Only allow billing-related reasons that name an invoice or charge.
#   OpenRouter API key:  sk-or-…           (blank = fall back to $SVAULT_OPENROUTER_KEY)
svault judge enable                 # flip the global on/off switch (on)
svault keyring unlock               # caches a 0600 session key so the judge is live this session
svault judge status
# keyring: unlocked
# judge (global): on   default: strict
# strict   google/gemini-2.5-flash   allow 60  high 80  KEY set
```

The first judge you add becomes the keyring's **default**, which vaults with no
explicit assignment use. A vault opts in to the judge via its per-vault toggle (set
at `svault create` or in settings); the keyring's global switch and each judge's
criteria are managed here. Until the keyring is unlocked the judge stays off and the
static tier rules apply (high = human-only).

## 6. Dry-run the model — `svault judge test`

This builds a sample request and asks the live model; nothing is read or written.
Pass a realistic `--vault` (the model sees it) and the descriptions. The outputs
below are real model responses:

```bash
# Plausible reason that matches the vault → ALLOW
svault judge test --vault billing-api --vault-description "production billing service" \
  --tier medium --scope database --secret DATABASE_URL \
  --reason "run the nightly billing migration against the production database" --caller claude-code
# ALLOW score 95 — Nightly billing migration is a plausible and specific reason for
#                  accessing the production database URL, matching the vault's purpose.

# Vague reason → DENY
svault judge test --vault billing-api --tier medium --scope database --secret DATABASE_URL \
  --reason "asdf" --caller claude-code
# DENY score 10 — Stated reason 'asdf' is vague and unspecific.

# Reason matches the secret's description → ALLOW
svault judge test --vault billing-api --tier high --scope payments --secret STRIPE_KEY \
  --description "production Stripe charge key — only for billing/charge flows" \
  --reason "charge a customer invoice for the monthly subscription" --caller billing-worker
# ALLOW score 95 — Caller is a billing worker, requesting a Stripe key for a billing-api
#                  vault to charge a customer invoice, which aligns perfectly with the
#                  secret's purpose.

# Reason contradicts the secret's description → DENY
svault judge test --vault billing-api --tier high --scope payments --secret STRIPE_KEY \
  --description "production Stripe charge key — only for billing/charge flows" \
  --reason "export the full customer email list for a marketing campaign" --caller billing-worker
# DENY score 90 — Stated reason does not match secret's purpose. STRIPE_KEY is for
#                 billing/charge flows, not exporting customer email lists.
```

The last two are the headline behavior: same secret, same caller, same tier — the
**reason versus the documented purpose** is what flips the decision.

## 7. The agent request — `svault get`

Unlock once (or run the [daemon](daemon.md) so the key stays in memory), then the
agent path runs the full gate — policy, then tier, then judge, then audit —
**enforced inside the daemon**.

```bash
svault daemon start
svault unlock billing-api

# Granted — reason fits the secret's purpose
svault get STRIPE_KEY -v billing-api --scope payments \
  --reason "charge a customer invoice for the monthly subscription" --caller billing-worker
# → sk_live_...        (value to stdout; a one-line granted: status to stderr)

# Denied — reason doesn't fit
svault get STRIPE_KEY -v billing-api --scope payments \
  --reason "export the customer email list for marketing" --caller billing-worker
# → denied: request not authorized for this secret
#   (exits non-zero; no value printed)
```

On allow, only the value goes to stdout, so an agent capturing stdout never sees the
rationale. On deny the caller gets a single **generic** message; the real reason
(judge score plus rationale, scope or caller mismatch, rate limit) is recorded only
in the audit log, so the agent can't hill-climb a denied request into a passing one.

## 8. Tiers and fail modes

| Tier | Judge on | If the judge is unreachable |
|---|---|---|
| `low` | skipped (unless `require_reason`) | allow |
| `medium` | allow if score ≥ `allow_threshold` (60) | **fail-open**, audit-flagged `judge-unavailable` |
| `high` | allow if score ≥ `high_threshold` (80) | **fail-closed** (deny) |

With the judge **off** (keyring locked, global switch off, no resolved key, or the
vault opted out), the gate falls back to the static rule (high = human-only), so
nothing regresses. To verify fail-closed, edit a judge (`svault judge edit strict`)
to point its base URL at an unreachable host, then request a high-tier secret — it
denies.

## 9. Review the audit trail

Every decision is appended to `.svault/billing-api/audit.log` (gitignored, `0600`),
stamped with the **peer UID** of the connecting process (unforgeable, unlike the
self-asserted `--caller`) and the judge's score and rationale — never the secret
value.

```bash
svault policy check billing-worker   # scopes, reachable secrets, recent allows/denials
```

## Notes

- **Key safety.** Each judge's OpenRouter key is stored AES-256-GCM encrypted in
  `.svault/keyring.enc`, never in a plaintext file. A judge with no stored key falls
  back to the opt-in `$SVAULT_OPENROUTER_KEY` environment variable. Rotate a key with
  `svault judge set-key <name>` if it is ever exposed (for example, pasted into a chat
  or a log).
- **What the judge sees.** Secret name, scope, tier, caller, reason, recent activity,
  and any vault or secret descriptions — **never the secret value**. Keep descriptions
  free of sensitive data, since they are sent to the model. See
  [security.md](security.md#ai-judge).
- **Honest boundary.** Svault enforces the gate for cooperative or semi-trusted agents
  and keeps a tamper-resistant audit trail. It is *not* a sandbox against a hostile
  same-UID process, which can read the unlocked daemon's memory directly.
