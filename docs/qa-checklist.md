# Manual QA checklist

A scenario-driven, hands-on test pass across the three surfaces — **CLI**, **TUI**,
and **MCP** — to run before tagging a release (and the 0.9.9 → 1.0 readiness gate in
particular). Unit tests cover the logic; this checklist covers the interactive and
end-to-end behaviour they can't.

Each scenario lists a **Goal**, any **Pre-req**, the **Steps**, the **Expected**
result, and a checkbox to tick. Run in a scratch directory so the real `.svault/`
is untouched:

```bash
mkdir -p /tmp/svault-qa && cd /tmp/svault-qa
cargo build --features yubikey       # or use the release binary
alias sv="$(pwd)/target/release/svault"   # adjust to your build path
```

Conventions: "agent get" means `svault get <NAME> --scope <S> --reason "<R>" --caller <C>`.
A **fresh run** means no master session is cached (run `svault lock --all` first, or
wait past the 6h cap). Reset between sections with `rm -rf .svault`.

---

## A. First run & identity (TUI)

### A1. First-run onboarding
- **Goal:** A brand-new install walks through disclaimer → passphrase → recovery → optional YubiKey.
- **Pre-req:** No `.svault/` exists.
- **Steps:** Launch `sv` (no subcommand).
- **Expected:**
  - A disclaimer / boundary screen appears first; it states the same-UID boundary honestly and requires an explicit accept.
  - Then a set-master-passphrase screen (with confirm + strength feedback).
  - Then a one-time recovery code screen that requires `y` to dismiss (and warns it is shown once).
  - Then an optional YubiKey enrollment screen that can be skipped.
  - You land on the vault list, signed in.
- [ ] Pass

### A2. Sign-in gate on reopen
- **Goal:** Reopening after the session expires requires the master again.
- **Pre-req:** Onboarding done (A1).
- **Steps:** Quit the TUI, run `sv lock --all`, relaunch `sv`.
- **Expected:** A **login screen** (master passphrase, or `Ctrl+Y` for an enrolled YubiKey) appears before the vault list.
- [ ] Pass

### A3. Logout (`o`)
- **Goal:** Logout signs out only — it does not lock vaults or change data.
- **Steps:** From the vault list, unlock a vault, then press `o`.
- **Expected:** You return to the **login screen**. After signing back in, the vault you unlocked is still unlocked, the keyring/daemon/judge and all data are unchanged.
- [ ] Pass

---

## B. Vaults, secrets & classification (CLI + TUI)

### B1. Create a vault and add tiered secrets
- **Goal:** Create + classify across all tiers.
- **Steps:**
  ```bash
  sv create                      # name: proj, accept defaults
  sv secret add DB_URL   --scope database --tier low    --description "dev database dsn"
  sv secret add API_KEY  --scope api      --tier medium --description "billing api key"
  sv secret add DEPLOY   --scope deploy   --tier high   --description "prod deploy key"
  sv secret list
  ```
- **Expected:** All three are added; `secret list` shows names only (never values). `meta.yaml` contains **no** scope/tier/description (it's encrypted in `vault.enc`).
- [ ] Pass

### B2. Classify in the TUI (incl. conditions)
- **Goal:** The `c` reclassify form edits scope/tier/require-reason **and** windows / required callers.
- **Steps:** In the TUI secret browser, select `API_KEY`, press `c`. Set Windows = `mon-fri 09:00-18:00`, Required callers = `ci`. Save.
- **Expected:** Form has all six fields; a bad window spec re-shows the form with an error rather than saving; on success the change persists (`sv policy check ci` shows the window + caller).
- [ ] Pass

---

## C. The agent gate (CLI)

> Set up caller rules first: `sv policy init` (seeds `default`), or add a caller via the TUI.

### C1. Allow path
- **Steps:** `sv get DB_URL --scope database --reason "run the nightly database backup" --caller default`
- **Expected:** The value is printed to **stdout**; status text (if any) goes to stderr.
- [ ] Pass

### C2. Reason floor
- **Steps:** `sv get DB_URL --scope database --reason "need" --caller default`
- **Expected:** Denied with the generic message; exit non-zero; no value.
- [ ] Pass

### C3. Scope mismatch
- **Steps:** `sv get DB_URL --scope api --reason "legit reason for the db" --caller default`
- **Expected:** Generic denial (the real reason — scope mismatch — is only in `audit.log`).
- [ ] Pass

### C4. Rate limit / burst
- **Steps:** Repeat an allowed `get` rapidly past the caller's rate limit / burst threshold.
- **Expected:** Once over the limit, requests are denied generically; the audit log records the rate/burst reason.
- [ ] Pass

### C5. High-tier, no judge
- **Steps:** `sv get DEPLOY --scope deploy --reason "deploy the release now" --caller default`
- **Expected:** Denied (high-tier is human-only with no judge). `sv secret get DEPLOY` (human path) still returns the value.
- [ ] Pass

### C6. Locked vault is a dead end (agent get never prompts)
- **Goal:** The agent path never prompts for the master — a locked vault tells a human to unlock.
- **Steps:** `sv lock --all` (and stop the daemon if running), then `sv get DB_URL --scope database --reason "run the nightly database backup" --caller default`.
- **Expected:** No passphrase prompt; it prints `denied: vault '<name>' is locked — a human must run 'svault unlock' first` and exits non-zero. (`svault secret get` / the TUI still prompt — only the agent path is silent.)
- [ ] Pass

### C7. Caller rotation can't beat the burst ceiling
- **Goal:** Rotating `--caller` doesn't evade burst detection.
- **Steps:** Drive >10 *allowed* reads of one low-tier secret inside ~10s while cycling caller names, e.g. `for i in $(seq 1 12); do sv get DB_URL --scope database --reason "scheduled backup pass $i" --caller rot$i; done`.
- **Expected:** After the per-secret ceiling (10 allowed reads/10s across all callers) the requests are denied generically, even with fresh caller names; the audit log shows the secret-burst reason.
- [ ] Pass

---

## D. Conditional access (CLI)

### D1. Required caller
- **Pre-req:** `API_KEY` has `--require-caller ci` (B2).
- **Steps:** `sv get API_KEY --scope api --reason "charge the nightly invoices" --caller claude`
- **Expected:** Denied (caller not in the required list). The same request with `--caller ci` is evaluated normally.
- [ ] Pass

### D2. Time window — in and out
- **Steps:** Add a secret with a window that is **open now** and another whose window is **closed now**:
  ```bash
  sv secret add NOW_OK  --scope ops --tier low --window "00:00-23:59" --require-caller ci
  sv secret add NOW_NO  --scope ops --tier low --window "00:00-00:01" --require-caller ci
  sv get NOW_OK --scope ops --reason "scheduled ops task run" --caller ci
  sv get NOW_NO --scope ops --reason "scheduled ops task run" --caller ci
  ```
- **Expected:** `NOW_OK` allowed (assuming it's not 00:00–00:01); `NOW_NO` denied generically — and the denial text never reveals the window.
- [ ] Pass

---

## E. Seal & escalate (CLI + TUI)

### E1. Sustained abuse seals a secret
- **Goal:** 5 denials in 5 minutes on a medium/high secret seal it.
- **Steps:** Drive 5+ denials on a medium secret, e.g. repeat a scope-mismatch get:
  ```bash
  for i in $(seq 1 5); do sv get API_KEY --scope wrong --reason "probing scope number $i now" --caller ci; done
  sv pending
  ```
- **Expected:** `sv pending` lists `API_KEY` as sealed (with denial count, last caller, sealed-at).
- [ ] Pass

### E2. Sealed denies even a valid request
- **Steps:** `sv get API_KEY --scope api --reason "legitimate billing run for tonight" --caller ci` (a request that would otherwise pass the conditions).
- **Expected:** Still denied generically while sealed.
- [ ] Pass

### E3. Human still reads it
- **Steps:** `sv secret get API_KEY`
- **Expected:** Returns the value — the seal blocks the agent path only.
- [ ] Pass

### E4. Approve clears the seal (and re-prompts the master)
- **Steps:** `sv approve API_KEY -v proj` then re-run a valid agent get.
- **Expected:** Approve **re-prompts the master credential** (passphrase or YubiKey touch) even if a session is cached — it ignores the cached session, so a lingering unlock can't clear a seal unattended. After the correct master, it confirms; `sv pending` no longer lists it; the valid agent get is evaluated normally again. (In a non-TTY/no-prompt context, approve refuses.)
- [ ] Pass

### E5. Approve in the TUI
- **Steps:** Re-seal (E1), open the TUI secret browser. 
- **Expected:** The sealed secret is shown in red with `SEALED — press A to approve`; pressing `A` clears it and the marker disappears; `Enter` still reveals its value while sealed.
- [ ] Pass

---

## F. MCP (end-to-end with an agent client)

> Wire `svault mcp` into an MCP client (Claude Code / Cursor) per [mcp.md](mcp.md), or
> drive it from a shell as shown there. Keep a vault unlocked first (`sv unlock`,
> ideally with the daemon running).

### F1. Discover + allowed get
- **Steps:** From the agent, call `svault_list_vaults`, then `svault_get_secret` for a low-tier secret with a good reason.
- **Expected:** The vault list shows lock state; the low-tier get returns the value through the same gate (audited `source = mcp`).
- [ ] Pass

### F2. Denied get is generic
- **Steps:** Call `svault_get_secret` with a weak/mismatched reason, or for a high-tier secret.
- **Expected:** `isError: true` with `request not authorized for this secret` — no value, no leak of why.
- [ ] Pass

### F3. Sealed secret via MCP
- **Steps:** With a secret sealed (E1), request it via `svault_get_secret`.
- **Expected:** Generic denial; the agent cannot tell it's sealed vs any other denial, and cannot unseal it.
- [ ] Pass

### F4. Locked vault is a dead end
- **Steps:** `sv lock --all`, then request any secret via MCP.
- **Expected:** An error telling a human to run `svault unlock`; the agent cannot unlock it.
- [ ] Pass

---

## G. Daemon, sessions & the 6h cap (Unix)

### G1. Daemon lifecycle
- **Steps:** `sv daemon start`, `sv daemon status`, `sv unlock`, an agent get, `sv daemon stop`.
- **Expected:** Status shows running; the unlocked vault serves from memory (no `.session` while the daemon holds it); stop zeroizes and cleans up the socket/pid.
- [ ] Pass

### G2. 6-hour hard cap
- **Steps:** Unlock a vault, then back-date its session: edit the timestamp on the first line of `.svault/proj/.session` (and/or `.svault/.master.session`) to >6h ago.
- **Expected:** `sv status` shows the vault as **locked**; the next `get` re-prompts the master; the stale session file is removed.
- [ ] Pass

### G3. `lock --all`
- **Steps:** `sv lock --all`.
- **Expected:** Every vault and the master session are cleared.
- [ ] Pass

---

## H. YubiKey (hardware — opt-in `yubikey` build)

> Requires a build with `--features yubikey` and a YubiKey attached.

### H1. Enroll
- **Steps:** `sv master yubikey enroll` (touch + PIN if set), `sv master yubikey status`.
- **Expected:** Enrolled; `master.yubikey.enc` + `.meta` exist; status reports enrolled + device present.
- [ ] Pass

### H2. Unlock by touch
- **Steps:** `sv lock --all`, then `sv unlock` — choose the YubiKey path; or in the TUI login press `Ctrl+Y`.
- **Expected:** A touch unlocks the master (the in-TUI "Touch your YubiKey" modal appears and the dashboard is not wiped); the passphrase still works as a fallback.
- [ ] Pass

### H3. Remove
- **Steps:** `sv master yubikey remove`.
- **Expected:** The keyslot is removed; passphrase + recovery code still open everything.
- [ ] Pass

---

## I. Recovery & portability

### I1. Master recovery code
- **Steps:** `sv master recover` with the code from onboarding; set a new passphrase.
- **Expected:** Unwraps the master and re-wraps under the new passphrase; every vault + the keyring reopen; nothing re-encrypted; the code is unchanged.
- [ ] Pass

### I2. Per-vault recovery
- **Steps:** `sv recover proj` with that vault's recovery code.
- **Expected:** Re-attaches the vault to the master; secrets preserved; the code stays the same.
- [ ] Pass

### I3. Export / import round-trip
- **Steps:** `sv export proj --out /tmp/proj.json`, then in a fresh `.svault/` `sv import /tmp/proj.json`.
- **Expected:** Checksum verified; import refuses to overwrite an existing name; secrets + classification survive the move.
- [ ] Pass

---

## Sign-off

- Tester: ____________________  Date: ____________  Build/commit: ____________
- Platform(s): ____________________________________________________________
- All scenarios pass, or deviations recorded above: [ ] yes  [ ] no — see notes.
