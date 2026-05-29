# Daemon

The daemon is an optional background process that holds unlocked vault keys **in memory** and serves secret reads over a local Unix socket. It replaces the file-based `.session` (which stores the derived key on disk) with a real "unlock once, use many times" session whose key material never touches disk.

It is **Unix-only** (macOS, Linux). On Windows the `daemon` commands print a note and everything falls back to the file session — no behavior changes.

## Why

Without the daemon, `svault unlock` caches the vault's derived key (not the passphrase) in `.svault/<vault>/.session` (mode `0600`) so later commands don't re-prompt. The daemon is the stronger option:

- The derived key lives only in the daemon's memory — there's **no `.session` file** written while the daemon is up.
- Keys are zeroized the moment a vault is locked, evicted by a timeout, or the daemon shuts down.
- Auto-lock is real: an idle timer and a hard-max timer drop keys automatically.

## Commands

```bash
svault daemon start     # spawn the daemon detached (logs to .svault/daemon.log)
svault daemon status    # list unlocked vaults + remaining idle / hard-max timers
svault daemon doctor    # health check (see below); add --fix to clean stale files
svault daemon stop      # lock everything and stop the daemon
svault daemon run       # run the server in the foreground (debugging)
```

Once the daemon is running, the normal commands route through it automatically:

```bash
svault daemon start
svault unlock myvault        # key cached in the daemon, no .session file written
svault get API_KEY --scope deploy --reason "ci" --caller ci   # served from memory, no prompt
svault secret get API_KEY    # served from memory, no prompt
svault status                # shows "unlocked (daemon)" for in-memory vaults
svault lock myvault          # drops the key from the daemon
```

If no daemon is running, every command behaves exactly as before (file session). You never have to use the daemon — it's purely opt-in.

You can also control it from the [interactive TUI](tui.md): the header shows a `daemon running` / `daemon off` indicator, and pressing `d` on the vault list starts it if it's off or stops it if it's running.

> **Note:** the daemon accelerates the **read** path (`unlock`, `get`, `secret get`, `lock`, `status`). Mutations — `secret add`, `secret list`, `secret remove` — still prompt for the passphrase, since the daemon deliberately holds only the key, not the passphrase, and does not expose write operations over the socket.

## Auto-lock

Two timers, both configurable in `.svault/config.yaml`:

| Setting | Default | Meaning |
|---|---|---|
| `idle_timeout_secs` | `900` (15 min) | Drop a vault's key after this long with no access. Reset on every `get`. |
| `max_unlocked_secs` | `28800` (8 h) | Hard cap — drop the key this long after unlock, regardless of activity. |

```yaml
# .svault/config.yaml
lock:
  idle_timeout_secs: 900
  max_unlocked_secs: 28800
daemon:
  max_connections: 512
```

A background ticker checks roughly every 10 seconds and evicts (and zeroizes) any key past either limit.

## Connection limits

The daemon serves one thread per connection. To bound that (so a runaway or hostile same-UID process can't spawn unbounded handler threads), it enforces a ceiling and a per-connection timeout:

| Setting | Default | Meaning |
|---|---|---|
| `daemon.max_connections` | `512` | Maximum simultaneously-served connections. Beyond it, new connections get a `too many connections` error and the client falls back. |
| (fixed) read timeout | `30 s` | A connection that opens but never finishes sending a request is dropped, so it can't pin a handler. |

The default is generous enough that realistic single-user / multi-agent concurrency never hits it (see the [stress simulation](security-review/stress/0.6.0.md) — 64-way concurrent reads refused nothing at the default). Lower it on small or shared hosts; raise it on big multi-agent boxes. The client (`daemon::send`) also retries a connect a few times with short backoff, so a momentary OS listener-backlog drop under burst is served rather than failing hard.

## doctor

`svault daemon doctor` runs read-only diagnostics and exits non-zero if anything is wrong:

- whether a daemon is running (and answers a ping), and its pid;
- the socket path and that its permissions are `0600`;
- the effective idle / hard-max timeouts and whether they came from `config.yaml` or defaults;
- **stale-state detection** — a socket file with no daemon behind it, or a pid file whose process is gone (both left by a crash).

```bash
svault daemon doctor          # report only
svault daemon doctor --fix    # also remove a stale socket / pid file
```

## How it works

- One daemon per project `.svault/`. Socket at `.svault/daemon.sock` (mode `0600`), pid at `.svault/daemon.pid`, log at `.svault/daemon.log`. All three are inside `.svault/`, which is gitignored.
- `start` execs `svault daemon run` in its own session (`setsid`) so closing the terminal won't kill it; output goes to the log file.
- Protocol: newline-delimited JSON requests (`Ping`, `Status`, `Unlock`, `Lock`, `LockAll`, `Get`, `Shutdown`) over the socket.
- **Concurrency:** the listener spawns one thread per connection. Shared key state is a mutex-guarded map, but a `Get` only holds the lock long enough to copy the 32-byte key and update the last-used timestamp — the actual AES-GCM decryption happens outside the lock, so parallel reads from many agents don't serialize on each other.
- On `stop` / `Shutdown` the daemon clears its key map (zeroizing every key) and removes the socket and pid file. A `stop` fallback signals the pid if the socket is unresponsive.

## Platform support

Unix (macOS, Linux) only. On Windows, `svault daemon <...>` prints `svault daemon is Unix-only — using the file session instead.` and `unlock` / `get` / `lock` / `status` use the file `.session` path unchanged.
