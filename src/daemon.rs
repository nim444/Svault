//! Background unlock daemon (Unix only).
//!
//! Replaces the file-based `.session` with a real process that holds derived
//! vault keys in memory and serves secret reads over a local Unix socket. One
//! daemon per project `.svault/`. Keys never touch disk — they're zeroized on
//! lock, on auto-lock eviction (idle / hard-max), and on shutdown.
//!
//! Concurrency: the listener accepts on the socket and spawns one std thread
//! per connection. Shared key state is an `Arc<Mutex<..>>`, but the critical
//! section is tiny — a `Get` clones the 32-byte key and bumps `last_used`
//! under the lock, then decrypts the value *outside* the lock, so parallel
//! reads don't serialize on each other.
//!
//! On non-Unix platforms this module compiles to stubs and the CLI falls back
//! to the file session (see `client`).

use serde::{Deserialize, Serialize};

pub const SOCKET_NAME: &str = "daemon.sock";
pub const PID_NAME: &str = "daemon.pid";
pub const LOG_NAME: &str = "daemon.log";

/// One request line (newline-delimited JSON) from a client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Liveness check.
    Ping,
    /// List unlocked vaults with their remaining idle / hard-max timers.
    Status,
    /// Cache a vault's derived key (hex-encoded, 32 bytes) in memory. The key is
    /// derived client-side from the passphrase, so the passphrase itself never
    /// crosses the socket (finding #3). The daemon validates the key opens the
    /// vault before caching it.
    Unlock { vault: String, key: String },
    /// Drop one vault's key.
    Lock { vault: String },
    /// Drop every cached key.
    LockAll,
    /// Read one secret value from an unlocked vault — the **human path**
    /// (`svault secret get`). Audited, but not policy/judge-gated; the human
    /// already holds the passphrase.
    Get { vault: String, secret: String },
    /// The **agent path** (`svault get`): a structured, policy- and judge-gated
    /// request. The daemon evaluates policy, consults the AI judge per tier,
    /// audits the decision (stamped with the peer UID), and only then returns a
    /// value. This is the enforced choke point (#2/#5/#22).
    GetGated {
        vault: String,
        secret: String,
        caller: String,
        scope: String,
        reason: String,
    },
    /// Lock everything and stop the daemon.
    Shutdown,
}

/// One response line from the daemon to a client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Pong {
        version: String,
    },
    Ok,
    Unlocked,
    Locked {
        count: usize,
    },
    Status {
        vaults: Vec<VaultStatus>,
    },
    Secret {
        value: String,
    },
    /// A gated request was allowed; carries the value and the secret's tier (for
    /// the granted-status line).
    Granted {
        value: String,
        tier: crate::policy::Tier,
    },
    /// A gated request was denied by policy or the AI judge.
    Denied {
        reason: String,
    },
    /// The vault isn't unlocked in the daemon — the caller should fall back.
    NotUnlocked,
    /// The vault is unlocked but the secret doesn't exist.
    NotFound,
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultStatus {
    pub name: String,
    pub idle_remaining_secs: u64,
    pub hard_remaining_secs: u64,
}

/// Pure auto-lock decision, factored out so it can be unit-tested with plain
/// numbers instead of wall-clock `Instant`s. A held key expires when it has
/// been idle past the idle timeout OR has been unlocked past the hard cap.
pub fn is_expired(idle_secs: u64, age_secs: u64, idle_timeout: u64, max_unlocked: u64) -> bool {
    idle_secs >= idle_timeout || age_secs >= max_unlocked
}

#[cfg(unix)]
mod imp {
    use super::{is_expired, Request, Response, VaultStatus, LOG_NAME, PID_NAME, SOCKET_NAME};
    use crate::crypto::VaultKey;
    use crate::judge::JudgeRuntime;
    use crate::vault::{Vault, SVAULT_DIR};
    use crate::{audit, gate, policy};
    use anyhow::{anyhow, Context, Result};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use zeroize::{Zeroize, Zeroizing};

    /// Per-connection read timeout. A client that opens the socket but never
    /// finishes sending a request can't pin a handler thread forever; the read
    /// errors out and the connection is dropped. Every real client does a fast
    /// connect → send → read → close, well under this.
    const CONN_READ_TIMEOUT: Duration = Duration::from_secs(30);

    /// Decrements the live-connection counter when a handler thread ends, even
    /// on panic (unwinding runs Drop), so the ceiling can't leak slots.
    struct ConnGuard(Arc<AtomicUsize>);
    impl Drop for ConnGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub fn base_dir() -> PathBuf {
        PathBuf::from(SVAULT_DIR)
    }
    fn socket_path(base: &Path) -> PathBuf {
        base.join(SOCKET_NAME)
    }
    fn pid_path(base: &Path) -> PathBuf {
        base.join(PID_NAME)
    }
    fn log_path(base: &Path) -> PathBuf {
        base.join(LOG_NAME)
    }
    fn vault_dir(base: &Path, name: &str) -> PathBuf {
        base.join(name)
    }

    /// A cached vault key plus the timestamps the auto-lock ticker reads.
    struct Held {
        key: Zeroizing<[u8; 32]>,
        unlocked_at: Instant,
        last_used: Instant,
    }

    type Store = Arc<Mutex<HashMap<String, Held>>>;

    /// Lock the key store, recovering the guard even if a previous holder
    /// panicked (poisoned the mutex). A single panicking connection handler must
    /// not take the whole daemon — and every still-held key — down with it. The
    /// worst a poisoned lock leaves behind is a possibly half-updated `last_used`
    /// timestamp; it can never leak or corrupt a key, so recovering is safe.
    fn lock_store(store: &Store) -> std::sync::MutexGuard<'_, HashMap<String, Held>> {
        store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Server-wide handler context, built once at start and shared (Arc) across
    /// connection threads. The judge is normally resolved per-request from the
    /// unlocked keyring (see [`resolve_judge`]); `judge_override` is a test-only
    /// seam to inject a fake transport — production sets it to `None`.
    pub(super) struct ServerCtx {
        base: PathBuf,
        idle: u64,
        max: u64,
        judge_override: Option<JudgeRuntime>,
    }

    /// Build the judge runtime for a gated request from the **unlocked keyring**:
    /// resolve the vault's assigned judge (or the keyring default), then its key.
    /// `None` when the keyring is locked, the global switch is off, or no key —
    /// the gate then applies the static tier rules. Per-vault `enabled = false`
    /// opt-out is honored inside the gate.
    fn resolve_judge(policy: &policy::VaultPolicyData) -> Option<JudgeRuntime> {
        let kr = crate::keyring::open_from_session()?;
        let (_name, def) = kr.data.resolve_judge(policy.judge.judge.as_deref())?;
        JudgeRuntime::from_def(def)
    }

    // ── Request handling ──────────────────────────────────────────────────

    fn handle(store: &Store, ctx: &ServerCtx, peer_uid: Option<u32>, req: Request) -> Response {
        let base = ctx.base.as_path();
        let (idle, max) = (ctx.idle, ctx.max);
        match req {
            Request::Ping => Response::Pong {
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            Request::Unlock { vault, key } => {
                // Decode the client-derived key; the passphrase never reaches here.
                let key_bytes = match hex::decode(&key)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                {
                    Some(k) => k,
                    None => {
                        return Response::Error {
                            message: "invalid key encoding".to_string(),
                        }
                    }
                };
                let dir = vault_dir(base, &vault);
                // Validate the key actually opens this vault before caching it.
                match Vault::open_with_key(&dir, VaultKey::from_bytes(key_bytes)) {
                    Ok(_) => {
                        let now = Instant::now();
                        let held = Held {
                            key: Zeroizing::new(key_bytes),
                            unlocked_at: now,
                            last_used: now,
                        };
                        lock_store(store).insert(vault, held);
                        Response::Unlocked
                    }
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            }
            Request::Lock { vault } => {
                let removed = lock_store(store).remove(&vault).is_some();
                Response::Locked {
                    count: usize::from(removed),
                }
            }
            Request::LockAll => {
                let mut s = lock_store(store);
                let count = s.len();
                s.clear(); // dropping each Held zeroizes its key
                Response::Locked { count }
            }
            Request::Status => {
                let now = Instant::now();
                let s = lock_store(store);
                let mut vaults: Vec<VaultStatus> = s
                    .iter()
                    .map(|(name, h)| {
                        let idle_used = now.duration_since(h.last_used).as_secs();
                        let age = now.duration_since(h.unlocked_at).as_secs();
                        VaultStatus {
                            name: name.clone(),
                            idle_remaining_secs: idle.saturating_sub(idle_used),
                            hard_remaining_secs: max.saturating_sub(age),
                        }
                    })
                    .collect();
                vaults.sort_by(|a, b| a.name.cmp(&b.name));
                Response::Status { vaults }
            }
            Request::Get { vault, secret } => {
                // Human path (`svault secret get`): no policy/judge gate (the
                // human holds the passphrase), but still audited so no daemon
                // read is unrecorded (N-5).
                let key_bytes = match cached_key(store, &vault) {
                    Some(k) => k,
                    None => return Response::NotUnlocked,
                };
                let dir = vault_dir(base, &vault);
                match Vault::open_with_key(&dir, VaultKey::from_bytes(key_bytes)) {
                    Ok(v) => match v.get_secret(&secret) {
                        // The original Zeroizing<String> wipes on drop; this transport
                        // copy and the serialized buffer are wiped after reply() (N-6).
                        Ok(Some(value)) => {
                            let _ = audit::record(
                                &dir,
                                &audit::Entry::now(
                                    "human",
                                    &secret,
                                    "-",
                                    "-",
                                    "allow",
                                    "human path",
                                    "",
                                )
                                .with_source("human")
                                .with_peer_uid(peer_uid),
                            );
                            Response::Secret {
                                value: value.to_string(),
                            }
                        }
                        Ok(None) => Response::NotFound,
                        Err(e) => Response::Error {
                            message: e.to_string(),
                        },
                    },
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            }
            Request::GetGated {
                vault,
                secret,
                caller,
                scope,
                reason,
            } => {
                let key_bytes = match cached_key(store, &vault) {
                    Some(k) => k,
                    None => return Response::NotUnlocked,
                };
                let dir = vault_dir(base, &vault);
                let v = match Vault::open_with_key(&dir, VaultKey::from_bytes(key_bytes)) {
                    Ok(v) => v,
                    Err(e) => {
                        return Response::Error {
                            message: e.to_string(),
                        }
                    }
                };
                // All policy comes from the decrypted, vault-key-authenticated
                // payload (#22) — classification, caller rules, judge overrides.
                let req = policy::Request {
                    vault: &v.meta.name,
                    vault_description: &v.meta.description,
                    vault_dir: &dir,
                    secret: &secret,
                    scope: &scope,
                    reason: &reason,
                    caller: &caller,
                };
                // Test override wins; otherwise resolve from the unlocked keyring.
                let resolved = if ctx.judge_override.is_some() {
                    None
                } else {
                    resolve_judge(&v.policy)
                };
                let rt = ctx.judge_override.as_ref().or(resolved.as_ref());
                let verdict = gate::authorize(&v.policy, &req, rt);
                let decision_str = if verdict.allowed() { "allow" } else { "deny" };
                // The full reason (judge score + rationale, mismatch, rate limit)
                // is recorded for the human; the caller only ever sees a generic
                // denial, so it can't learn what to change to pass.
                audit_gated(
                    &dir,
                    &caller,
                    &secret,
                    &scope,
                    &verdict.tier().to_string(),
                    decision_str,
                    &verdict.note,
                    &reason,
                    peer_uid,
                );
                if !verdict.allowed() {
                    return Response::Denied {
                        reason: gate::GENERIC_DENY.to_string(),
                    };
                }
                match v.get_secret(&secret) {
                    Ok(Some(value)) => Response::Granted {
                        value: value.to_string(),
                        tier: verdict.tier(),
                    },
                    Ok(None) => Response::NotFound,
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            }
            // Shutdown is acknowledged here; the connection handler sets the flag.
            Request::Shutdown => Response::Ok,
        }
    }

    /// Clone a cached key + bump `last_used` under the lock (minimal critical
    /// section), or `None` if the vault isn't unlocked.
    fn cached_key(store: &Store, vault: &str) -> Option<[u8; 32]> {
        let mut s = lock_store(store);
        s.get_mut(vault).map(|h| {
            h.last_used = Instant::now();
            *h.key
        })
    }

    /// Record a gated (agent-path) decision, stamped agent-source + peer UID.
    #[allow(clippy::too_many_arguments)]
    fn audit_gated(
        dir: &Path,
        caller: &str,
        secret: &str,
        scope: &str,
        tier: &str,
        decision: &str,
        rule: &str,
        reason: &str,
        peer_uid: Option<u32>,
    ) {
        let entry = audit::Entry::now(caller, secret, scope, tier, decision, rule, reason)
            .with_source("agent")
            .with_peer_uid(peer_uid);
        let _ = audit::record(dir, &entry);
    }

    fn reply(w: &mut UnixStream, resp: &Response) -> std::io::Result<()> {
        let mut s = serde_json::to_string(resp)
            .unwrap_or_else(|_| r#"{"status":"error","message":"encode failed"}"#.to_string());
        s.push('\n');
        let res = w.write_all(s.as_bytes()).and_then(|_| w.flush());
        // A Secret reply serializes the plaintext into this buffer — wipe it
        // before the allocation is freed rather than leaving it in the heap (N-6).
        s.zeroize();
        res
    }

    /// Serve one connection: read newline-delimited requests until EOF.
    fn serve_conn(
        stream: UnixStream,
        store: Store,
        ctx: Arc<ServerCtx>,
        peer_uid: Option<u32>,
        shutdown: Arc<AtomicBool>,
        sock: PathBuf,
    ) {
        let reader_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        // Bound how long a single request read may block so a stalled client
        // can't hold the handler (and a connection slot) open indefinitely.
        let _ = reader_stream.set_read_timeout(Some(CONN_READ_TIMEOUT));
        let mut writer = stream;
        let mut reader = BufReader::new(reader_stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break, // EOF or broken pipe
                Ok(_) => {}
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let req: Request = match serde_json::from_str(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    let _ = reply(
                        &mut writer,
                        &Response::Error {
                            message: format!("bad request: {e}"),
                        },
                    );
                    continue;
                }
            };
            let is_shutdown = matches!(req, Request::Shutdown);
            let mut resp = handle(&store, &ctx, peer_uid, req);
            let _ = reply(&mut writer, &resp);
            // Wipe the secret value held in the in-memory response now that it's
            // been written, so it doesn't linger in the freed allocation (N-6).
            match &mut resp {
                Response::Secret { value } | Response::Granted { value, .. } => value.zeroize(),
                _ => {}
            }
            if is_shutdown {
                shutdown.store(true, Ordering::SeqCst);
                // Wake the blocking accept loop so it notices the flag and exits.
                let _ = UnixStream::connect(&sock);
                break;
            }
        }
    }

    /// Background thread: every ~10s, evict keys past their idle / hard-max
    /// timers. `retain` drops the removed `Held`, zeroizing its key.
    fn spawn_ticker(store: Store, idle: u64, max: u64) {
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(10));
            let now = Instant::now();
            let mut s = lock_store(&store);
            s.retain(|_, h| {
                let idle_used = now.duration_since(h.last_used).as_secs();
                let age = now.duration_since(h.unlocked_at).as_secs();
                !is_expired(idle_used, age, idle, max)
            });
        });
    }

    /// Set by the SIGTERM/SIGINT handler; polled by the signal watcher thread.
    static SIGNAL_FLAG: AtomicBool = AtomicBool::new(false);

    /// Async-signal-safe handler: just flips an atomic (no allocation/I/O).
    extern "C" fn on_term_signal(_sig: libc::c_int) {
        SIGNAL_FLAG.store(true, Ordering::SeqCst);
    }

    /// Turn SIGTERM/SIGINT into a *graceful* shutdown so keys are zeroized and
    /// the socket/pid files are cleaned up, instead of an abrupt terminate (#17).
    /// A watcher thread flips the accept loop's `shutdown` flag and wakes it by
    /// connecting, reusing the same teardown as a `Shutdown` request.
    fn install_signal_watcher(shutdown: Arc<AtomicBool>, sock: PathBuf) {
        let handler = on_term_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // sigaction (POSIX, well-defined cross-Unix semantics) rather than the
        // legacy signal(), whose behaviour is unspecified on some variants (N-9).
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
            libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
        }
        std::thread::spawn(move || loop {
            if SIGNAL_FLAG.load(Ordering::SeqCst) {
                shutdown.store(true, Ordering::SeqCst);
                let _ = UnixStream::connect(&sock); // unblock accept()
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        });
    }

    /// The connecting peer's UID, or `None` if it can't be determined. Portable
    /// across the daemon's targets: `SO_PEERCRED` on Linux, `getpeereid` on
    /// macOS/BSD (std's `peer_cred` is still unstable). Used both for the
    /// peer-UID bond (#1) and to stamp the audit trail (N-1).
    fn peer_uid(stream: &UnixStream) -> Option<u32> {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        let peer_uid = {
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
                    &mut len,
                )
            };
            if rc != 0 {
                return None;
            }
            Some(cred.uid)
        };

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let peer_uid = {
            let mut uid: libc::uid_t = 0;
            let mut gid: libc::gid_t = 0;
            let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
            if rc != 0 {
                return None;
            }
            Some(uid)
        };

        peer_uid
    }

    /// The accept loop. Returns when a `Shutdown` request unblocks it.
    fn serve(listener: UnixListener, store: Store, ctx: Arc<ServerCtx>, max_conns: usize) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let sock = socket_path(&ctx.base);
        let me = unsafe { libc::geteuid() };
        install_signal_watcher(shutdown.clone(), sock.clone());
        for stream in listener.incoming() {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            let mut s = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Peer-UID bond: only serve connections from our own UID (#1). The
            // UID is also stamped into the audit trail (N-1).
            let puid = peer_uid(&s);
            if puid != Some(me) {
                continue; // drop — different UID or unknown
            }
            // Connection ceiling: refuse new work when too many handlers are
            // already live, instead of spawning unbounded threads.
            if active.load(Ordering::SeqCst) >= max_conns {
                let _ = reply(
                    &mut s,
                    &Response::Error {
                        message: "daemon busy: too many connections".to_string(),
                    },
                );
                continue; // drop s → closes the socket
            }
            active.fetch_add(1, Ordering::SeqCst);
            let (st, cx, sd, sk, ac) = (
                store.clone(),
                ctx.clone(),
                shutdown.clone(),
                sock.clone(),
                active.clone(),
            );
            std::thread::spawn(move || {
                let _guard = ConnGuard(ac); // decrements the live count on exit/panic
                serve_conn(s, st, cx, puid, sd, sk);
            });
        }
        // Lock everything (zeroize keys) and clean up our files.
        lock_store(&store).clear();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(pid_path(&ctx.base));
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    fn write_pid(base: &Path) -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(pid_path(base))?;
        writeln!(f, "{}", std::process::id())?;
        Ok(())
    }

    fn read_pid(base: &Path) -> Option<u32> {
        std::fs::read_to_string(pid_path(base))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// True if a process with this pid exists (kill(pid, 0) succeeds).
    fn pid_alive(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    fn socket_mode(sock: &Path) -> Option<u32> {
        std::fs::metadata(sock).ok().map(|m| m.mode() & 0o777)
    }

    /// Connect to the daemon socket, retrying briefly on transient failures.
    /// Under burst connect-churn the OS listener backlog can momentarily reject
    /// a connect (the daemon is alive, the accept queue is just full); a few
    /// short retries absorb that blip instead of surfacing a hard error to the
    /// caller. A genuinely-down daemon still fails fast (~all retries are cheap).
    fn connect_retry(sock: &Path) -> std::io::Result<UnixStream> {
        const ATTEMPTS: u32 = 4;
        let mut last_err = None;
        for attempt in 0..ATTEMPTS {
            match UnixStream::connect(sock) {
                Ok(s) => return Ok(s),
                Err(e) => {
                    last_err = Some(e);
                    if attempt + 1 < ATTEMPTS {
                        // 1ms, 2ms, 4ms — total worst case ~7ms.
                        std::thread::sleep(Duration::from_millis(1u64 << attempt));
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| std::io::Error::other("connect failed")))
    }

    /// Send one request to a running daemon and read its reply.
    pub fn send(base: &Path, req: &Request) -> Result<Response> {
        let mut stream = connect_retry(&socket_path(base)).context("connect to svault daemon")?;
        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        stream.write_all(line.as_bytes())?;
        stream.flush()?;
        let mut reader = BufReader::new(stream);
        let mut resp = String::new();
        reader.read_line(&mut resp)?;
        Ok(serde_json::from_str(resp.trim())?)
    }

    fn ping(base: &Path) -> bool {
        matches!(send(base, &Request::Ping), Ok(Response::Pong { .. }))
    }

    /// True when the socket exists and a daemon answers a ping.
    pub fn is_running(base: &Path) -> bool {
        socket_path(base).exists() && ping(base)
    }

    /// Foreground server loop (`svault daemon run`).
    pub fn run() -> Result<()> {
        let base = base_dir();
        crate::secfile::create_dir_owner_only(&base).context("create .svault directory")?;
        let sock = socket_path(&base);
        if sock.exists() {
            if ping(&base) {
                return Err(anyhow!("a daemon is already running on {}", sock.display()));
            }
            let _ = std::fs::remove_file(&sock); // stale socket from a crash
        }

        // Operational config lives in the encrypted keyring; read it if the
        // keyring is already unlocked, else use built-in defaults. (Changing
        // these takes effect on the next daemon start.) The judge itself is
        // resolved per-request, so it activates as soon as the keyring unlocks.
        let kr = crate::keyring::open_from_session();
        let (idle, max, max_conns, judge_on) = match &kr {
            Some(k) => (
                k.data.lock.idle_timeout_secs,
                k.data.lock.max_unlocked_secs,
                k.data.daemon.max_connections,
                k.data.judge_enabled,
            ),
            None => {
                let l = crate::config::LockConfig::default();
                let d = crate::config::DaemonConfig::default();
                (
                    l.idle_timeout_secs,
                    l.max_unlocked_secs,
                    d.max_connections,
                    false,
                )
            }
        };
        drop(kr);

        // Bind under a tight umask so the socket is born 0600 — no TOCTOU window
        // between bind and chmod where it's group/world-accessible (#16).
        let old_umask = unsafe { libc::umask(0o077) };
        let bind_result = UnixListener::bind(&sock);
        unsafe { libc::umask(old_umask) };
        let listener = bind_result.with_context(|| format!("bind {}", sock.display()))?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        write_pid(&base)?;

        let store: Store = Arc::new(Mutex::new(HashMap::new()));
        spawn_ticker(store.clone(), idle, max);

        eprintln!(
            "svault daemon listening on {} (idle {idle}s, hard-max {max}s, max-conns {max_conns}, judge {})",
            sock.display(),
            if judge_on { "on" } else { "off" }
        );
        let ctx = Arc::new(ServerCtx {
            base,
            idle,
            max,
            judge_override: None,
        });
        serve(listener, store, ctx, max_conns);
        Ok(())
    }

    /// Spawn `svault daemon run` detached. Returns a status message instead of
    /// printing, so callers like the TUI (which can't write to stdout) can show
    /// it in their own status line.
    pub fn start_quiet() -> Result<String> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let base = base_dir();
        crate::secfile::create_dir_owner_only(&base)?;
        if is_running(&base) {
            let pid = read_pid(&base)
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string());
            return Ok(format!("daemon already running (pid {pid})"));
        }
        let _ = std::fs::remove_file(socket_path(&base)); // clear any stale socket

        let exe = std::env::current_exe().context("locate svault binary")?;
        // Cap daemon.log growth (#17): rotate to .log.1 once it passes ~5 MB.
        let log_p = log_path(&base);
        if let Ok(meta) = std::fs::metadata(&log_p) {
            if meta.len() > 5 * 1024 * 1024 {
                let _ = std::fs::rename(&log_p, log_p.with_extension("log.1"));
            }
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_p)?;
        let log_err = log.try_clone()?;

        let mut cmd = Command::new(exe);
        cmd.arg("daemon")
            .arg("run")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        // Detach into its own session so closing the terminal won't SIGHUP it.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let child = cmd.spawn().context("spawn svault daemon")?;

        // Wait briefly for it to bind so we can report success or point at the log.
        for _ in 0..50 {
            if is_running(&base) {
                return Ok(format!("daemon started (pid {})", child.id()));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(anyhow!(
            "daemon did not come up within 5s — check {}",
            log_path(&base).display()
        ))
    }

    /// `svault daemon start`.
    pub fn start() -> Result<()> {
        println!("svault {}", start_quiet()?);
        Ok(())
    }

    /// Stop a running daemon. Returns a status message (see [`start_quiet`]).
    pub fn stop_quiet() -> Result<String> {
        let base = base_dir();
        let running = is_running(&base);
        let pid = read_pid(&base);
        if !running && pid.is_none() && !socket_path(&base).exists() {
            return Ok("daemon is not running".to_string());
        }
        if running {
            let _ = send(&base, &Request::Shutdown); // daemon zeroizes keys, removes files
            for _ in 0..40 {
                if !is_running(&base) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        // Fallback: signal the pid, then clean up any leftover files.
        if let Some(pid) = pid {
            if pid_alive(pid) {
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGTERM);
                }
            }
        }
        let _ = std::fs::remove_file(socket_path(&base));
        let _ = std::fs::remove_file(pid_path(&base));
        Ok("daemon stopped".to_string())
    }

    /// `svault daemon stop`.
    pub fn stop() -> Result<()> {
        println!("svault {}", stop_quiet()?);
        Ok(())
    }

    fn fmt_dur(secs: u64) -> String {
        let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
        if h > 0 {
            format!("{h}h{m:02}m")
        } else if m > 0 {
            format!("{m}m{s:02}s")
        } else {
            format!("{s}s")
        }
    }

    /// Show unlocked vaults + remaining timers (`svault daemon status`).
    pub fn status() -> Result<()> {
        let base = base_dir();
        if !is_running(&base) {
            println!("svault daemon is not running");
            return Ok(());
        }
        match send(&base, &Request::Status)? {
            Response::Status { vaults } if vaults.is_empty() => {
                println!("svault daemon running — no vaults unlocked");
            }
            Response::Status { vaults } => {
                println!("{:<24} {:<14} HARD LEFT", "VAULT", "IDLE LEFT");
                for v in vaults {
                    println!(
                        "{:<24} {:<14} {}",
                        v.name,
                        fmt_dur(v.idle_remaining_secs),
                        fmt_dur(v.hard_remaining_secs)
                    );
                }
            }
            other => println!("unexpected daemon response: {other:?}"),
        }
        Ok(())
    }

    fn check(problems: &mut u32, level: &str, label: &str, detail: &str) {
        if level != "ok" {
            *problems += 1;
        }
        println!("  [{level:>4}] {label:<18} {detail}");
    }

    /// Diagnose daemon health (`svault daemon doctor [--fix]`).
    pub fn doctor(fix: bool) -> Result<()> {
        let base = base_dir();
        let sock = socket_path(&base);
        let mut problems = 0u32;

        println!("svault daemon doctor");
        println!("  platform           unix (native daemon)");

        let kr = crate::keyring::open_from_session();
        let (idle_secs, max_secs, src) = match &kr {
            Some(k) => (
                k.data.lock.idle_timeout_secs,
                k.data.lock.max_unlocked_secs,
                "keyring",
            ),
            None => {
                let l = crate::config::LockConfig::default();
                (
                    l.idle_timeout_secs,
                    l.max_unlocked_secs,
                    "defaults (keyring locked)",
                )
            }
        };
        drop(kr);
        println!("  idle timeout       {idle_secs}s ({src})");
        println!("  hard max           {max_secs}s");

        let sock_exists = sock.exists();
        let responds = sock_exists && ping(&base);
        let pid = read_pid(&base);
        let pid_live = pid.map(pid_alive).unwrap_or(false);

        if responds {
            let pid_str = pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string());
            check(
                &mut problems,
                "ok",
                "daemon",
                &format!("running (pid {pid_str})"),
            );
            check(&mut problems, "ok", "socket", &sock.display().to_string());
            match socket_mode(&sock) {
                Some(0o600) => check(&mut problems, "ok", "socket perms", "0600"),
                Some(m) => check(
                    &mut problems,
                    "warn",
                    "socket perms",
                    &format!("{m:o} (expected 600)"),
                ),
                None => {}
            }
            if pid.is_none() {
                check(
                    &mut problems,
                    "warn",
                    "pid file",
                    "missing (daemon up anyway)",
                );
            }
        } else if sock_exists {
            // A socket file with no daemon answering — left by a crash.
            check(
                &mut problems,
                "err",
                "socket",
                "present but no daemon answers (stale)",
            );
            if fix {
                let _ = std::fs::remove_file(&sock);
                println!("         -> removed stale socket");
            } else {
                println!("         run 'svault daemon doctor --fix' to remove it");
            }
        } else {
            check(&mut problems, "ok", "daemon", "not running");
        }

        if let Some(pid) = pid {
            if !pid_live {
                check(
                    &mut problems,
                    "err",
                    "pid file",
                    &format!("{pid} is not alive (stale)"),
                );
                if fix {
                    let _ = std::fs::remove_file(pid_path(&base));
                    println!("         -> removed stale pid file");
                } else {
                    println!("         run 'svault daemon doctor --fix' to remove it");
                }
            }
        }

        if problems == 0 {
            println!("healthy");
            Ok(())
        } else if fix {
            println!("{problems} issue(s) found and cleaned up");
            Ok(())
        } else {
            println!("{problems} issue(s) found");
            std::process::exit(1);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::meta::{VaultMeta, VaultSettings};
        use crate::policy::VaultPolicyData;
        use crate::vault::Vault;
        use tempfile::TempDir;

        fn make_vault(base: &Path, name: &str, pass: &str) {
            let dir = vault_dir(base, name);
            let meta = VaultMeta::new(name.to_string(), "d".to_string(), VaultSettings::default());
            let v = Vault::init(&dir, pass, meta, VaultPolicyData::default()).unwrap();
            v.add_secret("API_KEY", "s3cr3t").unwrap();
        }

        /// Derive a vault's key the way the client now does (#3) and hex-encode
        /// it, for building `Unlock { key }` requests in tests.
        fn key_hex(base: &Path, name: &str, pass: &str) -> String {
            let v = Vault::open(&vault_dir(base, name), pass).unwrap();
            hex::encode(v.key().bytes())
        }

        /// Bind a daemon on a temp base and wait until it answers.
        /// Default connection ceiling for tests that don't care about the cap.
        const TEST_MAX_CONNS: usize = 64;

        fn start_test_daemon(base: PathBuf, idle: u64, max: u64) {
            start_test_daemon_capped(base, idle, max, TEST_MAX_CONNS);
        }

        fn start_test_daemon_capped(base: PathBuf, idle: u64, max: u64, max_conns: usize) {
            start_test_daemon_judged(base, idle, max, max_conns, None);
        }

        fn start_test_daemon_judged(
            base: PathBuf,
            idle: u64,
            max: u64,
            max_conns: usize,
            judge: Option<crate::judge::JudgeRuntime>,
        ) {
            let sock = socket_path(&base);
            let listener = UnixListener::bind(&sock).unwrap();
            let store: Store = Arc::new(Mutex::new(HashMap::new()));
            let ctx = Arc::new(ServerCtx {
                base,
                idle,
                max,
                judge_override: judge,
            });
            std::thread::spawn(move || serve(listener, store, ctx, max_conns));
        }

        fn wait_up(base: &Path) {
            for _ in 0..100 {
                if ping(base) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("daemon never came up");
        }

        // ── Gated (agent path) test scaffolding ────────────────────────────
        use crate::policy::Tier;
        const PASS: &str = "Str0ng!Pass#99";

        /// A vault with one classified secret, so the daemon gate has a tier to
        /// enforce. (No policy file exists in tests → caller auth via allow_agent.)
        fn make_classified_vault(base: &Path, name: &str, secret: &str, scope: &str, tier: Tier) {
            let dir = vault_dir(base, name);
            let meta = VaultMeta::new(name.to_string(), "d".to_string(), VaultSettings::default());
            let mut policy = VaultPolicyData::default();
            policy.secrets.insert(
                secret.to_string(),
                crate::policy::SecretRule {
                    scope: scope.to_string(),
                    tier,
                    require_reason: false,
                    description: String::new(),
                },
            );
            let v = Vault::init(&dir, PASS, meta, policy).unwrap();
            v.add_secret(secret, "s3cr3t").unwrap();
        }

        struct FakeJudge(std::result::Result<String, String>);
        impl crate::judge::JudgeTransport for FakeJudge {
            fn chat(&self, _m: &str, _s: &str, _u: &str) -> anyhow::Result<String> {
                self.0.clone().map_err(|e| anyhow::anyhow!(e))
            }
        }

        fn judge_rt(reply: std::result::Result<String, String>) -> crate::judge::JudgeRuntime {
            crate::judge::JudgeRuntime {
                model: "fake".into(),
                allow_threshold: 60,
                high_threshold: 80,
                criteria: String::new(),
                transport: Box::new(FakeJudge(reply)),
            }
        }

        fn unlock(base: &Path, name: &str) {
            assert!(matches!(
                send(
                    base,
                    &Request::Unlock {
                        vault: name.into(),
                        key: key_hex(base, name, PASS),
                    },
                )
                .unwrap(),
                Response::Unlocked
            ));
        }

        fn gated(base: &Path, name: &str, secret: &str, scope: &str, reason: &str) -> Response {
            send(
                base,
                &Request::GetGated {
                    vault: name.into(),
                    secret: secret.into(),
                    caller: "claude".into(),
                    scope: scope.into(),
                    reason: reason.into(),
                },
            )
            .unwrap()
        }

        const PLAUSIBLE: &str = "run the nightly database migration job";

        #[test]
        fn gated_medium_allowed_by_judge_and_audited() {
            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_classified_vault(&base, "v", "API_KEY", "api", Tier::Medium);
            start_test_daemon_judged(
                base.clone(),
                900,
                28800,
                TEST_MAX_CONNS,
                Some(judge_rt(Ok(
                    r#"{"decision":"allow","score":90,"reason":"plausible"}"#.into(),
                ))),
            );
            wait_up(&base);
            unlock(&base, "v");
            match gated(&base, "v", "API_KEY", "api", PLAUSIBLE) {
                Response::Granted { value, tier } => {
                    assert_eq!(value, "s3cr3t");
                    assert_eq!(tier, Tier::Medium);
                }
                other => panic!("expected Granted, got {other:?}"),
            }
            // The decision is audited with the agent source and a peer UID (N-1/N-5).
            let entries = crate::audit::all(&vault_dir(&base, "v")).unwrap();
            assert!(entries
                .iter()
                .any(|e| e.source == "agent" && e.decision == "allow" && e.peer_uid.is_some()));
        }

        #[test]
        fn gated_medium_denied_by_judge() {
            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_classified_vault(&base, "v", "API_KEY", "api", Tier::Medium);
            start_test_daemon_judged(
                base.clone(),
                900,
                28800,
                TEST_MAX_CONNS,
                Some(judge_rt(Ok(
                    r#"{"decision":"deny","score":5,"reason":"vague"}"#.into(),
                ))),
            );
            wait_up(&base);
            unlock(&base, "v");
            assert!(matches!(
                gated(&base, "v", "API_KEY", "api", PLAUSIBLE),
                Response::Denied { .. }
            ));
        }

        #[test]
        fn gated_high_fails_closed_when_judge_unavailable() {
            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_classified_vault(&base, "v", "DB_PW", "database", Tier::High);
            start_test_daemon_judged(
                base.clone(),
                900,
                28800,
                TEST_MAX_CONNS,
                Some(judge_rt(Err("network down".into()))),
            );
            wait_up(&base);
            unlock(&base, "v");
            assert!(matches!(
                gated(&base, "v", "DB_PW", "database", PLAUSIBLE),
                Response::Denied { .. }
            ));
        }

        #[test]
        fn gated_high_is_human_only_without_judge() {
            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_classified_vault(&base, "v", "DB_PW", "database", Tier::High);
            start_test_daemon(base.clone(), 900, 28800); // no judge
            wait_up(&base);
            unlock(&base, "v");
            assert!(matches!(
                gated(&base, "v", "DB_PW", "database", PLAUSIBLE),
                Response::Denied { .. }
            ));
        }

        #[test]
        fn gated_medium_allowed_without_judge() {
            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_classified_vault(&base, "v", "API_KEY", "api", Tier::Medium);
            start_test_daemon(base.clone(), 900, 28800); // no judge → allow + flag
            wait_up(&base);
            unlock(&base, "v");
            assert!(matches!(
                gated(&base, "v", "API_KEY", "api", PLAUSIBLE),
                Response::Granted { .. }
            ));
        }

        #[test]
        fn gated_short_reason_is_denied() {
            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_classified_vault(&base, "v", "API_KEY", "api", Tier::Medium);
            start_test_daemon(base.clone(), 900, 28800);
            wait_up(&base);
            unlock(&base, "v");
            assert!(matches!(
                gated(&base, "v", "API_KEY", "api", "fix"),
                Response::Denied { .. }
            ));
        }

        #[test]
        fn unlock_get_lock_shutdown() {
            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_vault(&base, "v", "Str0ng!Pass#99");
            start_test_daemon(base.clone(), 900, 28800);
            wait_up(&base);

            // Locked vault → NotUnlocked.
            assert!(matches!(
                send(
                    &base,
                    &Request::Get {
                        vault: "v".into(),
                        secret: "API_KEY".into()
                    }
                )
                .unwrap(),
                Response::NotUnlocked
            ));

            // Wrong key → Error (a bogus key doesn't open the vault).
            assert!(matches!(
                send(
                    &base,
                    &Request::Unlock {
                        vault: "v".into(),
                        key: hex::encode([0u8; 32])
                    }
                )
                .unwrap(),
                Response::Error { .. }
            ));

            // Correct (client-derived) key → Unlocked, then Get returns the value.
            assert!(matches!(
                send(
                    &base,
                    &Request::Unlock {
                        vault: "v".into(),
                        key: key_hex(&base, "v", "Str0ng!Pass#99")
                    }
                )
                .unwrap(),
                Response::Unlocked
            ));
            match send(
                &base,
                &Request::Get {
                    vault: "v".into(),
                    secret: "API_KEY".into(),
                },
            )
            .unwrap()
            {
                Response::Secret { value } => assert_eq!(value, "s3cr3t"),
                other => panic!("expected secret, got {other:?}"),
            }

            // Unknown secret → NotFound.
            assert!(matches!(
                send(
                    &base,
                    &Request::Get {
                        vault: "v".into(),
                        secret: "NOPE".into()
                    }
                )
                .unwrap(),
                Response::NotFound
            ));

            // Lock → subsequent Get is denied.
            assert!(matches!(
                send(&base, &Request::Lock { vault: "v".into() }).unwrap(),
                Response::Locked { count: 1 }
            ));
            assert!(matches!(
                send(
                    &base,
                    &Request::Get {
                        vault: "v".into(),
                        secret: "API_KEY".into()
                    }
                )
                .unwrap(),
                Response::NotUnlocked
            ));

            // Shutdown stops the daemon and removes the socket.
            let _ = send(&base, &Request::Shutdown);
            for _ in 0..100 {
                if !is_running(&base) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(!is_running(&base));
        }

        #[test]
        fn connections_do_not_leak_slots() {
            // Each connection must free its slot when its handler ends (ConnGuard),
            // so the daemon keeps answering far past the ceiling in *total*
            // connects. If the counter leaked, it would wedge after TEST_MAX_CONNS.
            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_vault(&base, "v", "Str0ng!Pass#99");
            start_test_daemon(base.clone(), 900, 28800);
            wait_up(&base);
            for _ in 0..(TEST_MAX_CONNS * 3) {
                assert!(matches!(
                    send(&base, &Request::Ping).unwrap(),
                    Response::Pong { .. }
                ));
            }
            let _ = send(&base, &Request::Shutdown);
        }

        #[test]
        fn poisoned_store_still_locks() {
            // A connection handler that panics while holding the lock poisons
            // the mutex. lock_store must still hand back the guard so the daemon
            // (and every key it holds) survives instead of aborting on the next
            // lock().unwrap().
            let store: Store = Arc::new(Mutex::new(HashMap::new()));
            let s2 = store.clone();
            let _ = std::thread::spawn(move || {
                let _g = s2.lock().unwrap();
                panic!("poison the mutex");
            })
            .join();

            // Confirm the mutex really is poisoned (bare lock would propagate it).
            assert!(store.lock().is_err());

            // lock_store recovers the guard and the store stays usable.
            let mut g = lock_store(&store);
            g.insert(
                "v".to_string(),
                Held {
                    key: Zeroizing::new([7u8; 32]),
                    unlocked_at: Instant::now(),
                    last_used: Instant::now(),
                },
            );
            assert_eq!(g.len(), 1);
        }

        #[test]
        fn concurrent_gets_all_succeed() {
            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_vault(&base, "v", "Str0ng!Pass#99");
            start_test_daemon(base.clone(), 900, 28800);
            wait_up(&base);
            send(
                &base,
                &Request::Unlock {
                    vault: "v".into(),
                    key: key_hex(&base, "v", "Str0ng!Pass#99"),
                },
            )
            .unwrap();

            // 16 threads x 25 reads each, all on one shared in-memory key.
            let mut handles = Vec::new();
            for _ in 0..16 {
                let b = base.clone();
                handles.push(std::thread::spawn(move || {
                    for _ in 0..25 {
                        match send(
                            &b,
                            &Request::Get {
                                vault: "v".into(),
                                secret: "API_KEY".into(),
                            },
                        )
                        .unwrap()
                        {
                            Response::Secret { value } => assert_eq!(value, "s3cr3t"),
                            other => panic!("expected secret, got {other:?}"),
                        }
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
            let _ = send(&base, &Request::Shutdown);
        }

        /// Heavy concurrency / pressure simulation. Ignored by default (and in
        /// CI) — it's a manual benchmark, not a correctness gate. It drives the
        /// real `serve`/`handle` path (one thread per connection, the shared
        /// `Arc<Mutex>` key store, AES-256-GCM decrypt on every `Get`) under
        /// sustained parallel load, then floods connections past the ceiling.
        /// It records latency percentiles, throughput, and refusal counts to a
        /// log file and prints a summary.
        ///
        /// Run it (release build strongly recommended):
        ///   cargo test --release daemon_stress_simulation -- --ignored --nocapture
        /// Tunables (env):
        ///   SVAULT_STRESS_THREADS   parallel reader threads        (default 64)
        ///   SVAULT_STRESS_READS     Get requests per thread        (default 2000)
        ///   SVAULT_STRESS_FLOOD     idle connections in the flood  (default 256)
        ///   SVAULT_STRESS_LOG       report path  (default target/stress-report.log)
        #[test]
        #[ignore = "manual pressure benchmark; run with --ignored --nocapture"]
        fn daemon_stress_simulation() {
            use std::io::Write as _;
            use std::os::unix::net::UnixStream;
            use std::sync::atomic::{AtomicU64, Ordering};

            fn env_usize(key: &str, default: usize) -> usize {
                std::env::var(key)
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(default)
            }

            let threads = env_usize("SVAULT_STRESS_THREADS", 64);
            let reads = env_usize("SVAULT_STRESS_READS", 2000);
            let flood = env_usize("SVAULT_STRESS_FLOOD", 256);
            // Default ceiling matches the shipped config default so the run
            // reflects real behavior; override to study the cap's effect.
            let max_conns = env_usize("SVAULT_STRESS_MAXCONN", 512);
            let log_path = std::env::var("SVAULT_STRESS_LOG")
                .unwrap_or_else(|_| "target/stress-report.log".to_string());

            let tmp = TempDir::new().unwrap();
            let base = tmp.path().to_path_buf();
            make_vault(&base, "v", "Str0ng!Pass#99");
            start_test_daemon_capped(base.clone(), 900, 28800, max_conns);
            wait_up(&base);
            send(
                &base,
                &Request::Unlock {
                    vault: "v".into(),
                    key: key_hex(&base, "v", "Str0ng!Pass#99"),
                },
            )
            .unwrap();

            // ── Phase 1: sustained concurrent reads ──────────────────────────
            // Three outcomes, kept distinct:
            //   correct   — Get returned the right value
            //   refused   — daemon answered "busy" (backpressure at the ceiling);
            //               acceptable, the real client falls back to a prompt
            //   conn_err  — couldn't even connect (OS listener-backlog drop under
            //               connect churn); a capacity symptom, not a logic bug
            //   wrong     — connected, got a response, but it was wrong
            //               (wrong value / NotUnlocked / NotFound). A real bug —
            //               must be zero no matter how hard we push.
            let refused = Arc::new(AtomicU64::new(0));
            let conn_err = Arc::new(AtomicU64::new(0));
            let wrong = Arc::new(AtomicU64::new(0));
            let total_ops = threads * reads;
            let started = Instant::now();
            let mut handles = Vec::new();
            for _ in 0..threads {
                let b = base.clone();
                let refused = refused.clone();
                let conn_err = conn_err.clone();
                let wrong = wrong.clone();
                handles.push(std::thread::spawn(move || {
                    // Per-op latencies in microseconds, collected per thread then merged.
                    let mut lat = Vec::with_capacity(reads);
                    for _ in 0..reads {
                        let t0 = Instant::now();
                        let resp = send(
                            &b,
                            &Request::Get {
                                vault: "v".into(),
                                secret: "API_KEY".into(),
                            },
                        );
                        let us = t0.elapsed().as_micros() as u64;
                        match resp {
                            Ok(Response::Secret { value }) if value == "s3cr3t" => lat.push(us),
                            Ok(Response::Error { ref message })
                                if message.contains("too many connections") =>
                            {
                                refused.fetch_add(1, Ordering::Relaxed);
                            }
                            // Transport failure — never reached the daemon
                            // (connect refused / backlog drop). Capacity symptom.
                            Err(_) => {
                                conn_err.fetch_add(1, Ordering::Relaxed);
                            }
                            // Connected and got a response, but it was wrong.
                            _ => {
                                wrong.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    lat
                }));
            }
            let mut all_lat: Vec<u64> = Vec::with_capacity(total_ops);
            for h in handles {
                all_lat.extend(h.join().unwrap());
            }
            let wall = started.elapsed();
            let refused_count = refused.load(Ordering::Relaxed);
            let conn_err_count = conn_err.load(Ordering::Relaxed);
            let wrong_count = wrong.load(Ordering::Relaxed);

            all_lat.sort_unstable();
            let pct = |p: f64| -> u64 {
                if all_lat.is_empty() {
                    return 0;
                }
                let idx = ((all_lat.len() as f64 - 1.0) * p).round() as usize;
                all_lat[idx]
            };
            let mean = if all_lat.is_empty() {
                0
            } else {
                all_lat.iter().sum::<u64>() / all_lat.len() as u64
            };
            let ops_sec = all_lat.len() as f64 / wall.as_secs_f64();

            // ── Phase 2: connection flood (exercise the ceiling, #8) ─────────
            // Open many connections that connect but never send, holding handler
            // slots, then probe. We report how many probes were refused with the
            // "busy" error vs answered; the daemon must stay alive throughout.
            let mut idle_conns = Vec::new();
            for _ in 0..flood {
                if let Ok(s) = UnixStream::connect(socket_path(&base)) {
                    idle_conns.push(s);
                }
            }
            std::thread::sleep(Duration::from_millis(200)); // let handlers register
            let mut refused = 0u32;
            let mut answered = 0u32;
            for _ in 0..32 {
                match send(&base, &Request::Ping) {
                    Ok(Response::Pong { .. }) => answered += 1,
                    Ok(Response::Error { .. }) => refused += 1,
                    _ => refused += 1,
                }
            }
            drop(idle_conns); // close them → handlers exit → slots free
            std::thread::sleep(Duration::from_millis(300));
            let recovered = matches!(send(&base, &Request::Ping), Ok(Response::Pong { .. }));

            // ── Report ───────────────────────────────────────────────────────
            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let report = format!(
                "\
=== Svault daemon stress simulation ===
when                 {ts}
build                {} (release={})
host threads avail   {}
--- phase 1: sustained concurrent reads ---
reader threads       {threads}
reads per thread     {reads}
total Get ops        {total_ops}
correct              {}
refused (busy)       {refused_count}
conn err (backlog)   {conn_err_count}
wrong (real bug)     {wrong_count}
wall time            {:.3}s
throughput (correct) {ops_sec:.0} ops/sec
latency min          {} us
latency mean         {mean} us
latency p50          {} us
latency p90          {} us
latency p99          {} us
latency max          {} us
--- phase 2: connection flood (ceiling = {max_conns}) ---
idle connections     {flood}
probes answered      {answered}
probes refused busy  {refused}
recovered after drain {recovered}
",
                env!("CARGO_PKG_VERSION"),
                cfg!(not(debug_assertions)),
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(0),
                all_lat.len(),
                wall.as_secs_f64(),
                all_lat.first().copied().unwrap_or(0),
                pct(0.50),
                pct(0.90),
                pct(0.99),
                all_lat.last().copied().unwrap_or(0),
            );

            print!("{report}");
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                let _ = writeln!(f, "{report}");
                println!("(report appended to {log_path})");
            }

            let _ = send(&base, &Request::Shutdown);

            // Correctness gates that still hold even under heavy load. Busy
            // refusals are acceptable backpressure; a wrong/dropped value or a
            // transport-level failure on an *accepted* request would be a bug.
            assert_eq!(
                wrong_count, 0,
                "every accepted Get must return the correct value (refusals/connect errors excluded)"
            );
            assert!(recovered, "daemon must recover after the connection flood");
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use anyhow::Result;
    use std::path::{Path, PathBuf};

    pub fn base_dir() -> PathBuf {
        PathBuf::from(crate::vault::SVAULT_DIR)
    }
    pub fn is_running(_base: &Path) -> bool {
        false
    }

    const UNIX_ONLY: &str = "daemon is Unix-only — using the file session instead.";

    fn unsupported() -> Result<()> {
        println!("svault {UNIX_ONLY}");
        Ok(())
    }
    pub fn run() -> Result<()> {
        unsupported()
    }
    pub fn start() -> Result<()> {
        unsupported()
    }
    pub fn stop() -> Result<()> {
        unsupported()
    }
    pub fn start_quiet() -> Result<String> {
        Ok(UNIX_ONLY.to_string())
    }
    pub fn stop_quiet() -> Result<String> {
        Ok(UNIX_ONLY.to_string())
    }
    pub fn status() -> Result<()> {
        unsupported()
    }
    pub fn doctor(_fix: bool) -> Result<()> {
        unsupported()
    }
}

#[cfg(unix)]
pub use imp::{
    base_dir, doctor, is_running, run, send, start, start_quiet, status, stop, stop_quiet,
};
#[cfg(not(unix))]
pub use imp::{base_dir, doctor, is_running, run, start, start_quiet, status, stop, stop_quiet};

#[cfg(test)]
mod proto_tests {
    use super::*;

    #[test]
    fn request_json_roundtrip() {
        let reqs = vec![
            Request::Ping,
            Request::Status,
            Request::Unlock {
                vault: "v".into(),
                key: "deadbeef".into(),
            },
            Request::Lock { vault: "v".into() },
            Request::LockAll,
            Request::Get {
                vault: "v".into(),
                secret: "s".into(),
            },
            Request::Shutdown,
        ];
        for r in reqs {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), r);
        }
    }

    #[test]
    fn response_json_roundtrip() {
        let resps = vec![
            Response::Pong {
                version: "0.0.0".into(),
            },
            Response::Ok,
            Response::Unlocked,
            Response::Locked { count: 3 },
            Response::Status {
                vaults: vec![VaultStatus {
                    name: "v".into(),
                    idle_remaining_secs: 10,
                    hard_remaining_secs: 20,
                }],
            },
            Response::Secret { value: "x".into() },
            Response::NotUnlocked,
            Response::NotFound,
            Response::Error {
                message: "e".into(),
            },
        ];
        for r in resps {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), r);
        }
    }

    #[test]
    fn idle_timeout_expires() {
        // idle 901s past a 900s idle timeout, well within the 8h hard cap.
        assert!(is_expired(901, 901, 900, 28800));
    }

    #[test]
    fn hard_max_expires_even_when_active() {
        // Just used (idle 0) but unlocked 8h+1s ago → hard cap fires.
        assert!(is_expired(0, 28801, 900, 28800));
    }

    #[test]
    fn active_within_limits_stays() {
        assert!(!is_expired(60, 600, 900, 28800));
    }
}
