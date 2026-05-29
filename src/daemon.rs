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
    /// Validate the passphrase and cache the derived key in memory.
    Unlock { vault: String, passphrase: String },
    /// Drop one vault's key.
    Lock { vault: String },
    /// Drop every cached key.
    LockAll,
    /// Read one secret value from an unlocked vault.
    Get { vault: String, secret: String },
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
    use crate::config::SvaultConfig;
    use crate::crypto::VaultKey;
    use crate::vault::{Vault, SVAULT_DIR};
    use anyhow::{anyhow, Context, Result};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

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

    // ── Request handling ──────────────────────────────────────────────────

    fn handle(store: &Store, base: &Path, idle: u64, max: u64, req: Request) -> Response {
        match req {
            Request::Ping => Response::Pong {
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            Request::Unlock { vault, passphrase } => {
                let dir = vault_dir(base, &vault);
                match Vault::open(&dir, &passphrase) {
                    Ok(v) => {
                        let now = Instant::now();
                        let held = Held {
                            key: Zeroizing::new(*v.key().bytes()),
                            unlocked_at: now,
                            last_used: now,
                        };
                        store.lock().unwrap().insert(vault, held);
                        Response::Unlocked
                    }
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            }
            Request::Lock { vault } => {
                let removed = store.lock().unwrap().remove(&vault).is_some();
                Response::Locked {
                    count: usize::from(removed),
                }
            }
            Request::LockAll => {
                let mut s = store.lock().unwrap();
                let count = s.len();
                s.clear(); // dropping each Held zeroizes its key
                Response::Locked { count }
            }
            Request::Status => {
                let now = Instant::now();
                let s = store.lock().unwrap();
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
                // Minimal critical section: clone the key + bump last_used under
                // the lock, then open + decrypt OUTSIDE it so concurrent Gets
                // don't serialize on the mutex.
                let key_bytes = {
                    let mut s = store.lock().unwrap();
                    match s.get_mut(&vault) {
                        Some(h) => {
                            h.last_used = Instant::now();
                            *h.key
                        }
                        None => return Response::NotUnlocked,
                    }
                };
                let dir = vault_dir(base, &vault);
                match Vault::open_with_key(&dir, VaultKey::from_bytes(key_bytes)) {
                    Ok(v) => match v.get_secret(&secret) {
                        Ok(Some(value)) => Response::Secret { value },
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
            // Shutdown is acknowledged here; the connection handler sets the flag.
            Request::Shutdown => Response::Ok,
        }
    }

    fn reply(w: &mut UnixStream, resp: &Response) -> std::io::Result<()> {
        let mut s = serde_json::to_string(resp)
            .unwrap_or_else(|_| r#"{"status":"error","message":"encode failed"}"#.to_string());
        s.push('\n');
        w.write_all(s.as_bytes())?;
        w.flush()
    }

    /// Serve one connection: read newline-delimited requests until EOF.
    #[allow(clippy::too_many_arguments)]
    fn serve_conn(
        stream: UnixStream,
        store: Store,
        base: PathBuf,
        idle: u64,
        max: u64,
        shutdown: Arc<AtomicBool>,
        sock: PathBuf,
    ) {
        let reader_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
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
            let resp = handle(&store, &base, idle, max, req);
            let _ = reply(&mut writer, &resp);
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
            let mut s = store.lock().unwrap();
            s.retain(|_, h| {
                let idle_used = now.duration_since(h.last_used).as_secs();
                let age = now.duration_since(h.unlocked_at).as_secs();
                !is_expired(idle_used, age, idle, max)
            });
        });
    }

    /// The accept loop. Returns when a `Shutdown` request unblocks it.
    fn serve(listener: UnixListener, store: Store, base: PathBuf, idle: u64, max: u64) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let sock = socket_path(&base);
        for stream in listener.incoming() {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            let s = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (st, bs, sd, sk) = (store.clone(), base.clone(), shutdown.clone(), sock.clone());
            std::thread::spawn(move || serve_conn(s, st, bs, idle, max, sd, sk));
        }
        // Lock everything (zeroize keys) and clean up our files.
        store.lock().unwrap().clear();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(pid_path(&base));
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

    /// Send one request to a running daemon and read its reply.
    pub fn send(base: &Path, req: &Request) -> Result<Response> {
        let mut stream =
            UnixStream::connect(socket_path(base)).context("connect to svault daemon")?;
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
        std::fs::create_dir_all(&base).context("create .svault directory")?;
        let sock = socket_path(&base);
        if sock.exists() {
            if ping(&base) {
                return Err(anyhow!("a daemon is already running on {}", sock.display()));
            }
            let _ = std::fs::remove_file(&sock); // stale socket from a crash
        }

        let cfg = SvaultConfig::load().lock;
        let (idle, max) = (cfg.idle_timeout_secs, cfg.max_unlocked_secs);

        let listener =
            UnixListener::bind(&sock).with_context(|| format!("bind {}", sock.display()))?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        write_pid(&base)?;

        let store: Store = Arc::new(Mutex::new(HashMap::new()));
        spawn_ticker(store.clone(), idle, max);

        eprintln!(
            "svault daemon listening on {} (idle {idle}s, hard-max {max}s)",
            sock.display()
        );
        serve(listener, store, base, idle, max);
        Ok(())
    }

    /// Spawn `svault daemon run` detached. Returns a status message instead of
    /// printing, so callers like the TUI (which can't write to stdout) can show
    /// it in their own status line.
    pub fn start_quiet() -> Result<String> {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let base = base_dir();
        std::fs::create_dir_all(&base)?;
        if is_running(&base) {
            let pid = read_pid(&base)
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string());
            return Ok(format!("daemon already running (pid {pid})"));
        }
        let _ = std::fs::remove_file(socket_path(&base)); // clear any stale socket

        let exe = std::env::current_exe().context("locate svault binary")?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path(&base))?;
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

        let cfg = SvaultConfig::load();
        let src = if crate::config::config_path().exists() {
            ".svault/config.yaml"
        } else {
            "defaults"
        };
        println!(
            "  idle timeout       {}s ({src})",
            cfg.lock.idle_timeout_secs
        );
        println!("  hard max           {}s", cfg.lock.max_unlocked_secs);

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
        use crate::meta::{AccessConfig, VaultMeta, VaultSettings};
        use crate::vault::Vault;
        use tempfile::TempDir;

        fn make_vault(base: &Path, name: &str, pass: &str) {
            let dir = vault_dir(base, name);
            let meta = VaultMeta::new(
                name.to_string(),
                "d".to_string(),
                AccessConfig::default(),
                VaultSettings::default(),
            );
            let v = Vault::init(&dir, pass, meta).unwrap();
            v.add_secret("API_KEY", "s3cr3t").unwrap();
        }

        /// Bind a daemon on a temp base and wait until it answers.
        fn start_test_daemon(base: PathBuf, idle: u64, max: u64) {
            let sock = socket_path(&base);
            let listener = UnixListener::bind(&sock).unwrap();
            let store: Store = Arc::new(Mutex::new(HashMap::new()));
            std::thread::spawn(move || serve(listener, store, base, idle, max));
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

            // Wrong passphrase → Error.
            assert!(matches!(
                send(
                    &base,
                    &Request::Unlock {
                        vault: "v".into(),
                        passphrase: "wrong".into()
                    }
                )
                .unwrap(),
                Response::Error { .. }
            ));

            // Correct passphrase → Unlocked, then Get returns the value.
            assert!(matches!(
                send(
                    &base,
                    &Request::Unlock {
                        vault: "v".into(),
                        passphrase: "Str0ng!Pass#99".into()
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
                    passphrase: "Str0ng!Pass#99".into(),
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
                passphrase: "p".into(),
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
