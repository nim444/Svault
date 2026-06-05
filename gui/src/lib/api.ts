// Typed bridge to the Rust backend. Every Svault operation goes through a Tauri
// command; this module keeps the command names and payload types in one place so
// screens import typed functions rather than raw `invoke` strings.

import { invoke } from "@tauri-apps/api/core";

export interface AppInfo {
  version: string;
  master_exists: boolean;
  recovery_exists: boolean;
  yubikey_enrolled: boolean;
  store_path: string;
}

export interface SessionStatus {
  master_exists: boolean;
  master_unlocked: boolean;
  daemon_up: boolean;
  yubikey_enrolled: boolean;
  unlocked_vaults: string[];
  reauth_deadline: number | null;
  next_autolock_secs: number | null;
}

export interface UnlockResult {
  unlocked: number;
  already: number;
  keyring_unlocked: boolean;
  vaults: string[];
  reauth_deadline: number | null;
}

export interface InitResult {
  recovery_code: string;
  reauth_deadline: number;
}

export const appInfo = () => invoke<AppInfo>("app_info");

// ── Session (screen 01) ────────────────────────────────────────────────────
export const sessionStatus = () => invoke<SessionStatus>("session_status");
export const unlock = (passphrase: string) =>
  invoke<UnlockResult>("unlock", { passphrase });
export const unlockYubikey = (pin: string | null) =>
  invoke<UnlockResult>("unlock_yubikey", { pin });
export const yubikeyPresent = () => invoke<boolean>("yubikey_present");
export const lockAll = () => invoke<number>("lock_all");

// ── Onboarding (screen 02) ─────────────────────────────────────────────────
export const initMaster = (passphrase: string) =>
  invoke<InitResult>("init_master", { passphrase });
export const enrollYubikey = (pin: string | null) =>
  invoke<void>("enroll_yubikey", { pin });
export const removeYubikey = () => invoke<void>("remove_yubikey");

// ── Vaults (screens 03–04) ─────────────────────────────────────────────────
export interface VaultSummary {
  leaf: string;
  name: string;
  description: string;
  storage: string;
  created_at: string;
  unlocked: boolean;
  secret_count: number;
  default_tier: string;
  allow_agent: string;
  judge_enabled: boolean;
  assigned_judge: string | null;
  sealed_count: number;
  last_activity: number | null;
}

export interface VaultForm {
  name: string;
  description: string;
  allow_agent_mode: "none" | "list" | "all";
  allow_agent_list: string[];
  rate_limit: string;
  autolock: boolean;
  autolock_timer: string;
  login_method: "passphrase" | "yubikey";
  default_tier: "low" | "medium" | "high";
  judge_enabled: boolean;
  assigned_judge: string | null;
}

export type VaultFormData = VaultForm & { leaf: string };

export const listVaults = () => invoke<VaultSummary[]>("list_vaults");
export const createVault = (form: VaultForm) =>
  invoke<{ recovery_code: string }>("create_vault", { form });
export const vaultSettings = (leaf: string) =>
  invoke<VaultFormData>("vault_settings", { leafId: leaf });
export const saveSettings = (leaf: string, form: VaultForm) =>
  invoke<void>("save_settings", { leafId: leaf, form });
export const unlockVault = (leaf: string) =>
  invoke<void>("unlock_vault", { leafId: leaf });
export const lockVault = (leaf: string) =>
  invoke<void>("lock_vault", { leafId: leaf });
export const deleteVault = (leaf: string) =>
  invoke<void>("delete_vault", { leafId: leaf });

// ── Secrets (screen 05) ────────────────────────────────────────────────────
export interface SecretSummary {
  name: string;
  scope: string;
  tier: string;
  require_reason: boolean;
  description: string;
  callers: string[];
  windows: string[];
  sealed: boolean;
  last_read: number | null;
}

export interface SecretForm {
  name: string;
  value: string | null;
  scope: string;
  tier: "low" | "medium" | "high";
  require_reason: boolean;
  description: string;
  windows: string[];
  require_callers: string[];
}

export const listSecrets = (leaf: string) =>
  invoke<SecretSummary[]>("list_secrets", { leafId: leaf });
export const addSecret = (leaf: string, form: SecretForm) =>
  invoke<void>("add_secret", { leafId: leaf, form });
export const editSecret = (leaf: string, form: SecretForm) =>
  invoke<void>("edit_secret", { leafId: leaf, form });
export const removeSecret = (leaf: string, name: string) =>
  invoke<void>("remove_secret", { leafId: leaf, name });
export const revealSecret = (leaf: string, name: string) =>
  invoke<string>("reveal_secret", { leafId: leaf, name });

// ── Judge & Policy (screen 06) ─────────────────────────────────────────────
export interface KeyringState {
  exists: boolean;
  unlocked: boolean;
  judge_enabled: boolean;
  mcp_enabled: boolean;
  default_judge: string | null;
  judge_count: number;
}
export interface JudgeInfo {
  name: string;
  model: string;
  allow_threshold: number;
  high_threshold: number;
  criteria: string;
  has_key: boolean;
  is_default: boolean;
}
export interface JudgeFormInput {
  name: string;
  model: string;
  allow_threshold: number;
  high_threshold: number;
  criteria: string;
  api_key: string | null;
}
export interface JudgeTestInput {
  judge: string | null;
  reason: string;
  scope: string;
  secret: string;
  caller: string;
  tier: string;
  secret_description: string;
}
export interface JudgeTestResult {
  verdict: "allow" | "deny" | "unavailable";
  score: number | null;
  rationale: string;
  model: string;
  allow_threshold: number;
  high_threshold: number;
}

export const keyringState = () => invoke<KeyringState>("keyring_state");
export const judgeList = () => invoke<JudgeInfo[]>("judge_list");
export const judgeSave = (form: JudgeFormInput) =>
  invoke<void>("judge_save", { form });
export const judgeRemove = (name: string) =>
  invoke<void>("judge_remove", { name });
export const judgeSetDefault = (name: string) =>
  invoke<void>("judge_set_default", { name });
export const judgeToggle = (enabled: boolean) =>
  invoke<void>("judge_toggle", { enabled });
export const judgeTest = (input: JudgeTestInput) =>
  invoke<JudgeTestResult>("judge_test", { input });
export const judgeNames = () => invoke<string[]>("judge_names");

export interface CallerRuleInfo {
  name: string;
  scopes: string[];
  rate_limit: string;
}
export interface ConditionInfo {
  secret: string;
  windows: string[];
  callers: string[];
}
export interface SealInfo {
  secret: string;
  trigger: string;
  last_caller: string;
  denials: number;
  sealed_at: string;
}
export interface TierGate {
  tier: string;
  gate: string;
}
export interface PolicySurface {
  rate_limit: string;
  allow_agent: string;
  default_tier: string;
  callers: CallerRuleInfo[];
  conditioned: ConditionInfo[];
  tier_gates: TierGate[];
  seal_threshold: number;
  seal_window_secs: number;
}
export interface AccessRow {
  secret: string;
  scope: string;
  tier: string;
}
export interface CallerAccess {
  defined: boolean;
  scopes: string[];
  rate_limit: string;
  accessible: AccessRow[];
  conditioned: ConditionInfo[];
  seals: SealInfo[];
  audit_total: number;
  audit_denied: number;
}
export const policySurface = (leaf: string) =>
  invoke<PolicySurface>("policy_surface", { leafId: leaf });
export const callerAccess = (leaf: string, caller: string) =>
  invoke<CallerAccess>("caller_access", { leafId: leaf, caller });

// ── MCP (screen 07) ────────────────────────────────────────────────────────
export interface ConnectedAgent {
  caller: string;
  peer_uid: number | null;
  last_call: number | null;
  calls_today: number;
}
export const connectedAgents = () =>
  invoke<ConnectedAgent[]>("connected_agents");
export const mcpToggle = (enabled: boolean) =>
  invoke<void>("mcp_toggle", { enabled });
export const mcpEnabled = () => invoke<boolean>("mcp_enabled");
export const mcpConfigSnippet = (bin: string, caller: string) =>
  invoke<string>("mcp_config_snippet", { bin, caller });
export const writeMcpConfig = (path: string, bin: string, caller: string) =>
  invoke<void>("write_mcp_config", { path, bin, caller });
export const storePath = () => invoke<string>("store_path");

// ── Pending approvals (screen 09) ──────────────────────────────────────────
export interface PendingItem {
  vault_leaf: string;
  vault_name: string;
  secret: string;
  scope: string;
  tier: string;
  sealed_at: string;
  trigger: string;
  last_caller: string;
  denials: number;
}
export const pending = () => invoke<PendingItem[]>("pending");
export const approveUnseal = (leaf: string, secret: string) =>
  invoke<void>("approve_unseal", { leafId: leaf, secret });

// ── Audit (screen 08) + MCP live log ───────────────────────────────────────
export interface AuditEvent {
  vault_leaf: string;
  vault_name: string;
  ts: string;
  unix: number | null;
  caller: string;
  peer_uid: number | null;
  secret: string;
  scope: string;
  tier: string;
  source: string;
  decision: string;
  rule: string;
  reason: string;
}
export interface AuditFilter {
  result?: string;
  vault?: string;
  caller?: string;
  source?: string;
  limit?: number;
}
export const auditEvents = (filter: AuditFilter) =>
  invoke<AuditEvent[]>("audit_events", { filter });
export const auditCallers = () => invoke<string[]>("audit_callers");
export const exportLog = (leaf: string, path: string) =>
  invoke<void>("export_log", { leafId: leaf, path });

// ── Backup & recovery (screen 10) ──────────────────────────────────────────
export interface RecoveryStatus {
  vault_leaf: string;
  vault_name: string;
  has_code: boolean;
}
export const exportVault = (leaf: string, path: string) =>
  invoke<void>("export_vault", { leafId: leaf, path });
export const importVault = (
  path: string,
  name: string | null,
  recoveryCode: string,
) => invoke<string>("import_vault", { path, name, recoveryCode });
export const recoverMaster = (code: string, newPassphrase: string) =>
  invoke<void>("recover_master", { code, newPassphrase });
export const recoveryStatus = () =>
  invoke<RecoveryStatus[]>("recovery_status");
export const rotateCode = (leaf: string) =>
  invoke<string>("rotate_code", { leafId: leaf });

// ── Settings (screen 11) ───────────────────────────────────────────────────
export interface DaemonInfo {
  running: boolean;
  pid: number | null;
  max_connections: number;
  idle_timeout_secs: number;
  max_unlocked_secs: number;
  supported: boolean;
}
export interface YubikeyStatus {
  enrolled: boolean;
  present: boolean;
}
export const getPrefs = () => invoke<Record<string, unknown>>("get_prefs");
export const setPrefs = (prefs: Record<string, unknown>) =>
  invoke<void>("set_prefs", { prefs });
export const changeMaster = (newPassphrase: string) =>
  invoke<void>("change_master", { newPassphrase });
export const yubikeyStatus = () => invoke<YubikeyStatus>("yubikey_status");
export const daemonInfo = () => invoke<DaemonInfo>("daemon_info");
export const daemonStart = () => invoke<string>("daemon_start");
export const daemonStop = () => invoke<string>("daemon_stop");
export const daemonDoctor = () => invoke<boolean>("daemon_doctor");
export const setDaemonLimits = (
  idleTimeoutSecs: number,
  maxConnections: number,
) => invoke<void>("set_daemon_limits", { idleTimeoutSecs, maxConnections });
export const diagnostics = () => invoke<string>("diagnostics");
export const storeFolder = () => invoke<string>("store_folder");

export const installCli = () => invoke<string>("install_cli");

// ── Tray / popover (screen 12) ─────────────────────────────────────────────
export const openMain = () => invoke<void>("open_main");
export const hidePopover = () => invoke<void>("hide_popover");
