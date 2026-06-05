import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createVault,
  saveSettings,
  vaultSettings,
  VaultForm,
} from "../lib/api";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useJudgeActive } from "../lib/hooks";
import { Page } from "../components/shell";
import {
  Button,
  Card,
  Checkbox,
  Field,
  Input,
  Modal,
  Segmented,
  Select,
  Toggle,
} from "../components/ui";

const emptyForm: VaultForm = {
  name: "",
  description: "",
  allow_agent_mode: "none",
  allow_agent_list: [],
  rate_limit: "10/hour",
  autolock: true,
  autolock_timer: "1d",
  login_method: "passphrase",
  default_tier: "low",
  judge_enabled: false,
  assigned_judge: null,
};

// Screen 04 — vault config. Create mode (/vaults/new) and edit mode
// (/vaults/:leaf/settings) share one field set written into the encrypted policy.
export default function VaultConfig() {
  const { leaf } = useParams();
  const editing = Boolean(leaf);
  const navigate = useNavigate();
  const qc = useQueryClient();

  const judgeActive = useJudgeActive();
  const [form, setForm] = useState<VaultForm>(emptyForm);
  const [callersText, setCallersText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);

  const existing = useQuery({
    queryKey: ["vault-settings", leaf],
    queryFn: () => vaultSettings(leaf!),
    enabled: editing,
  });

  useEffect(() => {
    if (existing.data) {
      const { leaf: _leaf, ...rest } = existing.data;
      setForm(rest);
      setCallersText(rest.allow_agent_list.join(", "));
    }
  }, [existing.data]);

  function set<K extends keyof VaultForm>(key: K, value: VaultForm[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  const finalForm = (): VaultForm => ({
    ...form,
    allow_agent_list:
      form.allow_agent_mode === "list"
        ? callersText
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : [],
    assigned_judge: form.judge_enabled ? form.assigned_judge || null : null,
  });

  const createM = useMutation({
    mutationFn: () => createVault(finalForm()),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["vaults"] });
      setRecoveryCode(res.recovery_code);
    },
    onError: (e) => setError(String(e)),
  });

  const saveM = useMutation({
    mutationFn: () => saveSettings(leaf!, finalForm()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vaults"] });
      navigate("/vaults");
    },
    onError: (e) => setError(String(e)),
  });

  return (
    <Page title={editing ? `Edit settings · ${form.name}` : "Create vault"}>
      <Card className="max-w-2xl p-6">
        <div className="flex flex-col gap-5">
          {!editing && (
            <Field label="Vault name" hint="Must be unique. Used as the vault id.">
              <Input
                autoFocus
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="my-project"
              />
            </Field>
          )}

          <Field label="Description" hint="Given to the AI judge as the vault's purpose.">
            <Input
              value={form.description}
              onChange={(e) => set("description", e.target.value)}
            />
          </Field>

          <Field label="Allow agent" hint="Which callers may request secrets via the gate.">
            <div className="flex flex-col gap-2">
              <Segmented
                value={form.allow_agent_mode}
                onChange={(v) => set("allow_agent_mode", v)}
                options={[
                  { value: "none", label: "None" },
                  { value: "list", label: "List" },
                  { value: "all", label: "All" },
                ]}
              />
              {form.allow_agent_mode === "list" && (
                <Input
                  placeholder="caller names, comma-separated"
                  value={callersText}
                  onChange={(e) => setCallersText(e.target.value)}
                />
              )}
            </div>
          </Field>

          <div className="grid grid-cols-2 gap-4">
            <Field label="Rate limit">
              <Input
                value={form.rate_limit}
                onChange={(e) => set("rate_limit", e.target.value)}
                placeholder="10/hour"
              />
            </Field>
            <Field
              label="Default tier"
              hint={
                judgeActive
                  ? "medium/high invoke the AI judge."
                  : "medium/high are human-only until an AI judge is active."
              }
            >
              <Segmented
                value={form.default_tier}
                onChange={(v) => set("default_tier", v)}
                options={[
                  { value: "low", label: "Low" },
                  { value: "medium", label: "Medium" },
                  { value: "high", label: "High" },
                ]}
              />
            </Field>
          </div>

          <Field label="Auto-lock">
            <div className="flex items-center gap-4">
              <Toggle
                checked={form.autolock}
                onChange={(v) => set("autolock", v)}
                label="Lock when idle"
              />
              {form.autolock && (
                <Select
                  className="w-32"
                  value={form.autolock_timer}
                  onChange={(e) => set("autolock_timer", e.target.value)}
                >
                  <option value="30m">30m</option>
                  <option value="12h">12h</option>
                  <option value="1d">1d</option>
                </Select>
              )}
            </div>
          </Field>

          <Field label="Login method">
            <Select
              className="w-48"
              value={form.login_method}
              onChange={(e) => set("login_method", e.target.value as VaultForm["login_method"])}
            >
              <option value="passphrase">Passphrase</option>
              <option value="yubikey">YubiKey</option>
            </Select>
          </Field>

          {judgeActive && (
            <Field label="AI judge">
              <div className="flex flex-col gap-2">
                <Checkbox
                  checked={form.judge_enabled}
                  onChange={(v) => set("judge_enabled", v)}
                >
                  Use the AI judge for this vault's medium/high secrets
                </Checkbox>
                {form.judge_enabled && (
                  <Input
                    placeholder="assigned judge name (blank = keyring default)"
                    value={form.assigned_judge ?? ""}
                    onChange={(e) => set("assigned_judge", e.target.value || null)}
                  />
                )}
              </div>
            </Field>
          )}

          {error && <p className="text-sm text-state-deny">{error}</p>}

          <div className="flex justify-end gap-2 border-t border-border-subtle pt-4">
            <Button variant="secondary" onClick={() => navigate("/vaults")}>
              Cancel
            </Button>
            {editing ? (
              <Button onClick={() => saveM.mutate()} disabled={saveM.isPending}>
                {saveM.isPending ? "Saving…" : "Save changes"}
              </Button>
            ) : (
              <Button
                onClick={() => createM.mutate()}
                disabled={createM.isPending || !form.name.trim()}
              >
                {createM.isPending ? "Creating…" : "Create vault"}
              </Button>
            )}
          </div>
        </div>
      </Card>

      {recoveryCode && (
        <RecoveryModal
          code={recoveryCode}
          onDone={() => navigate("/vaults")}
        />
      )}
    </Page>
  );
}

function RecoveryModal({ code, onDone }: { code: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  return (
    <Modal title="Vault recovery code" onClose={() => {}}>
      <p className="text-sm text-content-muted">
        Shown once, never stored in plaintext. It re-attaches this vault if you
        lose your passphrase. Save it now.
      </p>
      <div className="my-4 rounded-lg border border-state-pending/30 bg-state-pending/10 p-3 text-center font-mono text-sm tracking-wide">
        {code}
      </div>
      <Button
        variant="secondary"
        className="mb-4 w-full"
        onClick={async () => {
          await writeText(code);
          setCopied(true);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </Button>
      <Checkbox checked={saved} onChange={setSaved}>
        I've stored this somewhere safe
      </Checkbox>
      <div className="mt-5 flex justify-end">
        <Button disabled={!saved} onClick={onDone}>
          Done
        </Button>
      </div>
    </Modal>
  );
}
