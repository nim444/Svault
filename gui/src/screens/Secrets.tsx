import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  addSecret,
  editSecret,
  listSecrets,
  removeSecret,
  revealSecret,
  SecretForm,
  SecretSummary,
  vaultSettings,
} from "../lib/api";
import { useJudgeActive } from "../lib/hooks";
import { shortTime } from "../lib/time";
import { Page } from "../components/shell";
import {
  Badge,
  Button,
  Card,
  Checkbox,
  ConfirmDialog,
  Field,
  Input,
  Modal,
  Segmented,
  TierBadge,
} from "../components/ui";

interface PanelState {
  editingName: string | null;
  name: string;
  value: string;
  scope: string;
  tier: "low" | "medium" | "high";
  require_reason: boolean;
  description: string;
  windowsText: string;
  callersText: string;
}

const blankPanel: PanelState = {
  editingName: null,
  name: "",
  value: "",
  scope: "misc",
  tier: "low",
  require_reason: false,
  description: "",
  windowsText: "",
  callersText: "",
};

// Screen 05 — a vault's secrets with inline classification + add/classify panel.
export default function Secrets() {
  const { leaf } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const judgeActive = useJudgeActive();
  const [panel, setPanel] = useState<PanelState>(blankPanel);
  const [toDelete, setToDelete] = useState<SecretSummary | null>(null);
  const [revealed, setRevealed] = useState<{ name: string; value: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const meta = useQuery({
    queryKey: ["vault-settings", leaf],
    queryFn: () => vaultSettings(leaf!),
  });
  const secrets = useQuery({
    queryKey: ["secrets", leaf],
    queryFn: () => listSecrets(leaf!),
  });

  const refresh = () => qc.invalidateQueries({ queryKey: ["secrets", leaf] });

  function toForm(p: PanelState): SecretForm {
    return {
      name: p.name,
      value: p.value || null,
      scope: p.scope,
      tier: p.tier,
      require_reason: p.require_reason,
      description: p.description,
      windows: p.windowsText.split(",").map((s) => s.trim()).filter(Boolean),
      require_callers: p.callersText.split(",").map((s) => s.trim()).filter(Boolean),
    };
  }

  const saveM = useMutation({
    mutationFn: () =>
      panel.editingName
        ? editSecret(leaf!, toForm(panel))
        : addSecret(leaf!, toForm(panel)),
    onSuccess: () => {
      setPanel(blankPanel);
      setError(null);
      refresh();
    },
    onError: (e) => setError(String(e)),
  });

  const deleteM = useMutation({
    mutationFn: (name: string) => removeSecret(leaf!, name),
    onSuccess: () => {
      setToDelete(null);
      refresh();
    },
  });

  const revealM = useMutation({
    mutationFn: (name: string) => revealSecret(leaf!, name),
    onSuccess: (value, name) => setRevealed({ name, value }),
    onError: (e) => setError(String(e)),
  });

  function startEdit(s: SecretSummary) {
    setPanel({
      editingName: s.name,
      name: s.name,
      value: "",
      scope: s.scope,
      tier: (s.tier as PanelState["tier"]) || "low",
      require_reason: s.require_reason,
      description: s.description,
      windowsText: s.windows.join(", "),
      callersText: s.callers.join(", "),
    });
  }

  const rows = secrets.data ?? [];

  return (
    <Page
      title={`Secrets · ${meta.data?.name ?? leaf}`}
      actions={
        <Button variant="secondary" onClick={() => navigate("/vaults")}>
          ← Vaults
        </Button>
      }
    >
      <div className="flex gap-6">
        {/* Secrets table */}
        <div className="min-w-0 flex-1">
          {secrets.isLoading && <p className="text-content-muted">Loading…</p>}
          {secrets.error && <p className="text-state-deny">{String(secrets.error)}</p>}
          {rows.length === 0 && !secrets.isLoading && (
            <div className="rounded-xl border border-dashed border-border-subtle p-10 text-center text-content-muted">
              No secrets yet. Add one on the right.
            </div>
          )}
          {rows.length > 0 && (
            <div className="overflow-hidden rounded-xl border border-border-subtle">
              <table className="w-full text-sm">
                <thead className="bg-surface-sunken text-left text-xs uppercase text-content-muted">
                  <tr>
                    <Th>Secret</Th>
                    <Th>Scope</Th>
                    <Th>Tier</Th>
                    <Th>Callers</Th>
                    <Th>Window</Th>
                    <Th>Read</Th>
                    <Th>Actions</Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((s) => (
                    <tr key={s.name} className="border-t border-border-subtle">
                      <Td className="font-medium text-content">{s.name}</Td>
                      <Td>
                        <Badge tone="neutral">{s.scope || "—"}</Badge>
                      </Td>
                      <Td>
                        <TierBadge tier={s.tier} />
                      </Td>
                      <Td>
                        {s.sealed ? (
                          <Badge tone="deny">sealed</Badge>
                        ) : s.callers.length ? (
                          s.callers.join(", ")
                        ) : (
                          <span className="text-content-muted">any</span>
                        )}
                      </Td>
                      <Td className="text-content-muted">
                        {s.windows.length ? s.windows.join("; ") : "any"}
                      </Td>
                      <Td className="text-content-muted">{shortTime(s.last_read)}</Td>
                      <Td>
                        <div className="flex gap-1">
                          <IconBtn title="Reveal" onClick={() => revealM.mutate(s.name)}>
                            ◉
                          </IconBtn>
                          <IconBtn title="Edit" onClick={() => startEdit(s)}>
                            ✎
                          </IconBtn>
                          <IconBtn title="Delete" danger onClick={() => setToDelete(s)}>
                            ✕
                          </IconBtn>
                        </div>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Add / classify panel */}
        <Card className="h-fit w-80 shrink-0 p-5">
          <h2 className="mb-4 text-sm font-semibold">
            {panel.editingName ? `Edit · ${panel.editingName}` : "Add & classify"}
          </h2>
          <div className="flex flex-col gap-3">
            <Field label="Name">
              <Input
                value={panel.name}
                disabled={!!panel.editingName}
                onChange={(e) => setPanel({ ...panel, name: e.target.value })}
              />
            </Field>
            <Field
              label="Value"
              hint="Encrypted into vault.enc, never logged."
            >
              <Input
                type="password"
                placeholder={panel.editingName ? "unchanged" : ""}
                value={panel.value}
                onChange={(e) => setPanel({ ...panel, value: e.target.value })}
              />
            </Field>
            <Field label="Scope">
              <Input
                value={panel.scope}
                onChange={(e) => setPanel({ ...panel, scope: e.target.value })}
              />
            </Field>
            <Field
              label="Sensitivity tier"
              hint={
                judgeActive
                  ? "medium/high invoke the AI judge."
                  : "medium/high are human-only until an AI judge is active."
              }
            >
              <Segmented
                value={panel.tier}
                onChange={(v) => setPanel({ ...panel, tier: v })}
                options={[
                  { value: "low", label: "Low" },
                  { value: "medium", label: "Med" },
                  { value: "high", label: "High" },
                ]}
              />
            </Field>
            {judgeActive && (
              <Checkbox
                checked={panel.require_reason}
                onChange={(v) => setPanel({ ...panel, require_reason: v })}
              >
                Always judge (even at low tier)
              </Checkbox>
            )}
            <Field
              label="Description"
              hint={
                judgeActive
                  ? "The judge weighs this against each request's reason."
                  : "Shown alongside the secret; the AI judge uses it once one is active."
              }
            >
              <Input
                value={panel.description}
                onChange={(e) => setPanel({ ...panel, description: e.target.value })}
              />
            </Field>
            <Field label="Allowed callers" hint="Comma-separated. Blank = any.">
              <Input
                value={panel.callersText}
                onChange={(e) => setPanel({ ...panel, callersText: e.target.value })}
              />
            </Field>
            <Field label="Time window" hint="e.g. mon-fri 09:00-18:00. Comma-separated.">
              <Input
                value={panel.windowsText}
                onChange={(e) => setPanel({ ...panel, windowsText: e.target.value })}
              />
            </Field>

            {error && <p className="text-sm text-state-deny">{error}</p>}

            <div className="flex gap-2 pt-1">
              {panel.editingName && (
                <Button variant="ghost" className="flex-1" onClick={() => setPanel(blankPanel)}>
                  Cancel
                </Button>
              )}
              <Button
                className="flex-1"
                disabled={saveM.isPending || !panel.name.trim()}
                onClick={() => saveM.mutate()}
              >
                {panel.editingName ? "Save" : "Add secret"}
              </Button>
            </div>
          </div>
        </Card>
      </div>

      {toDelete && (
        <ConfirmDialog
          title={`Delete secret "${toDelete.name}"?`}
          danger
          confirmLabel="Delete"
          busy={deleteM.isPending}
          message="This permanently removes the secret value and its classification."
          onCancel={() => setToDelete(null)}
          onConfirm={() => deleteM.mutate(toDelete.name)}
        />
      )}

      {revealed && (
        <Modal title={`Value · ${revealed.name}`} onClose={() => setRevealed(null)}>
          <div className="rounded-lg border border-border-subtle bg-surface-sunken p-3 font-mono text-sm break-all">
            {revealed.value}
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => writeText(revealed.value)}>
              Copy
            </Button>
            <Button onClick={() => setRevealed(null)}>Close</Button>
          </div>
        </Modal>
      )}
    </Page>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2.5 font-medium">{children}</th>;
}
function Td({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <td className={`px-3 py-3 align-top ${className ?? ""}`}>{children}</td>;
}
function IconBtn({
  children,
  title,
  danger,
  onClick,
}: {
  children: React.ReactNode;
  title: string;
  danger?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      title={title}
      onClick={onClick}
      className={`rounded-md px-2 py-1 text-sm transition-colors hover:bg-surface-sunken ${
        danger ? "text-state-deny" : "text-content-muted hover:text-content"
      }`}
    >
      {children}
    </button>
  );
}
