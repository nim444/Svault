import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Lock, LockOpen, Settings2, Trash2 } from "lucide-react";
import {
  deleteVault,
  listVaults,
  lockVault,
  unlockVault,
  VaultSummary,
} from "../lib/api";
import { useJudgeActive } from "../lib/hooks";
import { shortTime } from "../lib/time";
import { Page } from "../components/shell";
import {
  Badge,
  Button,
  Card,
  Field,
  Input,
  Modal,
  StateDot,
  TierBadge,
} from "../components/ui";

// Screen 03 — vault list (home). Card grid, consistent with providers/judges.
export default function Vaults() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [toDelete, setToDelete] = useState<VaultSummary | null>(null);
  const judgeActive = useJudgeActive();

  const { data, isLoading, error } = useQuery({
    queryKey: ["vaults"],
    queryFn: listVaults,
  });

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["vaults"] });
    qc.invalidateQueries({ queryKey: ["session-status"] });
  };

  const lockM = useMutation({ mutationFn: lockVault, onSuccess: refresh });
  const unlockM = useMutation({ mutationFn: unlockVault, onSuccess: refresh });
  const deleteM = useMutation({
    mutationFn: deleteVault,
    onSuccess: () => {
      setToDelete(null);
      refresh();
    },
  });

  const vaults = (data ?? []).filter(
    (v) =>
      v.name.toLowerCase().includes(search.toLowerCase()) ||
      v.description.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <Page
      title="Vaults"
      badge={<Badge tone="neutral">local only</Badge>}
      actions={
        <>
          <Input
            placeholder="Search…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-48"
          />
          <Button onClick={() => navigate("/vaults/new")}>+ Create vault</Button>
        </>
      }
    >
      {isLoading && <p className="text-content-muted">Loading…</p>}
      {error && <p className="text-state-deny">{String(error)}</p>}

      {data && vaults.length === 0 && (
        <div className="rounded-xl border border-dashed border-border-subtle p-10 text-center text-content-muted">
          {search ? "No vaults match." : "No vaults yet. Create your first one."}
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {vaults.map((v) => (
          <Card key={v.leaf} className="flex flex-col p-4">
            {/* Identity + lock state */}
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <StateDot tone={v.unlocked ? "allow" : "deny"} />
                  <span className="truncate font-medium">
                    <span className="text-content-muted">local:</span>
                    {v.name}
                  </span>
                </div>
                <p className="mt-1 truncate text-xs text-content-muted">
                  {v.description || "no description"}
                </p>
              </div>
              <Badge tone={v.unlocked ? "allow" : "deny"}>
                {v.unlocked ? "unlocked" : "locked"}
              </Badge>
            </div>

            {/* Stats */}
            <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-content-muted">
              <span>
                {v.secret_count} secret{v.secret_count === 1 ? "" : "s"}
              </span>
              <span>·</span>
              <TierBadge tier={v.default_tier} />
              {judgeActive && (
                <>
                  <span>·</span>
                  {v.judge_enabled ? (
                    <Badge tone="judge">{v.assigned_judge ?? "default"}</Badge>
                  ) : (
                    <span>judge off</span>
                  )}
                </>
              )}
              {v.sealed_count > 0 && (
                <>
                  <span>·</span>
                  <Badge tone="pending">{v.sealed_count} sealed</Badge>
                </>
              )}
              <span className="ml-auto">{shortTime(v.last_activity)}</span>
            </div>

            {/* Actions */}
            <div className="mt-3 flex items-center gap-1 border-t border-border-subtle pt-3">
              <Button
                variant="secondary"
                className="px-3 py-1 text-xs"
                onClick={() => navigate(`/vaults/${v.leaf}`)}
              >
                Open
              </Button>
              {v.unlocked ? (
                <Button
                  variant="ghost"
                  className="gap-1.5 px-2 py-1 text-xs"
                  onClick={() => lockM.mutate(v.leaf)}
                >
                  <Lock className="size-3.5" />
                  Lock
                </Button>
              ) : (
                <Button
                  variant="ghost"
                  className="gap-1.5 px-2 py-1 text-xs"
                  onClick={() => unlockM.mutate(v.leaf)}
                >
                  <LockOpen className="size-3.5" />
                  Unlock
                </Button>
              )}
              <Button
                variant="ghost"
                className="gap-1.5 px-2 py-1 text-xs"
                onClick={() => navigate(`/vaults/${v.leaf}/settings`)}
              >
                <Settings2 className="size-3.5" />
                Settings
              </Button>
              <Button
                variant="ghost"
                className="ml-auto px-2 py-1 text-xs text-state-deny"
                title="Delete vault"
                onClick={() => setToDelete(v)}
              >
                <Trash2 className="size-3.5" />
              </Button>
            </div>
          </Card>
        ))}
      </div>

      {toDelete && (
        <DeleteVaultModal
          vault={toDelete}
          busy={deleteM.isPending}
          onCancel={() => setToDelete(null)}
          onConfirm={() => deleteM.mutate(toDelete.leaf)}
        />
      )}
    </Page>
  );
}

// GitHub-style destructive confirmation: spell out the consequences, offer the
// export ramp first, and require typing the vault's name before Delete arms.
function DeleteVaultModal({
  vault,
  busy,
  onCancel,
  onConfirm,
}: {
  vault: VaultSummary;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const navigate = useNavigate();
  const [typed, setTyped] = useState("");
  const armed = typed === vault.name;
  return (
    <Modal title={`Delete vault "${vault.name}"`} onClose={onCancel}>
      <div className="flex flex-col gap-3 text-sm">
        <p className="text-state-deny">
          This permanently destroys the vault, its{" "}
          <strong>{vault.secret_count}</strong> secret
          {vault.secret_count === 1 ? "" : "s"}, its policy, and its recovery
          code. <strong>It cannot be restored</strong> — not even with your
          master passphrase or the recovery code.
        </p>
        <div className="rounded-lg border border-border-subtle bg-surface-sunken p-3 text-xs text-content-muted">
          Want a way back? Export an encrypted backup first — it can be
          re-imported later with this vault's recovery code.
          <Button
            variant="secondary"
            className="mt-2 block px-3 py-1.5 text-xs"
            onClick={() => navigate("/backup")}
          >
            Export a backup first
          </Button>
        </div>
        <Field
          label={`Type "${vault.name}" to confirm`}
          hint="Nothing happens until the name matches exactly."
        >
          <Input
            autoFocus
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={vault.name}
          />
        </Field>
        <div className="mt-1 flex justify-end gap-2">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={!armed || busy}
            className="disabled:bg-muted disabled:text-muted-foreground disabled:opacity-100"
            onClick={onConfirm}
          >
            {busy ? "Deleting…" : "I understand — delete this vault"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
