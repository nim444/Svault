import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
  ConfirmDialog,
  Input,
  StateDot,
  TierBadge,
} from "../components/ui";

// Screen 03 — vault list (home). Dense-table direction.
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

      {vaults.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-border-subtle">
          <table className="w-full text-sm">
            <thead className="bg-surface-sunken text-left text-xs uppercase text-content-muted">
              <tr>
                <Th>Vault</Th>
                <Th>State</Th>
                <Th>Secrets</Th>
                <Th>Default tier</Th>
                {judgeActive && <Th>Judge</Th>}
                <Th>Last activity</Th>
                <Th>Actions</Th>
              </tr>
            </thead>
            <tbody>
              {vaults.map((v) => (
                <tr
                  key={v.leaf}
                  className="border-t border-border-subtle hover:bg-surface-raised/40"
                >
                  <Td>
                    <div className="font-medium text-content">
                      <span className="text-content-muted">local:</span>
                      {v.name}
                    </div>
                    {v.description && (
                      <div className="text-xs text-content-muted">{v.description}</div>
                    )}
                  </Td>
                  <Td>
                    <span className="inline-flex items-center gap-2">
                      <StateDot tone={v.unlocked ? "allow" : "deny"} />
                      {v.unlocked ? "unlocked" : "locked"}
                    </span>
                  </Td>
                  <Td>{v.secret_count}</Td>
                  <Td>
                    <TierBadge tier={v.default_tier} />
                  </Td>
                  {judgeActive && (
                    <Td>
                      {v.judge_enabled ? (
                        <Badge tone="judge">{v.assigned_judge ?? "default"}</Badge>
                      ) : (
                        <span className="text-content-muted">off</span>
                      )}
                    </Td>
                  )}
                  <Td className="text-content-muted">{shortTime(v.last_activity)}</Td>
                  <Td>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="secondary"
                        className="px-2 py-1 text-xs"
                        onClick={() => navigate(`/vaults/${v.leaf}`)}
                      >
                        Open
                      </Button>
                      <IconBtn
                        title="Settings"
                        onClick={() => navigate(`/vaults/${v.leaf}/settings`)}
                      >
                        ⚙
                      </IconBtn>
                      {v.unlocked ? (
                        <IconBtn title="Lock" onClick={() => lockM.mutate(v.leaf)}>
                          🔒
                        </IconBtn>
                      ) : (
                        <IconBtn title="Unlock" onClick={() => unlockM.mutate(v.leaf)}>
                          🔓
                        </IconBtn>
                      )}
                      <IconBtn title="Delete" danger onClick={() => setToDelete(v)}>
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

      {toDelete && (
        <ConfirmDialog
          title={`Delete vault "${toDelete.name}"?`}
          danger
          confirmLabel="Delete vault"
          busy={deleteM.isPending}
          message={
            <>
              This permanently removes the vault and all{" "}
              <strong>{toDelete.secret_count}</strong> of its secrets. This cannot
              be undone.
            </>
          }
          onCancel={() => setToDelete(null)}
          onConfirm={() => deleteM.mutate(toDelete.leaf)}
        />
      )}
    </Page>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-4 py-2.5 font-medium">{children}</th>;
}
function Td({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <td className={`px-4 py-3 align-top ${className ?? ""}`}>{children}</td>;
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
