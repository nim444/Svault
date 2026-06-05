import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  auditEvents,
  listVaults,
  lockAll,
  lockVault,
  openMain,
  pending,
  unlockVault,
} from "../lib/api";
import { useSessionStatus } from "../lib/hooks";
import { formatSecs, shortTime } from "../lib/time";
import { Badge, Button, StateDot } from "../components/ui";

// Screen 12 — the menu-bar / tray popover. Compact: state, lock all, per-vault
// lock/unlock, pending shortcut, latest activity, open full app.
export default function TrayPopover() {
  const qc = useQueryClient();
  const { data: status } = useSessionStatus();
  const vaults = useQuery({ queryKey: ["vaults"], queryFn: listVaults, refetchInterval: 2000 });
  const pend = useQuery({ queryKey: ["pending"], queryFn: pending, refetchInterval: 3000 });
  const latest = useQuery({
    queryKey: ["latest"],
    queryFn: () => auditEvents({ limit: 1 }),
    refetchInterval: 3000,
  });

  const refresh = () => qc.invalidateQueries();
  const lockAllM = useMutation({ mutationFn: lockAll, onSuccess: refresh });
  const lockM = useMutation({ mutationFn: lockVault, onSuccess: refresh });
  const unlockM = useMutation({ mutationFn: unlockVault, onSuccess: refresh });

  const unlocked = new Set(status?.unlocked_vaults ?? []);
  const daemonUp = status?.daemon_up ?? false;
  const pendingCount = pend.data?.length ?? 0;
  const lastEvent = latest.data?.[0];

  return (
    <div className="flex h-screen flex-col bg-surface text-sm">
      <header className="flex items-center justify-between border-b border-border-subtle px-3 py-2.5">
        <span className="font-semibold">Svault</span>
        <span className="flex items-center gap-1.5 text-xs text-content-muted">
          <StateDot tone={daemonUp ? "allow" : "deny"} />
          daemon {daemonUp ? "up" : "down"}
        </span>
      </header>

      <div className="border-b border-border-subtle px-3 py-2.5 text-xs">
        <div className="flex justify-between text-content-muted">
          <span>Keys in memory</span>
          <span className="text-content">{unlocked.size > 0 ? "yes" : "no"}</span>
        </div>
        <div className="flex justify-between text-content-muted">
          <span>Auto-lock in</span>
          <span className="text-content">{formatSecs(status?.next_autolock_secs)}</span>
        </div>
        <Button
          variant="secondary"
          className="mt-2 w-full py-1.5 text-xs"
          onClick={() => lockAllM.mutate()}
        >
          Lock all
        </Button>
      </div>

      {pendingCount > 0 && (
        <button
          onClick={() => openMain()}
          className="flex items-center justify-between border-b border-border-subtle bg-state-pending/10 px-3 py-2 text-xs text-state-pending"
        >
          <span>{pendingCount} pending approval{pendingCount > 1 ? "s" : ""}</span>
          <span>Review →</span>
        </button>
      )}

      <div className="flex-1 overflow-auto px-3 py-2">
        <div className="mb-1 text-[10px] uppercase tracking-wide text-content-muted">
          Vaults
        </div>
        {(vaults.data ?? []).map((v) => (
          <div key={v.leaf} className="flex items-center justify-between py-1">
            <span className="flex items-center gap-2">
              <StateDot tone={unlocked.has(v.leaf) ? "allow" : "deny"} />
              {v.name}
            </span>
            {unlocked.has(v.leaf) ? (
              <button
                className="text-xs text-content-muted hover:text-content"
                onClick={() => lockM.mutate(v.leaf)}
              >
                Lock
              </button>
            ) : (
              <button
                className="text-xs text-content-muted hover:text-content"
                onClick={() => unlockM.mutate(v.leaf)}
              >
                Unlock
              </button>
            )}
          </div>
        ))}
      </div>

      {lastEvent && (
        <div className="border-t border-border-subtle px-3 py-2 text-xs text-content-muted">
          <Badge tone={lastEvent.decision === "deny" ? "deny" : "allow"}>
            {lastEvent.decision.toUpperCase()}
          </Badge>{" "}
          {lastEvent.secret} · {shortTime(lastEvent.unix)}
        </div>
      )}

      <div className="border-t border-border-subtle p-2">
        <Button className="w-full py-1.5 text-xs" onClick={() => openMain()}>
          Open Svault
        </Button>
      </div>
    </div>
  );
}
