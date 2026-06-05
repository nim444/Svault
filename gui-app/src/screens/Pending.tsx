import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { approveUnseal, pending, PendingItem } from "../lib/api";
import { shortTime } from "../lib/time";
import { Page } from "../components/shell";
import { Badge, Button, Card, TierBadge } from "../components/ui";

// Screen 09 — sealed secrets awaiting a human. Agents can never self-clear.
export default function Pending() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { data, isLoading } = useQuery({ queryKey: ["pending"], queryFn: pending });

  const unsealM = useMutation({
    mutationFn: (i: PendingItem) => approveUnseal(i.vault_leaf, i.secret),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["pending"] });
      qc.invalidateQueries({ queryKey: ["vaults"] });
    },
  });

  return (
    <Page title="Pending approvals">
      {isLoading && <p className="text-content-muted">Loading…</p>}
      {data && data.length === 0 && (
        <div className="rounded-xl border border-dashed border-border-subtle p-10 text-center text-content-muted">
          No sealed secrets — nothing pending approval.
        </div>
      )}
      <div className="flex flex-col gap-3">
        {(data ?? []).map((i) => (
          <Card key={`${i.vault_leaf}/${i.secret}`} className="p-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="mb-1 flex items-center gap-2">
                  <Badge tone="deny">SEALED</Badge>
                  <span className="font-medium">{i.secret}</span>
                  <span className="text-content-muted">in {i.vault_name}</span>
                  <Badge tone="neutral">{i.scope || "—"}</Badge>
                  <TierBadge tier={i.tier} />
                </div>
                <div className="text-sm text-content-muted">
                  {i.trigger} · last caller <strong>{i.last_caller}</strong> ·{" "}
                  {i.denials} denials · sealed {shortTime(toUnix(i.sealed_at))}
                </div>
              </div>
              <div className="flex shrink-0 gap-2">
                <Button
                  variant="secondary"
                  className="px-2 py-1 text-xs"
                  onClick={() => navigate("/audit")}
                >
                  View in audit
                </Button>
                <Button
                  className="px-2 py-1 text-xs"
                  disabled={unsealM.isPending}
                  onClick={() => unsealM.mutate(i)}
                >
                  Approve &amp; unseal
                </Button>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </Page>
  );
}

function toUnix(rfc3339: string): number | null {
  const t = Date.parse(rfc3339);
  return Number.isNaN(t) ? null : Math.floor(t / 1000);
}
