import { useEffect, useState } from "react";
import { Fingerprint } from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  changeMaster,
  daemonDoctor,
  daemonInfo,
  daemonStart,
  daemonStop,
  diagnostics,
  enrollTouchid,
  enrollYubikey,
  getPrefs,
  installCli,
  lockAll,
  removeTouchid,
  removeYubikey,
  setDaemonLimits,
  setPrefs,
  touchidStatus,
  yubikeyStatus,
} from "../lib/api";
import { Page } from "../components/shell";
import { Button, Card, Field, Input, Select, Toggle } from "../components/ui";
import { applyAppearance } from "../lib/theme";

type ItemId =
  | "appearance"
  | "passphrase"
  | "touchid"
  | "yubikey"
  | "lock"
  | "daemon"
  | "diagnostics";

type NavItem = { id: ItemId; label: string; keywords: string };
type NavGroup = { label: string; items: NavItem[] };

export default function Settings() {
  const [selected, setSelected] = useState<ItemId>("appearance");
  const [search, setSearch] = useState("");
  const tid = useQuery({ queryKey: ["touchid"], queryFn: touchidStatus });

  const groups: NavGroup[] = [
    {
      label: "General",
      items: [
        {
          id: "appearance",
          label: "Appearance & startup",
          keywords: "theme tray launch login motion",
        },
      ],
    },
    {
      label: "Security",
      items: [
        {
          id: "passphrase",
          label: "Passphrase",
          keywords: "master rekey change password",
        },
        ...(tid.data?.supported
          ? [
              {
                id: "touchid" as const,
                label: "Touch ID",
                keywords: "fingerprint biometric",
              },
            ]
          : []),
        {
          id: "yubikey",
          label: "YubiKey",
          keywords: "fido2 hardware key pin",
        },
        {
          id: "lock",
          label: "Lock & sessions",
          keywords: "lock all re-auth session",
        },
      ],
    },
    {
      label: "System",
      items: [
        { id: "daemon", label: "Daemon", keywords: "auto-lock connections" },
        {
          id: "diagnostics",
          label: "Diagnostics",
          keywords: "cli install about version",
        },
      ],
    },
  ];

  const q = search.trim().toLowerCase();
  const filtered = groups
    .map((g) => ({
      ...g,
      items: g.items.filter(
        (it) =>
          !q ||
          it.label.toLowerCase().includes(q) ||
          it.keywords.toLowerCase().includes(q),
      ),
    }))
    .filter((g) => g.items.length > 0);

  const visibleIds = filtered.flatMap((g) => g.items.map((it) => it.id));
  useEffect(() => {
    if (visibleIds.length > 0 && !visibleIds.includes(selected)) {
      setSelected(visibleIds[0]);
    }
  }, [visibleIds.join(","), selected]);

  return (
    <Page title="Settings">
      <div className="flex h-full gap-6">
        <div className="flex w-56 shrink-0 flex-col gap-3">
          <Input
            placeholder="Search settings"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <nav className="flex flex-col gap-4">
            {filtered.map((g) => (
              <div key={g.label}>
                <div className="mb-1 px-2 text-[11px] font-semibold uppercase tracking-wider text-content-muted">
                  {g.label}
                </div>
                <div className="flex flex-col gap-0.5">
                  {g.items.map((it) => (
                    <button
                      key={it.id}
                      onClick={() => setSelected(it.id)}
                      className={`rounded-lg px-2 py-1.5 text-left text-sm transition-colors hover:bg-surface-sunken ${
                        selected === it.id
                          ? "bg-surface-sunken font-medium"
                          : "text-content-muted"
                      }`}
                    >
                      {it.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
            {filtered.length === 0 && (
              <p className="px-2 text-sm text-content-muted">No matches.</p>
            )}
          </nav>
        </div>
        <div className="min-w-0 flex-1">
          {selected === "appearance" && <AppearancePanel />}
          {selected === "passphrase" && <PassphrasePanel />}
          {selected === "touchid" && <TouchIdPanel />}
          {selected === "yubikey" && <YubikeyPanel />}
          {selected === "lock" && <LockPanel />}
          {selected === "daemon" && <DaemonPanel />}
          {selected === "diagnostics" && <DiagnosticsPanel />}
        </div>
      </div>
    </Page>
  );
}

function PanelCard({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="max-w-xl p-5">
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="mb-4 mt-1 text-xs text-content-muted">{description}</p>
      {children}
    </Card>
  );
}

function AppearancePanel() {
  const prefs = useQuery({ queryKey: ["prefs"], queryFn: getPrefs });
  const qc = useQueryClient();
  const [local, setLocal] = useState<Record<string, unknown>>({});
  useEffect(() => {
    if (prefs.data) setLocal(prefs.data);
  }, [prefs.data]);

  const saveM = useMutation({
    mutationFn: (next: Record<string, unknown>) => setPrefs(next),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["prefs"] }),
  });
  function update(key: string, value: unknown) {
    const next = { ...local, [key]: value };
    setLocal(next);
    applyAppearance(next); // theme / reduce-motion take effect immediately
    saveM.mutate(next);
  }

  return (
    <PanelCard
      title="Appearance & startup"
      description="Theme and app behavior. Preferences are saved instantly."
    >
      <div className="flex flex-col gap-4">
        <Field label="Theme">
          <Select
            className="w-48"
            value={String(local.theme ?? "system")}
            onChange={(e) => update("theme", e.target.value)}
          >
            <option value="system">System</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
            <option value="hicontrast">Hi-contrast</option>
          </Select>
        </Field>
        <Toggle
          checked={Boolean(local.reduce_motion)}
          onChange={(v) => update("reduce_motion", v)}
          label="Reduce motion"
        />
        <Toggle
          checked={Boolean(local.show_tray ?? true)}
          onChange={(v) => update("show_tray", v)}
          label="Show in menu bar / system tray"
        />
        <Toggle
          checked={Boolean(local.launch_at_login)}
          onChange={(v) => update("launch_at_login", v)}
          label="Launch at login"
        />
        <Toggle
          checked={Boolean(local.close_to_tray ?? true)}
          onChange={(v) => update("close_to_tray", v)}
          label="Close to tray"
        />
        <p className="text-xs text-content-muted">
          Preferences are saved instantly. Theme, motion, launch-at-login, and
          close-to-tray apply immediately; the tray icon itself appears or
          disappears on the next app start.
        </p>
      </div>
    </PanelCard>
  );
}

function PassphrasePanel() {
  const [pp, setPp] = useState("");
  const [pp2, setPp2] = useState("");
  const [status, setStatus] = useState<string | null>(null);

  const rekeyM = useMutation({
    mutationFn: () => changeMaster(pp),
    onSuccess: () => {
      setStatus("Master passphrase changed.");
      setPp("");
      setPp2("");
    },
    onError: (e) => setStatus(String(e)),
  });

  return (
    <PanelCard
      title="Passphrase"
      description="Changing the passphrase rewraps only the master key, never any vault data."
    >
      <div className="flex max-w-sm flex-col gap-3">
        <Field label="New master passphrase">
          <Input type="password" value={pp} onChange={(e) => setPp(e.target.value)} />
        </Field>
        <Field label="Confirm">
          <Input type="password" value={pp2} onChange={(e) => setPp2(e.target.value)} />
        </Field>
        <Button
          disabled={!pp || pp !== pp2 || rekeyM.isPending}
          onClick={() => rekeyM.mutate()}
        >
          Change passphrase
        </Button>
        {status && <p className="text-sm text-content-muted">{status}</p>}
      </div>
    </PanelCard>
  );
}

function TouchIdPanel() {
  const qc = useQueryClient();
  const tid = useQuery({ queryKey: ["touchid"], queryFn: touchidStatus });
  const [status, setStatus] = useState<string | null>(null);

  const enrollTidM = useMutation({
    mutationFn: enrollTouchid,
    onSuccess: () => {
      setStatus("Touch ID enrolled.");
      qc.invalidateQueries({ queryKey: ["touchid"] });
    },
    onError: (e) => setStatus(String(e)),
  });
  const removeTidM = useMutation({
    mutationFn: removeTouchid,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["touchid"] }),
  });

  return (
    <PanelCard
      title="Touch ID"
      description="The wrapping key lives in the login keychain and is released after the system fingerprint sheet. The passphrase always keeps working."
    >
      <div className="flex flex-col gap-3 text-sm">
        <div className="flex items-center gap-2 text-content-muted">
          <Fingerprint className="size-4" />
          Touch ID: {tid.data?.enrolled ? "enrolled" : "not enrolled"}
        </div>
        {tid.data?.enrolled ? (
          <Button
            variant="secondary"
            className="self-start"
            onClick={() => removeTidM.mutate()}
          >
            Remove Touch ID
          </Button>
        ) : (
          <Button
            disabled={enrollTidM.isPending}
            onClick={() => enrollTidM.mutate()}
            className="flex items-center justify-center gap-2 self-start"
          >
            <Fingerprint className="size-4" />
            {enrollTidM.isPending ? "Touch the sensor…" : "Enroll Touch ID"}
          </Button>
        )}
        {status && <p className="text-sm text-content-muted">{status}</p>}
      </div>
    </PanelCard>
  );
}

function YubikeyPanel() {
  const qc = useQueryClient();
  const yk = useQuery({ queryKey: ["yubikey"], queryFn: yubikeyStatus });
  const [pin, setPin] = useState("");
  const [status, setStatus] = useState<string | null>(null);

  const enrollM = useMutation({
    mutationFn: () => enrollYubikey(pin || null),
    onSuccess: () => {
      setStatus("YubiKey enrolled.");
      setPin("");
      qc.invalidateQueries({ queryKey: ["yubikey"] });
    },
    onError: (e) => setStatus(String(e)),
  });
  const removeYkM = useMutation({
    mutationFn: removeYubikey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["yubikey"] }),
  });

  return (
    <PanelCard
      title="YubiKey"
      description="Use a hardware key as an unlock factor. Enrollment asks for two touches."
    >
      <div className="flex flex-col gap-3 text-sm">
        <div className="text-content-muted">
          YubiKey: {yk.data?.enrolled ? "enrolled" : "not enrolled"} ·{" "}
          {yk.data?.present ? "connected" : "not connected"}
        </div>
        {yk.data?.enrolled ? (
          <Button
            variant="secondary"
            className="self-start"
            onClick={() => removeYkM.mutate()}
          >
            Remove YubiKey
          </Button>
        ) : (
          <div className="flex max-w-sm gap-2">
            <Input
              type="password"
              placeholder="PIN (blank if none)"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
            />
            <Button
              disabled={!yk.data?.present || enrollM.isPending}
              onClick={() => enrollM.mutate()}
            >
              Enroll
            </Button>
          </div>
        )}
        {status && <p className="text-sm text-content-muted">{status}</p>}
      </div>
    </PanelCard>
  );
}

function LockPanel() {
  const daemon = useQuery({ queryKey: ["daemon-info"], queryFn: daemonInfo });
  const [capHours, setCapHours] = useState<number | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    if (daemon.data && capHours == null) {
      setCapHours(Math.round(daemon.data.max_unlocked_secs / 3600));
    }
  }, [daemon.data]);

  const capM = useMutation({
    mutationFn: () =>
      setDaemonLimits(
        daemon.data?.idle_timeout_secs ?? 15 * 60,
        daemon.data?.max_connections ?? 512,
        Math.min(168, Math.max(1, capHours ?? 6)) * 3600,
      ),
    onSuccess: () => {
      setStatus("Re-auth cap saved — applies from the next sign-in.");
      daemon.refetch();
    },
    onError: (e) => setStatus(String(e)),
  });

  return (
    <PanelCard
      title="Lock & sessions"
      description="Lock every vault now and set how long a sign-in lasts before re-authentication."
    >
      <div className="flex max-w-sm flex-col gap-3">
        <Field label="Re-auth cap (hours, 1-168 = 1 week)">
          <div className="flex gap-2">
            <Input
              type="number"
              min={1}
              max={168}
              value={capHours ?? ""}
              onChange={(e) => setCapHours(Number(e.target.value))}
            />
            <Button disabled={capM.isPending} onClick={() => capM.mutate()}>
              Save
            </Button>
          </div>
        </Field>
        {status && <p className="text-sm text-content-muted">{status}</p>}
        <Button variant="dangerOutline" className="self-start" onClick={() => lockAll()}>
          Lock all
        </Button>
      </div>
    </PanelCard>
  );
}

function DaemonPanel() {
  const daemon = useQuery({
    queryKey: ["daemon-info"],
    queryFn: daemonInfo,
    refetchInterval: 2000,
  });
  const [status, setStatus] = useState<string | null>(null);
  const [idle, setIdle] = useState<number | null>(null);
  const [maxc, setMaxc] = useState<number | null>(null);

  useEffect(() => {
    if (daemon.data) {
      if (idle == null) setIdle(Math.round(daemon.data.idle_timeout_secs / 60));
      if (maxc == null) setMaxc(daemon.data.max_connections);
    }
  }, [daemon.data]);

  const startM = useMutation({ mutationFn: daemonStart, onSuccess: () => daemon.refetch() });
  const stopM = useMutation({ mutationFn: daemonStop, onSuccess: () => daemon.refetch() });
  const doctorM = useMutation({ mutationFn: daemonDoctor, onSuccess: () => daemon.refetch() });
  const limitsM = useMutation({
    mutationFn: () =>
      setDaemonLimits(
        (idle ?? 15) * 60,
        maxc ?? 512,
        daemon.data?.max_unlocked_secs ?? 6 * 3600,
      ),
    onSuccess: () => setStatus("Daemon limits saved (apply on next start)."),
  });

  return (
    <PanelCard
      title="Daemon"
      description="Background agent that holds unlocked sessions and serves the CLI."
    >
      {daemon.data?.supported === false ? (
        <p className="text-sm text-content-muted">
          This platform has no daemon — Svault uses the 0600 session fallback.
        </p>
      ) : (
        <div className="flex max-w-sm flex-col gap-3 text-sm">
          <Row k="Status" v={daemon.data?.running ? "running" : "stopped"} />
          <Row k="PID" v={daemon.data?.pid ? String(daemon.data.pid) : "—"} />
          <div className="flex gap-2">
            {daemon.data?.running ? (
              <Button variant="secondary" onClick={() => stopM.mutate()}>
                Stop
              </Button>
            ) : (
              <Button variant="secondary" onClick={() => startM.mutate()}>
                Start
              </Button>
            )}
            <Button variant="secondary" onClick={() => doctorM.mutate()}>
              Run doctor
            </Button>
          </div>
          <Field label="Auto-lock idle (minutes)">
            <Input
              type="number"
              value={idle ?? ""}
              onChange={(e) => setIdle(Number(e.target.value))}
            />
          </Field>
          <Field label="Max connections">
            <Input
              type="number"
              value={maxc ?? ""}
              onChange={(e) => setMaxc(Number(e.target.value))}
            />
          </Field>
          <Button onClick={() => limitsM.mutate()}>Save daemon limits</Button>
          {status && <p className="text-sm text-content-muted">{status}</p>}
        </div>
      )}
    </PanelCard>
  );
}

function DiagnosticsPanel() {
  const diag = useQuery({ queryKey: ["diagnostics"], queryFn: diagnostics });
  const [cliStatus, setCliStatus] = useState<string | null>(null);
  const installM = useMutation({
    mutationFn: installCli,
    onSuccess: (p) => setCliStatus(`Installed to ${p}`),
    onError: (e) => setCliStatus(String(e)),
  });
  return (
    <PanelCard
      title="About & diagnostics"
      description="Version and environment info for bug reports. No secrets are included."
    >
      <pre className="overflow-auto rounded-lg bg-surface-sunken p-3 text-xs">
        {diag.data ?? "…"}
      </pre>
      <div className="mt-3 flex gap-2">
        <Button variant="secondary" onClick={() => writeText(diag.data ?? "")}>
          Copy diagnostics
        </Button>
        <Button variant="secondary" onClick={() => installM.mutate()}>
          Install CLI to PATH
        </Button>
      </div>
      {cliStatus && <p className="mt-2 text-xs text-content-muted">{cliStatus}</p>}
      <p className="mt-3 text-xs text-content-muted">
        Installing the CLI also provides the TUI and MCP server (`svault mcp`). No
        secrets are included in diagnostics.
      </p>
    </PanelCard>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-4 py-0.5 text-sm">
      <span className="text-content-muted">{k}</span>
      <span>{v}</span>
    </div>
  );
}
