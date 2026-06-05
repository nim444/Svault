import { ComponentType, ReactNode } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArchiveRestore,
  Bot,
  Hourglass,
  ListChecks,
  Plug,
  Scale,
  ScrollText,
  Settings,
  Vault,
} from "lucide-react";
import { lockAll, pending } from "../lib/api";
import { useSessionStatus } from "../lib/hooks";
import { countdownTo, formatSecs } from "../lib/time";
import { useSession } from "../store/session";
import { useStartState } from "../screens/Start";
import { Badge, Button, StateDot, cx } from "./ui";

interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string }>;
  badge?: number;
}

const primaryNav: NavItem[] = [
  { to: "/vaults", label: "Vaults", icon: Vault },
  { to: "/providers", label: "AI providers", icon: Bot },
  { to: "/judges", label: "Judges & Policy", icon: Scale },
  { to: "/mcp", label: "MCP", icon: Plug },
  { to: "/audit", label: "Audit", icon: ScrollText },
  { to: "/pending", label: "Pending", icon: Hourglass },
];

const secondaryNav: NavItem[] = [
  { to: "/backup", label: "Backup & recovery", icon: ArchiveRestore },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function AppShell() {
  return (
    <div className="flex h-full">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}

function Sidebar() {
  const pendingQ = useQuery({
    queryKey: ["pending"],
    queryFn: pending,
    refetchInterval: 5000,
  });
  const pendingCount = pendingQ.data?.length ?? 0;
  const start = useStartState();
  return (
    <aside className="flex w-58 shrink-0 flex-col border-r border-border-subtle bg-surface-sunken">
      <div className="px-4 py-4">
        <span className="text-lg font-semibold tracking-tight">Svault</span>
      </div>
      <nav className="flex flex-1 flex-col gap-0.5 px-2">
        {start && !start.complete && (
          <>
            <NavRow
              to="/start"
              label="Getting started"
              icon={ListChecks}
              badge={start.remaining}
            />
            <div className="my-2 border-t border-border-subtle" />
          </>
        )}
        {primaryNav.map((item) => (
          <NavRow
            key={item.to}
            {...item}
            badge={item.to === "/pending" ? pendingCount : undefined}
          />
        ))}
        <div className="my-2 border-t border-border-subtle" />
        {secondaryNav.map((item) => (
          <NavRow key={item.to} {...item} />
        ))}
      </nav>
      <DaemonBlock />
    </aside>
  );
}

function NavRow({ to, label, icon: Icon, badge }: NavItem) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cx(
          "flex items-center justify-between rounded-lg px-3 py-2 text-sm transition-colors",
          isActive
            ? "bg-surface-raised font-medium text-content"
            : "text-content-muted hover:bg-surface-raised hover:text-content",
        )
      }
    >
      <span className="flex items-center gap-2.5">
        <Icon className="size-4 shrink-0 opacity-70" />
        {label}
      </span>
      {badge ? <Badge tone="pending">{badge}</Badge> : null}
    </NavLink>
  );
}

function DaemonBlock() {
  const { data } = useSessionStatus();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const signOut = useSession((s) => s.signOut);

  const unlockedCount = data?.unlocked_vaults.length ?? 0;
  const daemonUp = data?.daemon_up ?? false;

  async function onLockAll() {
    await lockAll();
    qc.invalidateQueries();
  }

  return (
    <div className="m-2 rounded-lg border border-border-subtle bg-surface p-3 text-xs">
      <div className="mb-2 flex items-center gap-2">
        <StateDot tone={daemonUp ? "allow" : "deny"} />
        <span className="font-medium text-content">
          Daemon {daemonUp ? "up" : "down"}
        </span>
      </div>
      <dl className="mb-3 space-y-1 text-content-muted">
        <Row k="Keys in memory" v={unlockedCount > 0 ? "yes" : "no"} />
        <Row k="Vaults unlocked" v={String(unlockedCount)} />
        <Row k="Auto-lock in" v={formatSecs(data?.next_autolock_secs)} />
        <Row k="Re-auth in" v={countdownTo(data?.reauth_deadline ?? null)} />
      </dl>
      <div className="flex gap-2">
        <Button variant="secondary" className="flex-1 px-2 py-1.5 text-xs" onClick={onLockAll}>
          Lock all
        </Button>
        <Button
          variant="ghost"
          className="flex-1 px-2 py-1.5 text-xs"
          onClick={() => {
            signOut();
            navigate("/");
          }}
        >
          Sign out
        </Button>
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between">
      <dt>{k}</dt>
      <dd className="text-content">{v}</dd>
    </div>
  );
}

// Shared page scaffold: a header bar + content area, used by every screen.
export function Page({
  title,
  badge,
  actions,
  children,
}: {
  title: string;
  badge?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border-subtle px-6 py-4">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {badge}
        </div>
        <div className="flex items-center gap-2">{actions}</div>
      </header>
      <div className="flex-1 overflow-auto p-6">{children}</div>
    </div>
  );
}
