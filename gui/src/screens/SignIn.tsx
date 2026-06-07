import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, KeyRound, LockKeyhole, Usb } from "lucide-react";
import { unlock, unlockTouchid, unlockYubikey, yubikeyPresent } from "../lib/api";
import { useSessionStatus } from "../lib/hooks";
import { useSession } from "../store/session";
import { Button, Card, Input } from "../components/ui";

// Screen 01 — returning-user sign-in. The app launches locked; nothing is
// readable until the master passphrase (or an enrolled Touch ID / YubiKey
// keyslot) unlocks it. One method renders at a time; the others are a
// switcher row. The last method that successfully unlocked is remembered as
// the favorite and pre-selected next launch.
type Method = "passphrase" | "touchid" | "yubikey";

const FAVORITE_KEY = "svault.signin.favorite";

function loadFavorite(): Method | null {
  const v = localStorage.getItem(FAVORITE_KEY);
  return v === "passphrase" || v === "touchid" || v === "yubikey" ? v : null;
}

export default function SignIn() {
  const [method, setMethod] = useState<Method | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [pin, setPin] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { data: status } = useSessionStatus();
  const signIn = useSession((s) => s.signIn);
  const navigate = useNavigate();
  const qc = useQueryClient();

  const touchidAvailable = Boolean(
    status?.touchid_enrolled && status?.touchid_supported,
  );
  const yubikeyAvailable = Boolean(status?.yubikey_enrolled);

  // YubiKey presence is a USB scan — query it on its own slow cadence (only
  // when a key is enrolled), never in the 1s session poll.
  const { data: ykPresent } = useQuery({
    queryKey: ["yubikey-present"],
    queryFn: yubikeyPresent,
    enabled: yubikeyAvailable,
    refetchInterval: 3000,
  });

  const available: Method[] = [
    ...(touchidAvailable ? (["touchid"] as const) : []),
    ...(yubikeyAvailable ? (["yubikey"] as const) : []),
    "passphrase",
  ];

  // Pick the starting method once the session status is known: the stored
  // favorite if it's still available, else Touch ID, else passphrase.
  useEffect(() => {
    if (method !== null || !status) return;
    const fav = loadFavorite();
    if (fav && available.includes(fav)) setMethod(fav);
    else if (touchidAvailable) setMethod("touchid");
    else setMethod("passphrase");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  async function complete(used: Method) {
    localStorage.setItem(FAVORITE_KEY, used);
    signIn();
    await qc.invalidateQueries();
    navigate("/vaults");
  }

  async function run(used: Method, fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await complete(used);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    await run("passphrase", async () => {
      await unlock(passphrase);
      setPassphrase("");
    });
  }

  const active = method ?? "passphrase";
  const others = available.filter((m) => m !== active);

  return (
    <div className="flex h-full items-center justify-center p-8">
      <Card className="w-full max-w-sm p-7">
        <div className="flex flex-col items-center text-center">
          <div className="flex size-12 items-center justify-center rounded-2xl border border-border bg-surface-sunken">
            <LockKeyhole className="size-5 text-content-muted" />
          </div>
          <h1 className="mt-3 text-2xl font-semibold tracking-tight">Svault</h1>
          <p className="mt-1 text-sm text-content-muted">Welcome back</p>
        </div>

        <div className="mt-6">
          {active === "passphrase" && (
            <form onSubmit={onSubmit} className="flex flex-col gap-3">
              <Input
                type="password"
                autoFocus
                placeholder="Master passphrase"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
              />
              <Button type="submit" disabled={busy || !passphrase}>
                {busy ? "Unlocking…" : "Unlock"}
              </Button>
            </form>
          )}

          {active === "touchid" && (
            <div className="flex flex-col items-center gap-4 py-2">
              <button
                type="button"
                disabled={busy}
                onClick={() => run("touchid", unlockTouchid)}
                className="flex size-20 items-center justify-center rounded-full border border-state-judge/40 bg-state-judge/15 text-state-judge transition-colors hover:border-state-judge hover:bg-state-judge/25 disabled:opacity-50"
                aria-label="Unlock with Touch ID"
              >
                <Fingerprint className="size-9" />
              </button>
              <p className="text-sm text-content-muted">
                {busy ? "Touch the sensor…" : "Unlock with Touch ID"}
              </p>
            </div>
          )}

          {active === "yubikey" &&
            (ykPresent ? (
              <div className="flex flex-col gap-3">
                <Input
                  type="password"
                  placeholder="YubiKey PIN (blank if none)"
                  value={pin}
                  onChange={(e) => setPin(e.target.value)}
                />
                <Button
                  disabled={busy}
                  onClick={() =>
                    run("yubikey", async () => {
                      await unlockYubikey(pin || null);
                      setPin("");
                    })
                  }
                  className="flex items-center justify-center gap-2"
                >
                  <Usb className="size-4" />
                  {busy ? "Waiting for touch…" : "Touch your YubiKey"}
                </Button>
              </div>
            ) : (
              <p className="rounded-lg border border-dashed border-border p-4 text-center text-xs text-content-muted">
                Plug in your enrolled YubiKey — it's detected automatically.
              </p>
            ))}
        </div>

        {error && (
          <p className="mt-4 text-center text-sm text-state-deny">{error}</p>
        )}

        {others.length > 0 && (
          <div className="mt-6 border-t border-border-subtle pt-4">
            <div className="flex items-center justify-center gap-2">
              {others.map((m) => (
                <MethodChip
                  key={m}
                  method={m}
                  disabled={busy}
                  onClick={() => {
                    setError(null);
                    setMethod(m);
                  }}
                />
              ))}
            </div>
          </div>
        )}

        <button
          type="button"
          onClick={() => navigate("/recover")}
          className="mt-5 w-full text-center text-xs text-content-muted underline-offset-2 hover:underline"
        >
          Lost your passphrase? Use recovery code
        </button>
      </Card>
    </div>
  );
}

const METHOD_META: Record<
  Method,
  { label: string; Icon: typeof KeyRound }
> = {
  passphrase: { label: "Passphrase", Icon: KeyRound },
  touchid: { label: "Touch ID", Icon: Fingerprint },
  yubikey: { label: "YubiKey", Icon: Usb },
};

function MethodChip({
  method,
  disabled,
  onClick,
}: {
  method: Method;
  disabled: boolean;
  onClick: () => void;
}) {
  const { label, Icon } = METHOD_META[method];
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className="flex items-center gap-1.5 rounded-full border border-border px-3 py-1.5 text-xs text-content-muted transition-colors hover:bg-surface-sunken hover:text-content disabled:opacity-50"
    >
      <Icon className="size-3.5" />
      {label}
    </button>
  );
}
