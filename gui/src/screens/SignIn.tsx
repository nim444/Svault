import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint } from "lucide-react";
import { unlock, unlockTouchid, unlockYubikey, yubikeyPresent } from "../lib/api";
import { useSessionStatus } from "../lib/hooks";
import { useSession } from "../store/session";
import { Button, Card, Input } from "../components/ui";

// Screen 01 — returning-user sign-in. The app launches locked; nothing is
// readable until the master passphrase (or an enrolled YubiKey) unlocks it.
export default function SignIn() {
  const [passphrase, setPassphrase] = useState("");
  const [pin, setPin] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { data: status } = useSessionStatus();
  // YubiKey presence is a USB scan — query it on its own slow cadence (only when
  // a key is enrolled), never in the 1s session poll.
  const { data: ykPresent } = useQuery({
    queryKey: ["yubikey-present"],
    queryFn: yubikeyPresent,
    enabled: status?.yubikey_enrolled ?? false,
    refetchInterval: 3000,
  });
  const signIn = useSession((s) => s.signIn);
  const navigate = useNavigate();
  const qc = useQueryClient();

  async function complete() {
    signIn();
    await qc.invalidateQueries();
    navigate("/vaults");
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await unlock(passphrase);
      setPassphrase("");
      await complete();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onTouchid() {
    setBusy(true);
    setError(null);
    try {
      await unlockTouchid();
      await complete();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onYubikey() {
    setBusy(true);
    setError(null);
    try {
      await unlockYubikey(pin || null);
      setPin("");
      await complete();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center p-8">
      <Card className="w-full max-w-sm p-7">
        <h1 className="text-2xl font-semibold tracking-tight">Svault</h1>
        <p className="mt-1 text-sm text-content-muted">Welcome back</p>

        <form onSubmit={onSubmit} className="mt-6 flex flex-col gap-3">
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

        {status?.touchid_enrolled && status?.touchid_supported && (
          <>
            <Divider />
            <Button
              variant="secondary"
              onClick={onTouchid}
              disabled={busy}
              className="flex items-center justify-center gap-2"
            >
              <Fingerprint className="size-4" />
              Unlock with Touch ID
            </Button>
          </>
        )}

        {status?.yubikey_enrolled && (
          <>
            <Divider />
            {ykPresent ? (
              <div className="flex flex-col gap-2">
                <Input
                  type="password"
                  placeholder="YubiKey PIN (blank if none)"
                  value={pin}
                  onChange={(e) => setPin(e.target.value)}
                />
                <Button variant="secondary" onClick={onYubikey} disabled={busy}>
                  Touch your YubiKey
                </Button>
              </div>
            ) : (
              <p className="text-center text-xs text-content-muted">
                Plug in your enrolled YubiKey to use it.
              </p>
            )}
          </>
        )}

        {error && <p className="mt-4 text-sm text-state-deny">{error}</p>}

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

function Divider() {
  return (
    <div className="my-5 flex items-center gap-3 text-xs text-content-muted">
      <span className="h-px flex-1 bg-border-subtle" />
      or
      <span className="h-px flex-1 bg-border-subtle" />
    </div>
  );
}
