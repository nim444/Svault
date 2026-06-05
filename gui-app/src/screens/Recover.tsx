import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { recoverMaster } from "../lib/api";
import { Button, Card, Input } from "../components/ui";

// Signed-out master recovery: reset a forgotten master passphrase with the
// one-time master recovery code, then return to sign-in.
export default function Recover() {
  const navigate = useNavigate();
  const [code, setCode] = useState("");
  const [pp, setPp] = useState("");
  const [pp2, setPp2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await recoverMaster(code, pp);
      setDone(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center p-8">
      <Card className="w-full max-w-sm p-7">
        <h1 className="text-xl font-semibold">Recover with code</h1>
        <p className="mt-1 text-sm text-content-muted">
          Use your master recovery code to set a new passphrase. It opens every
          vault and the keyring.
        </p>
        {done ? (
          <div className="mt-6">
            <p className="text-sm text-state-allow">
              Master reset. Sign in with your new passphrase.
            </p>
            <Button className="mt-4 w-full" onClick={() => navigate("/")}>
              Back to sign in
            </Button>
          </div>
        ) : (
          <div className="mt-6 flex flex-col gap-3">
            <Input
              placeholder="Master recovery code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
            <Input
              type="password"
              placeholder="New master passphrase"
              value={pp}
              onChange={(e) => setPp(e.target.value)}
            />
            <Input
              type="password"
              placeholder="Confirm passphrase"
              value={pp2}
              onChange={(e) => setPp2(e.target.value)}
            />
            {error && <p className="text-sm text-state-deny">{error}</p>}
            <Button disabled={busy || !code || !pp || pp !== pp2} onClick={submit}>
              {busy ? "Recovering…" : "Reset passphrase"}
            </Button>
            <button
              type="button"
              onClick={() => navigate("/")}
              className="text-center text-xs text-content-muted hover:underline"
            >
              Back to sign in
            </button>
          </div>
        )}
      </Card>
    </div>
  );
}
