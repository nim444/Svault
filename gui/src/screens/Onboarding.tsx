import { useState } from "react";
import { Fingerprint } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  enrollTouchid,
  enrollYubikey,
  initMaster,
  touchidStatus,
  yubikeyPresent,
} from "../lib/api";
import { useSession } from "../store/session";
import { Button, Card, Checkbox, Field, Input } from "../components/ui";

// Screen 02 — first-run onboarding. Linear 4-step stepper; the important steps
// (disclaimer, recovery code) can't be skipped.
type Step = 1 | 2 | 3 | 4;

export default function Onboarding() {
  const [splashDone, setSplashDone] = useState(false);
  const [step, setStep] = useState<Step>(1);
  const [recoveryCode, setRecoveryCode] = useState("");
  const navigate = useNavigate();
  const qc = useQueryClient();
  const signIn = useSession((s) => s.signIn);

  async function finish() {
    signIn();
    await qc.invalidateQueries();
    navigate("/vaults");
  }

  // First-run splash, shown once before setup. Onboarding only renders when no
  // master exists, so returning users never see this.
  if (!splashDone) return <Splash onStart={() => setSplashDone(true)} />;

  return (
    <div className="flex h-full items-center justify-center p-8">
      <Card className="w-full max-w-md p-8 shadow-xl">
        <div className="mb-6">
          <div className="text-lg font-semibold tracking-tight">Svault</div>
          <div className="text-xs text-muted-foreground">First-run setup</div>
        </div>
        <Stepper step={step} />
        {step === 1 && <StepTerms onNext={() => setStep(2)} />}
        {step === 2 && (
          <StepPassphrase
            onCreated={(code) => {
              setRecoveryCode(code);
              setStep(3);
            }}
          />
        )}
        {step === 3 && (
          <StepRecovery code={recoveryCode} onNext={() => setStep(4)} />
        )}
        {step === 4 && <StepExtraUnlock onDone={finish} />}
      </Card>
    </div>
  );
}

function Splash({ onStart }: { onStart: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center p-8 text-center">
      <h1 className="splash-title text-6xl font-semibold tracking-tight">
        Svault
      </h1>
      <p className="splash-tagline mt-3 text-sm text-muted-foreground">
        secret access layer for AI agents
      </p>
      <Button className="splash-cta mt-12 px-8" onClick={onStart}>
        Get Started
      </Button>
    </div>
  );
}

const STEP_LABELS = ["Terms", "Passphrase", "Recovery", "Unlock methods"];

function Stepper({ step }: { step: Step }) {
  return (
    <div className="mb-6">
      <div className="flex items-center gap-1.5">
        {[1, 2, 3, 4].map((n) => (
          <span
            key={n}
            className={
              "h-1 flex-1 rounded-full " +
              (n <= step ? "bg-primary" : "bg-border")
            }
          />
        ))}
      </div>
      <div className="mt-2 text-xs text-muted-foreground">
        Step {step} of 4 · {STEP_LABELS[step - 1]}
      </div>
    </div>
  );
}

function StepTerms({ onNext }: { onNext: () => void }) {
  const [understood, setUnderstood] = useState(false);
  return (
    <div className="flex flex-col gap-4">
      <h2 className="text-lg font-semibold">Before you start</h2>
      <div className="max-h-48 overflow-auto rounded-lg border border-border-subtle bg-surface-sunken p-3 text-sm text-content-muted">
        <p className="mb-2">
          Svault is the principled way to give <em>cooperative</em> AI agents
          structured, policy-gated, audited access to your secrets.
        </p>
        <p className="mb-2">
          It is <strong>not</strong> a sandbox against a hostile process running
          as your own user. A same-UID process that wants to read the unlocked
          daemon's memory directly is outside Svault's threat model — this is the
          documented same-UID boundary.
        </p>
        <p>
          One master passphrase unlocks every vault. Keys live only in memory
          while unlocked and are zeroized on lock.
        </p>
      </div>
      <Checkbox checked={understood} onChange={setUnderstood}>
        I understand the same-UID boundary
      </Checkbox>
      <Button disabled={!understood} onClick={onNext}>
        Continue
      </Button>
    </div>
  );
}

function StepPassphrase({ onCreated }: { onCreated: (code: string) => void }) {
  const [pp, setPp] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mismatch = confirm.length > 0 && pp !== confirm;

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const res = await initMaster(pp);
      onCreated(res.recovery_code);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <h2 className="text-lg font-semibold">Set your master passphrase</h2>
      <p className="text-sm text-content-muted">
        Argon2id, 64&nbsp;MB. One passphrase unlocks every vault.
      </p>
      <Input
        type="password"
        autoFocus
        placeholder="Master passphrase"
        value={pp}
        onChange={(e) => setPp(e.target.value)}
      />
      <StrengthMeter value={pp} />
      <Input
        type="password"
        placeholder="Confirm passphrase"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
      />
      {mismatch && <p className="text-xs text-state-deny">Passphrases don't match.</p>}
      {error && <p className="text-sm text-state-deny">{error}</p>}
      <Button disabled={busy || !pp || mismatch || pp !== confirm} onClick={create}>
        {busy ? "Setting…" : "Set passphrase"}
      </Button>
    </div>
  );
}

function StepRecovery({ code, onNext }: { code: string; onNext: () => void }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  return (
    <div className="flex flex-col gap-4">
      <h2 className="text-lg font-semibold">Your master recovery code</h2>
      <p className="text-sm font-medium text-state-deny">
        Shown once, never stored in plaintext. It recovers your master if you
        forget the passphrase and opens every vault + the keyring.
      </p>
      <div className="rounded-lg border border-state-allow/40 bg-state-allow/10 p-3 text-center font-mono text-sm tracking-wide text-content">
        {code}
      </div>
      <Button
        variant="secondary"
        className="w-full"
        onClick={async () => {
          await writeText(code);
          setCopied(true);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </Button>
      <Checkbox checked={saved} onChange={setSaved}>
        <span className="font-semibold">I've stored this somewhere safe</span>
      </Checkbox>
      <Button
        disabled={!saved}
        className="disabled:bg-muted disabled:text-muted-foreground disabled:opacity-100"
        onClick={onNext}
      >
        Continue
      </Button>
    </div>
  );
}

function StepExtraUnlock({ onDone }: { onDone: () => void }) {
  // Touch ID (macOS) — offered first on supported machines; YubiKey below.
  const { data: tid, refetch: refetchTid } = useQuery({
    queryKey: ["touchid"],
    queryFn: touchidStatus,
  });
  const [tidBusy, setTidBusy] = useState(false);
  const [tidError, setTidError] = useState<string | null>(null);

  const { data: present, refetch } = useQuery({
    queryKey: ["yubikey-present"],
    queryFn: yubikeyPresent,
    refetchInterval: 3000,
  });
  const [pin, setPin] = useState("");
  const [noPin, setNoPin] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ykEnrolled, setYkEnrolled] = useState(false);

  // Guard: most keys have a PIN. Require either a PIN, or an explicit "this key
  // has no PIN" acknowledgment, before we ask for a touch.
  const ready = pin.trim().length > 0 || noPin;

  async function enrollTid() {
    setTidBusy(true);
    setTidError(null);
    try {
      await enrollTouchid();
      await refetchTid();
    } catch (err) {
      setTidError(String(err));
    } finally {
      setTidBusy(false);
    }
  }

  async function enroll() {
    setBusy(true);
    setError(null);
    try {
      await enrollYubikey(pin.trim() ? pin : null);
      setYkEnrolled(true);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  const anyEnrolled = Boolean(tid?.enrolled) || ykEnrolled;

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-base font-semibold">Extra unlock methods</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Optional. Add Touch ID or a YubiKey as an alternative to typing the
          master passphrase — it always keeps working. You can also do this
          later in Settings.
        </p>
      </div>

      {tid?.supported && (
        <div className="flex flex-col gap-3 rounded-lg border border-border bg-muted/40 p-4">
          {tid.enrolled ? (
            <div className="flex items-center gap-2 text-sm text-state-allow">
              <span className="size-2 rounded-full bg-state-allow" />
              Touch ID enrolled — a fingerprint now unlocks Svault
            </div>
          ) : (
            <>
              <div className="flex items-center gap-2 text-sm font-medium">
                <Fingerprint className="size-4" />
                Touch ID
              </div>
              <p className="text-xs text-muted-foreground">
                Unlock with your Mac's fingerprint reader. The wrapping key is
                kept in your login keychain.
              </p>
              <Button
                disabled={tidBusy}
                onClick={enrollTid}
                className="flex items-center justify-center gap-2"
              >
                <Fingerprint className="size-4" />
                {tidBusy ? "Touch the sensor…" : "Enroll Touch ID"}
              </Button>
            </>
          )}
          {tidError && <p className="text-sm text-state-deny">{tidError}</p>}
        </div>
      )}

      {ykEnrolled ? (
        <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/40 p-4 text-sm text-state-allow">
          <span className="size-2 rounded-full bg-state-allow" />
          YubiKey enrolled — a touch now unlocks Svault
        </div>
      ) : present ? (
        <div className="flex flex-col gap-3 rounded-lg border border-border bg-muted/40 p-4">
          <div className="flex items-center gap-2 text-sm text-state-allow">
            <span className="size-2 rounded-full bg-state-allow" />
            YubiKey detected
          </div>
          <Field label="YubiKey PIN">
            <Input
              type="password"
              placeholder="Enter your key's PIN"
              value={pin}
              disabled={noPin}
              onChange={(e) => setPin(e.target.value)}
            />
          </Field>
          <Checkbox checked={noPin} onChange={setNoPin}>
            This key has no PIN
          </Checkbox>
          {!ready && (
            <p className="text-xs text-state-pending">
              Enter your PIN, or confirm the key has none, before touching it.
            </p>
          )}
          {ready && !busy && (
            <p className="text-xs text-muted-foreground">
              You'll be asked to touch your key <strong>twice</strong> — once to
              register it, once to confirm.
            </p>
          )}
          <Button disabled={busy || !ready} onClick={enroll}>
            {busy ? "Touch your key twice…" : "Enroll YubiKey"}
          </Button>
        </div>
      ) : (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-dashed border-border p-4">
          <p className="text-sm text-muted-foreground">
            No YubiKey detected. Plug one in, then rescan.
          </p>
          <Button variant="secondary" className="shrink-0" onClick={() => refetch()}>
            Rescan
          </Button>
        </div>
      )}

      {error && <p className="text-sm text-state-deny">{error}</p>}

      {anyEnrolled ? (
        <Button className="self-stretch" onClick={onDone}>
          Finish
        </Button>
      ) : (
        <Button variant="ghost" className="self-center" onClick={onDone}>
          Skip for now
        </Button>
      )}
    </div>
  );
}

function StrengthMeter({ value }: { value: string }) {
  // Heuristic only — the real entropy floor is enforced by core on init.
  let score = 0;
  if (value.length >= 8) score++;
  if (value.length >= 14) score++;
  if (/[0-9]/.test(value) && /[a-zA-Z]/.test(value)) score++;
  if (/[^a-zA-Z0-9]/.test(value)) score++;
  const labels = ["", "weak", "fair", "good", "strong"];
  const tone = score >= 4 ? "allow" : score >= 2 ? "pending" : "deny";
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-1.5 flex-1 gap-1">
        {[1, 2, 3, 4].map((n) => (
          <span
            key={n}
            className="flex-1 rounded-full"
            style={{
              backgroundColor:
                n <= score ? `var(--state-${tone})` : "var(--border)",
            }}
          />
        ))}
      </div>
      <span className="w-12 text-right text-xs text-content-muted">
        {value ? labels[score] : ""}
      </span>
    </div>
  );
}
