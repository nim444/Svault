// shadcn/ui-style primitives, backed by Radix where it matters (Dialog, Switch,
// Checkbox) and class-variance-authority for variants. The exported API is kept
// stable so the screens don't change. Data (codes, secrets, paths, logs) uses
// `font-mono`; UI text uses the system sans set in styles.css.

import {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
  forwardRef,
  useEffect,
} from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "../lib/utils";

// Back-compat alias — some modules import `cx`.
export const cx = cn;

// ── Button ───────────────────────────────────────────────────────────────────
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md px-4 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        primary: "bg-primary text-primary-foreground shadow-sm hover:bg-primary/90",
        secondary:
          "border border-input bg-transparent text-foreground shadow-sm hover:bg-accent-bg",
        ghost: "text-muted-foreground hover:bg-accent-bg hover:text-foreground",
        danger: "bg-destructive text-white shadow-sm hover:bg-destructive/90",
        dangerOutline:
          "border border-destructive/40 bg-transparent text-destructive/80 shadow-sm hover:border-destructive/60 hover:bg-destructive/10 hover:text-destructive",
      },
    },
    defaultVariants: { variant: "primary" },
  },
);

export function Button({
  variant,
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants>) {
  return (
    <button className={cn(buttonVariants({ variant }), className)} {...props} />
  );
}

// ── Input / Textarea / Select ────────────────────────────────────────────────
const controlBase =
  "w-full rounded-md border border-input bg-input text-sm text-foreground placeholder:text-muted-foreground/60 shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50";

export const Input = forwardRef<
  HTMLInputElement,
  InputHTMLAttributes<HTMLInputElement>
>(function Input({ className, ...props }, ref) {
  return (
    <input ref={ref} className={cn(controlBase, "h-9 px-3 py-1", className)} {...props} />
  );
});

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement>
>(function Textarea({ className, ...props }, ref) {
  return (
    <textarea ref={ref} className={cn(controlBase, "min-h-16 px-3 py-2", className)} {...props} />
  );
});

export function Select({
  className,
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn(controlBase, "h-9 cursor-pointer px-3", className)} {...props}>
      {children}
    </select>
  );
}

// ── Field + help ─────────────────────────────────────────────────────────────
export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="flex items-center gap-1.5 text-sm font-medium text-foreground">
        {label}
        {hint && <HelpDot hint={hint} />}
      </span>
      {children}
    </label>
  );
}

export function HelpDot({ hint }: { hint: string }) {
  return (
    <span
      title={hint}
      className="inline-flex size-4 cursor-help items-center justify-center rounded-full border border-border text-[10px] text-muted-foreground"
    >
      ?
    </span>
  );
}

// ── Card ─────────────────────────────────────────────────────────────────────
export function Card({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={cn("rounded-xl border border-border bg-card", className)}>
      {children}
    </div>
  );
}

// ── Badge ────────────────────────────────────────────────────────────────────
type Tone = "allow" | "deny" | "pending" | "judge" | "neutral";

const toneStyles: Record<Tone, string> = {
  allow: "bg-state-allow/15 text-state-allow border-state-allow/30",
  deny: "bg-state-deny/15 text-state-deny border-state-deny/30",
  pending: "bg-state-pending/15 text-state-pending border-state-pending/30",
  judge: "bg-state-judge/15 text-state-judge border-state-judge/30",
  neutral: "bg-muted text-muted-foreground border-border",
};

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        toneStyles[tone],
      )}
    >
      {children}
    </span>
  );
}

export function TierBadge({ tier }: { tier: string }) {
  const tone: Tone =
    tier === "high" ? "deny" : tier === "medium" ? "pending" : "neutral";
  return <Badge tone={tone}>{tier}</Badge>;
}

// ── Toast ────────────────────────────────────────────────────────────────────
// A transient bottom-right notice that dismisses itself. Render it
// conditionally; `onDone` clears the state that mounted it.
export function Toast({
  tone = "neutral",
  children,
  onDone,
  duration = 2000,
}: {
  tone?: Tone;
  children: ReactNode;
  onDone: () => void;
  duration?: number;
}) {
  useEffect(() => {
    const t = setTimeout(onDone, duration);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div
      className={cn(
        "toast-in fixed bottom-6 right-6 z-50 max-w-sm rounded-lg border px-4 py-2.5 text-sm shadow-lg",
        toneStyles[tone],
        "bg-card",
      )}
    >
      {children}
    </div>
  );
}

export function StateDot({ tone }: { tone: Tone }) {
  return (
    <span
      className="inline-block size-2 rounded-full"
      style={{
        backgroundColor: `var(--state-${tone === "neutral" ? "pending" : tone})`,
      }}
    />
  );
}

// ── Toggle (Radix Switch) ────────────────────────────────────────────────────
export function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
      <SwitchPrimitive.Root
        checked={checked}
        onCheckedChange={onChange}
        className="peer inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 data-[state=checked]:bg-switch-on data-[state=unchecked]:bg-input data-[state=unchecked]:shadow-[inset_0_0_0_1px_var(--border)]"
      >
        <SwitchPrimitive.Thumb className="pointer-events-none block size-4 rounded-full bg-white shadow transition-transform data-[state=checked]:translate-x-4 data-[state=unchecked]:translate-x-0.5" />
      </SwitchPrimitive.Root>
      {label}
    </label>
  );
}

// ── Segmented control ────────────────────────────────────────────────────────
export function Segmented<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="inline-flex rounded-lg border border-border bg-muted p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded-md px-3 py-1.5 text-sm transition-colors",
            value === o.value
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

// ── Checkbox (Radix) ─────────────────────────────────────────────────────────
export function Checkbox({
  checked,
  onChange,
  children,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  children: ReactNode;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
      <CheckboxPrimitive.Root
        checked={checked}
        onCheckedChange={(v) => onChange(v === true)}
        className="flex size-4 shrink-0 items-center justify-center rounded border border-border bg-input focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 data-[state=checked]:border-primary data-[state=checked]:bg-primary"
      >
        <CheckboxPrimitive.Indicator className="text-[10px] leading-none text-primary-foreground">
          ✓
        </CheckboxPrimitive.Indicator>
      </CheckboxPrimitive.Root>
      {children}
    </label>
  );
}

// ── Sub-tab strip ────────────────────────────────────────────────────────────
export function SubTabs<T extends string>({
  value,
  tabs,
  onChange,
}: {
  value: T;
  tabs: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="mb-5 flex gap-1 border-b border-border">
      {tabs.map((t) => (
        <button
          key={t.value}
          type="button"
          onClick={() => onChange(t.value)}
          className={cn(
            "-mb-px border-b-2 px-3 py-2 text-sm transition-colors",
            value === t.value
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground",
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ── Modal + ConfirmDialog (Radix Dialog) ─────────────────────────────────────
export function Modal({
  title,
  onClose,
  children,
  width = "max-w-md",
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  width?: string;
}) {
  return (
    <DialogPrimitive.Root
      open
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
    >
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
        <DialogPrimitive.Content
          aria-describedby={undefined}
          className={cn(
            "fixed left-1/2 top-1/2 z-50 w-full -translate-x-1/2 -translate-y-1/2 rounded-xl border border-border bg-card p-6 shadow-xl",
            width,
          )}
        >
          <DialogPrimitive.Title className="mb-4 text-lg font-semibold">
            {title}
          </DialogPrimitive.Title>
          {children}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

export function ConfirmDialog({
  title,
  message,
  confirmLabel = "Confirm",
  danger,
  onConfirm,
  onCancel,
  busy,
}: {
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  busy?: boolean;
}) {
  return (
    <Modal title={title} onClose={onCancel}>
      <div className="text-sm text-muted-foreground">{message}</div>
      <div className="mt-6 flex justify-end gap-2">
        <Button variant="secondary" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} disabled={busy}>
          {busy ? "Working…" : confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}
