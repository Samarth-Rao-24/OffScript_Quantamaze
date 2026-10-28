import { useState, type ReactNode } from "react";
import { REASON_TEXT, short, type Step } from "../api";

export function Panel({ title, aside, children, className = "", tone = "plain" }: {
  title?: ReactNode;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
  tone?: "plain" | "quiet";
}) {
  return (
    <section className={`${tone === "plain" ? "bg-panel border border-rule" : "bg-transparent"} rounded-md ${className}`}>
      {(title || aside) && (
        <header className="flex flex-wrap items-baseline justify-between gap-2 px-4 pt-3 pb-2">
          {title && <h2 className="font-cond text-lg font-semibold text-ink tracking-tight">{title}</h2>}
          {aside && <div className="text-sm text-mute">{aside}</div>}
        </header>
      )}
      <div className="px-4 pb-4">{children}</div>
    </section>
  );
}

export function Button({ children, onClick, disabled, kind = "primary", busy, title, type = "button" }: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  kind?: "primary" | "secondary" | "danger" | "quantum";
  busy?: boolean;
  title?: string;
  type?: "button" | "submit";
}) {
  const styles = {
    primary: "bg-ink text-white hover:bg-[#1f3560]",
    secondary: "bg-white text-ink border border-rule hover:border-ink",
    danger: "bg-reject text-white hover:bg-[#a8302a]",
    quantum: "bg-quantum text-white hover:bg-[#4a38bd]",
  }[kind];
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled || busy}
      className={`inline-flex items-center gap-2 rounded px-3.5 py-2 text-sm font-semibold transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-quantum disabled:cursor-not-allowed disabled:opacity-45 ${styles}`}
    >
      {busy && <span className="h-3 w-3 animate-spin rounded-full border-2 border-current border-r-transparent" aria-hidden />}
      {children}
    </button>
  );
}

export function VerdictTag({ verdict, reason }: { verdict?: string; reason?: string }) {
  if (!verdict) return <span className="text-mute">—</span>;
  const ok = verdict === "ACCEPT";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-sm font-semibold ${ok ? "bg-accept/10 text-accept" : "bg-reject/10 text-reject"}`}
      title={reason ? REASON_TEXT[reason] : undefined}
    >
      <span aria-hidden>{ok ? "✓" : "✗"}</span>
      {ok ? "Accepted" : "Rejected"}
      {reason && reason !== "OK" && <code className="font-mono text-xs">{reason}</code>}
    </span>
  );
}

export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return <code className="font-mono text-[0.8rem] text-ink break-all" title={title}>{children}</code>;
}

export function CopyId({ value, empty = "none recorded" }: { value?: string | null; empty?: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-mute italic">{empty}</span>;
  return (
    <button
      type="button"
      className="group inline-flex items-center gap-1 rounded text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-quantum"
      onClick={() => {
        navigator.clipboard?.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
      title="Copy full ID"
    >
      <Mono>{short(value, 12)}</Mono>
      <span className="text-xs text-mute group-hover:text-ink">{copied ? "copied" : "copy"}</span>
    </button>
  );
}

export function StepLadder({ steps, animate = false }: { steps?: Step[]; animate?: boolean }) {
  if (!steps?.length) return <p className="text-sm text-mute">No frame verified yet.</p>;
  return (
    <ol className="space-y-1">
      {steps.map((s, i) => {
        const tone =
          s.status === "pass" ? "border-accept/40 bg-accept/5" : s.status === "fail" ? "border-reject/60 bg-reject/10" : "border-rule bg-transparent opacity-50";
        return (
          <li
            key={s.name}
            className={`grid grid-cols-[1.6rem_1fr_auto] items-start gap-2 rounded border px-2 py-1.5 ${tone} ${animate ? "ladder-in" : ""}`}
            style={animate ? { animationDelay: `${i * 110}ms` } : undefined}
          >
            <span className="font-cond text-sm font-semibold text-mute">{s.step ?? "·"}</span>
            <div className="min-w-0">
              <div className="text-sm font-medium text-ink">{s.label}</div>
              {s.detail && <div className="truncate text-xs text-mute" title={s.detail}>{s.detail}</div>}
            </div>
            <span className={`text-sm font-semibold ${s.status === "pass" ? "text-accept" : s.status === "fail" ? "text-reject" : "text-mute"}`}>
              {s.status === "pass" ? "✓" : s.status === "fail" ? "✗" : "skipped"}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

export function ErrorNote({ error, onDismiss }: { error: string | null; onDismiss?: () => void }) {
  if (!error) return null;
  return (
    <div role="alert" className="flex items-start justify-between gap-3 rounded border border-reject/40 bg-reject/5 px-3 py-2 text-sm text-reject">
      <span>{error}</span>
      {onDismiss && (
        <button className="text-mute hover:text-ink" onClick={onDismiss} aria-label="Dismiss">
          ✕
        </button>
      )}
    </div>
  );
}

export function Fact({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div title={hint}>
      <dt className="text-xs text-mute">{label}</dt>
      <dd className="font-cond text-xl font-semibold text-ink tabular-nums">{children}</dd>
    </div>
  );
}

export function Provenance({ kind }: { kind: "cloud" | "hardware" | "local" | "dev" | "fixture" | "emulated" | string }) {
  const map: Record<string, [string, string]> = {
    hardware: ["Quantum hardware", "bg-quantum text-white"],
    cloud: ["QCloud simulator", "bg-quantum/15 text-quantum"],
    local: ["Local simulation", "bg-caution/15 text-caution"],
    dev: ["Development only", "bg-reject/10 text-reject"],
    provisioning: ["Pre-launch provisioning", "bg-ink/10 text-ink"],
    fixture: ["Test fixture", "bg-reject/10 text-reject"],
    emulated: ["Emulated host", "bg-ink/10 text-ink"],
    platform: ["QpiAI Opt platform job", "bg-ink text-white"],
    opt_local: ["QpiAI Opt local solver", "bg-ink/10 text-ink"],
  };
  const [label, cls] = map[kind] ?? [kind, "bg-ink/10 text-ink"];
  return <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${cls}`}>{label}</span>;
}

export function randomnessKind(cls?: string | null): string {
  if (!cls) return "dev";
  if (cls === "quantum-hardware") return "hardware";
  if (cls.startsWith("qcloud")) return "cloud";
  if (cls.startsWith("local")) return "local";
  return "dev";
}
