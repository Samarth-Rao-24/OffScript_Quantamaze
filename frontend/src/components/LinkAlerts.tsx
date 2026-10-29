import { useCallback, useEffect, useState } from "react";
import { api, type Json } from "../api";
import { useLive } from "../live";
import { Button, ErrorNote, Panel } from "./ui";

const SEV: Record<string, string> = {
  error: "border-reject/40 bg-reject/5 text-reject",
  warn: "border-caution/40 bg-caution/5 text-caution",
  info: "border-rule bg-white text-ink",
};
const KIND: Record<string, string> = {
  MISSING_PACKET: "Missing packet",
  DEPENDENCY_HOLD: "Held for dependency",
  GAP_REPORTED: "Satellite gap report",
  RETRANSMIT_OK: "Recovered",
  CARRIED_OVER: "Carried over",
  REPLANNED: "Re-planned",
};

export default function LinkAlerts() {
  const { state, subscribe, refreshState } = useLive();
  const [d, setD] = useState<Json | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => api.get("/api/delivery").then(setD).catch(() => undefined), []);
  useEffect(() => {
    load();
    return subscribe((e) => {
      if (["alert", "pass_done", "reset", "plan"].includes(e.type)) load();
    });
  }, [load, subscribe]);

  const replan = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post("/api/replan", {});
      await load();
      refreshState();
      window.dispatchEvent(new Event("plan-changed"));
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const gaps = state?.onboard?.gaps;
  const carried: Json[] = d?.carried_over ?? [];
  const delivered = d ? Object.keys(d.delivered).length : 0;
  return (
    <Panel
      title="Missing-packet monitor"
      aside={
        <span className="text-sm text-mute">
          {delivered} command(s) acknowledged · satellite gap reports {gaps?.reports ?? 0} ({gaps?.missing_counters ?? 0} counter(s))
        </span>
      }
    >
      <p className="max-w-4xl text-sm text-mute">
        A frame that gets no acknowledgement is treated as lost. Its dependents are held (never sent ahead of it), it is re-signed with a fresh counter
        while the pass budget allows, and the satellite's counter-gap report is checked against the ground's own transmit ledger.
      </p>
      <ErrorNote error={error} onDismiss={() => setError(null)} />
      {carried.length > 0 && d?.next_pass && (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded border border-caution/40 bg-caution/5 px-3 py-2 text-sm">
          <span>
            <b className="text-caution">Not delivered in pass {d.last_pass_run}:</b>{" "}
            {carried.map((c) => `${c.cmd_id} (${c.reason})`).join("; ")}
          </span>
          <Button busy={busy} onClick={replan}>
            Re-plan passes {d.next_pass}–{d.passes} with QpiAI Opt
          </Button>
        </div>
      )}
      <ul className="mt-3 max-h-80 space-y-1.5 overflow-y-auto pr-1 text-sm">
        {(d?.alerts ?? []).length === 0 && <li className="text-mute">No link alerts yet. Choose a packet-loss drill above and run a pass.</li>}
        {(d?.alerts ?? []).slice(0, 14).map((a: Json) => (
          <li key={a.id} className={`rounded border px-2.5 py-1.5 ${SEV[a.severity] ?? SEV.info}`}>
            <span className="mr-2 font-cond text-xs font-semibold uppercase tracking-wide">{KIND[a.kind] ?? a.kind}</span>
            <span className="text-ink">{a.message}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
