import { useEffect, useState } from "react";
import { api, short } from "./api";
import { useLive } from "./live";
import Planner from "./screens/Planner";
import Uplink from "./screens/Uplink";
import AttackLab from "./screens/AttackLab";
import Resources from "./screens/Resources";
import Evidence from "./screens/Evidence";

// The five screens follow the demo order, so the rail numbers them.
const SCREENS = [
  { id: "planner", name: "Pass planner", hint: "QpiAI Opt schedules the uplink", C: Planner },
  { id: "uplink", name: "Live uplink", hint: "Sign, transmit, verify", C: Uplink },
  { id: "attacks", name: "Attack lab", hint: "Hostile frames, real verifier", C: AttackLab },
  { id: "resources", name: "Resource budget", hint: "Bytes, latency, memory", C: Resources },
  { id: "evidence", name: "Evidence", hint: "Logs, job IDs, bundle", C: Evidence },
] as const;

function useHashRoute(): [string, (id: string) => void] {
  const read = () => location.hash.replace("#/", "") || "planner";
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const f = () => setRoute(read());
    window.addEventListener("hashchange", f);
    return () => window.removeEventListener("hashchange", f);
  }, []);
  return [route, (id) => (location.hash = `#/${id}`)];
}

function Telemetry() {
  const { state, connected } = useLive();
  const o = state?.onboard;
  const cfg = state?.config;
  const flood = o?.flood;
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-1 border-b border-rule bg-panel px-5 py-2 text-sm">
      <span className="flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${connected ? "bg-accept" : "bg-reject"}`} aria-hidden />
        <span className="text-mute">{connected ? "Live link to backend" : "Backend unreachable: start the API"}</span>
      </span>
      {o && (
        <>
          <span>
            <span className="text-mute">Spacecraft </span>
            <b className="font-cond">SAT-{o.sat_id}</b>
          </span>
          <span>
            <span className="text-mute">Last accepted counter </span>
            <b className="font-cond tabular-nums">{o.last_counter}</b>
          </span>
          <span>
            <span className="text-mute">Pass </span>
            <b className="font-cond">#{o.pass_index}</b>
            <span className="text-mute"> nonce </span>
            <code className="font-mono text-xs">{short(o.pass_nonce, 6)}</code>
          </span>
          <span className={flood?.locked ? "font-semibold text-reject" : ""}>
            <span className={flood?.locked ? "" : "text-mute"}>Flood guard </span>
            <b className="font-cond tabular-nums">
              {flood?.failures}/{flood?.limit}
            </b>
            {flood?.locked && " locked"}
          </span>
        </>
      )}
      {cfg && (
        <span className="ml-auto flex gap-3 text-xs">
          <span className={cfg.opt_key_configured ? "text-accept" : "text-reject"}>
            {cfg.opt_key_configured ? "✓" : "✗"} Opt key
          </span>
          <span className={cfg.qcloud_key_configured ? "text-accept" : "text-reject"}>
            {cfg.qcloud_key_configured ? "✓" : "✗"} QCloud key
          </span>
        </span>
      )}
    </div>
  );
}

export default function App() {
  const [route, go] = useHashRoute();
  const [resetting, setResetting] = useState(false);
  const { refreshState } = useLive();
  const active = SCREENS.find((s) => s.id === route) ?? SCREENS[0];
  const Screen = active.C;
  return (
    <div className="min-h-screen md:grid md:grid-cols-[15.5rem_1fr]">
      <nav className="border-b border-rule bg-ink text-white md:sticky md:top-0 md:h-screen md:border-b-0" aria-label="Screens">
        <div className="px-5 pb-4 pt-5">
          <div className="font-cond text-2xl font-bold leading-none">Q-Uplink</div>
          <div className="mt-1 text-sm text-white/70">Quantum-safe satellite command authentication</div>
        </div>
        <ol className="flex gap-1 overflow-x-auto px-3 pb-3 md:block md:space-y-1 md:overflow-visible">
          {SCREENS.map((s, i) => {
            const on = s.id === active.id;
            return (
              <li key={s.id} className="shrink-0">
                <button
                  onClick={() => go(s.id)}
                  aria-current={on ? "page" : undefined}
                  className={`grid w-full grid-cols-[1.5rem_1fr] items-baseline rounded px-2 py-2 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-white ${on ? "bg-white text-ink" : "text-white/85 hover:bg-white/10"}`}
                >
                  <span className="font-cond text-lg font-bold">{i + 1}</span>
                  <span>
                    <span className="block font-semibold leading-tight">{s.name}</span>
                    <span className={`hidden text-xs md:block ${on ? "text-mute" : "text-white/60"}`}>{s.hint}</span>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
        <div className="hidden px-5 pt-4 md:block">
          <button
            className="text-sm text-white/70 underline-offset-2 hover:text-white hover:underline disabled:opacity-50"
            disabled={resetting}
            onClick={async () => {
              if (!confirm("Reset onboard state for a clean demo run? Logs are archived, keys are kept.")) return;
              setResetting(true);
              try {
                await api.post("/api/reset");
                await refreshState();
              } finally {
                setResetting(false);
              }
            }}
          >
            {resetting ? "Resetting…" : "Reset demo state"}
          </button>
          <p className="mt-6 text-xs leading-relaxed text-white/55">
            Falcon-512 signed frames with a monotonic counter, a QRNG pass nonce and an onboard flood guard. Software-only build: timings are emulated host measurements.
          </p>
        </div>
      </nav>
      <div className="min-w-0">
        <Telemetry />
        <main className="mx-auto max-w-[88rem] px-4 py-5 md:px-6">
          <Screen />
        </main>
      </div>
    </div>
  );
}
