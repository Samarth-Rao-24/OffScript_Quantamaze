import { useEffect, useMemo, useState } from "react";
import { api, fmtBytes, REASON_TEXT, short, type Json } from "../api";
import { useLive } from "../live";
import QrngInspector from "../components/QrngInspector";
import { Button, CopyId, ErrorNote, Mono, Panel, Provenance, StepLadder, VerdictTag, randomnessKind } from "../components/ui";

const DEVICES = [
  ["QpiAI-QSV-Local", "QpiAI local simulator (no credits)"],
  ["QpiAI-QSV-Simulator", "QCloud statevector simulator"],
  ["QpiAI-Indus-1", "Indus-1 quantum computer"],
];

export default function Uplink() {
  const { state, events, subscribe } = useLive();
  const [plan, setPlan] = useState<Json | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [device, setDevice] = useState("QpiAI-Indus-1");
  const [pace, setPace] = useState(450);
  const [flight, setFlight] = useState<Json | null>(null); // frame currently crossing the link
  const [lastVerdict, setLastVerdict] = useState<Json | null>(null);

  useEffect(() => {
    api.get("/api/plan").then((p) => setPlan(p?.opt ? p : null));
    api.get("/api/config").then((c) => setDevice(c.config.qrng_device));
  }, []);

  useEffect(
    () =>
      subscribe((e) => {
        if (e.type !== "frame") return;
        if (e.phase === "tx") setFlight({ ...e, key: `${e.ts}-${e.label}` });
        if (e.phase === "verdict") setLastVerdict({ ...e, key: `${e.ts}-${e.label}` });
      }),
    [subscribe],
  );

  const frames = useMemo(() => events.filter((e) => e.type === "frame" && e.phase === "verdict").slice(-14).reverse(), [events]);
  const refused = useMemo(() => events.filter((e) => e.type === "frame" && e.phase === "refused").slice(-3).reverse(), [events]);
  const signed = useMemo(() => events.filter((e) => e.type === "frame" && e.phase === "signed").slice(-8).reverse(), [events]);

  const g = state?.ground;
  const nonceInfo = g?.nonce_history?.[g.nonce_history.length - 1];
  const link = state?.link;
  const pool = state?.qrng;

  const act = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key);
    setError(null);
    try {
      await fn();
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  };

  const latest = lastVerdict ?? frames[0] ?? null;
  const shown = latest?.result;
  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="max-w-3xl">
          <h1 className="font-cond text-3xl font-bold">Live uplink</h1>
          <p className="text-mute">
            Each pass starts with a signed PASS_OPEN carrying a fresh QRNG nonce. Every command in that pass is signed over its header, body and
            that nonce, crosses the byte-limited link, and is checked by the onboard verifier running in its own process.
          </p>
        </div>
        <label className="text-sm text-mute">
          Animation pace{" "}
          <select value={pace} onChange={(e) => setPace(Number(e.target.value))}>
            <option value={0}>instant</option>
            <option value={250}>fast</option>
            <option value={450}>presenter</option>
            <option value={800}>slow</option>
          </select>
        </label>
      </header>
      <ErrorNote error={error} onDismiss={() => setError(null)} />

      <Panel
        title="Pass nonce"
        aside={nonceInfo && <Provenance kind={nonceInfo.pass === 0 ? "provisioning" : randomnessKind(nonceInfo.randomness_class)} />}
      >
        <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
          <div>
            <Mono>{g?.current_nonce ?? "—"}</Mono>
            <dl className="mt-2 grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
              <div>
                <dt className="inline text-mute">Installed for </dt>
                <dd className="inline">{nonceInfo?.pass === 0 ? "provisioning (pre-launch genesis)" : `pass ${nonceInfo?.pass ?? "ad hoc"}, window ${nonceInfo?.window}`}</dd>
              </div>
              <div>
                <dt className="inline text-mute">QCloud job </dt>
                <dd className="inline"><CopyId value={nonceInfo?.job_id} empty={nonceInfo?.pass === 0 ? "n/a" : "none (QpiAI local simulator)"} /></dd>
              </div>
              <div>
                <dt className="inline text-mute">Device </dt>
                <dd className="inline">{nonceInfo?.device ?? "—"}</dd>
              </div>
              <div>
                <dt className="inline text-mute">Derivation </dt>
                <dd className="inline">SHA-256(OS 32 B, QCloud counts, job ID, pass)</dd>
              </div>
            </dl>
          </div>
          <div className="rounded border border-quantum/30 bg-quantum/5 p-3 text-sm">
            <div className="flex items-baseline justify-between">
              <span className="font-semibold text-quantum">QRNG pool</span>
              <span className="tabular-nums">{pool?.unused_for_nonce ?? 0} unused job(s)</span>
            </div>
            <p className="mt-1 text-mute">
              One {pool?.n_qubits}-qubit Hadamard circuit ({pool?.shots} shots) per pass nonce. Default: the QpiAI local simulator (no credits, as the organisers advised). Only Indus-1 output would be physical quantum randomness; simulators sample with a classical PRNG and are labelled so. Either way it is mixed with OS entropy.
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <select value={device} onChange={(e) => setDevice(e.target.value)} aria-label="QRNG device">
                {DEVICES.map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
              <Button
                kind="quantum"
                busy={busy === "qrng"}
                onClick={() => {
                  if (device !== "QpiAI-QSV-Local" && !confirm(`Submit a QRNG circuit to ${device}? This is a QCloud job and may use credits.`)) return;
                  act("qrng", () => api.post("/api/qrng/fetch", { device }));
                }}
              >
                Run QRNG circuit
              </Button>
            </div>
          </div>
        </div>
      </Panel>

      <div className="flex flex-wrap items-center gap-2">
        {plan ? (
          plan.instance.passes.map((p: Json) => {
            const n = Object.values(plan.opt.plan).filter((t) => t === p.index).length;
            return (
              <Button key={p.index} busy={busy === `pass${p.index}`} disabled={!!busy} onClick={() => act(`pass${p.index}`, () => api.post(`/api/pass/${p.index}/run`, { pace_ms: pace }))}>
                Run pass {p.index} ({n} command{n === 1 ? "" : "s"})
              </Button>
            );
          })
        ) : (
          <span className="text-sm text-mute">
            No Opt plan yet. <a className="text-ink underline" href="#/planner">Optimize in the pass planner</a> to run planned passes.
          </span>
        )}
        <Button kind="secondary" busy={busy === "open"} disabled={!!busy} onClick={() => act("open", () => api.post("/api/pass/open", { pace_ms: pace }))}>
          Open ad-hoc contact window
        </Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_1.1fr_1.25fr]">
        <Panel title="Ground station" aside="signs with Falcon-512">
          <ul className="space-y-1.5 text-sm">
            {signed.length === 0 && <li className="text-mute">Signed frames appear here.</li>}
            {signed.map((e, i) => (
              <li key={`${e.ts}-${i}`} className="flex items-center justify-between gap-2 rounded border border-rule bg-white px-2 py-1">
                <span>
                  <span className="font-cond font-semibold">{e.label}</span> <span className="text-mute">{e.opcode_name}</span>
                </span>
                <span className="tabular-nums text-mute">
                  #{e.counter}, {e.bytes} B
                </span>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Uplink" aside={link?.window_id ? `window ${link.window_id}${link.pass ? `, pass ${link.pass}` : ""}` : "no window open"}>
          <div className="relative h-14 overflow-hidden rounded bg-white ring-1 ring-rule">
            <div className="absolute inset-y-0 left-0 right-0 m-auto h-px bg-rule" />
            {flight && (
              <div key={flight.key} className={`frame-cross absolute top-3 flex h-8 w-14 items-center justify-center rounded text-xs font-semibold text-white ${flight.hostile ? "bg-reject" : flight.label === "PASS_OPEN" ? "bg-s2" : "bg-s1"}`}>
                {flight.hostile ? "hostile" : String(flight.label).slice(0, 7)}
              </div>
            )}
          </div>
          {link?.window_id ? (
            <div className="mt-3">
              <div className="flex justify-between text-sm">
                <span className="text-mute">Ground bytes this pass</span>
                <span className="tabular-nums">
                  {fmtBytes(link.used_bytes)} / {fmtBytes(link.budget_bytes)}
                </span>
              </div>
              <div className="mt-1 h-2.5 rounded bg-white ring-1 ring-rule">
                <div className="h-full rounded bg-s1" style={{ width: `${Math.min(100, (100 * link.used_bytes) / Math.max(1, link.budget_bytes))}%` }} />
              </div>
              <p className="mt-1 text-xs text-mute">
                {link.frames_sent} frames sent, {link.refused} refused at budget. Hostile traffic: {link.hostile_frames} frames ({fmtBytes(link.hostile_bytes)}).
              </p>
            </div>
          ) : (
            <p className="mt-3 text-sm text-mute">Open a window or run a pass.</p>
          )}
          {refused.map((e, i) => (
            <p key={i} className="mt-2 rounded bg-caution/10 px-2 py-1 text-xs text-caution">
              Link refused {e.label}: {e.error}
            </p>
          ))}
        </Panel>

        <Panel
          title="Spacecraft verifier"
          aside={shown && <VerdictTag verdict={shown.verdict} reason={shown.reason} />}
        >
          {shown && (
            <p className="mb-2 text-sm">
              <span className="font-cond font-semibold">{latest.label}</span>{" "}
              <span className="text-mute">
                counter {shown.counter ?? "?"}, {shown.sig_checked ? `signature checked in ${shown.verify_us} µs` : "no signature work"}
              </span>
            </p>
          )}
          <StepLadder key={lastVerdict?.key ?? "initial"} steps={shown?.steps} animate={!!lastVerdict} />
          {shown?.executed && <p className="mt-2 text-sm text-accept">Executed: {shown.executed}</p>}
          {shown && shown.verdict === "REJECT" && <p className="mt-2 text-sm text-reject">{REASON_TEXT[shown.reason]}</p>}
        </Panel>
      </div>

      <Panel title="Frame log, this session" aside={<a className="underline" href="#/evidence">full audit log</a>}>
        <div className="overflow-x-auto">
          <table className="data w-full text-sm">
            <thead>
              <tr>
                <th>Frame</th>
                <th>Window</th>
                <th className="text-right">Counter</th>
                <th className="text-right">Bytes</th>
                <th>Verdict</th>
                <th>Log #</th>
                <th>SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {frames.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-mute">
                    Nothing transmitted yet in this session.
                  </td>
                </tr>
              )}
              {frames.map((e, i) => (
                <tr key={`${e.ts}-${i}`}>
                  <td className="font-cond font-semibold">{e.label}</td>
                  <td className="tabular-nums">{e.window}</td>
                  <td className="text-right tabular-nums">{e.result?.counter ?? "—"}</td>
                  <td className="text-right tabular-nums">{e.bytes}</td>
                  <td>
                    <VerdictTag verdict={e.result?.verdict} reason={e.result?.reason} />
                  </td>
                  <td className="tabular-nums">{e.result?.log?.seq}</td>
                  <td>
                    <Mono>{short(e.result?.frame_sha256, 6)}</Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <QrngInspector />
    </div>
  );
}
