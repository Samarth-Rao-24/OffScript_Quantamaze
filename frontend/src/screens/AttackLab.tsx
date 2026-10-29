import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, REASON_TEXT, type Json } from "../api";
import { useLive } from "../live";
import { Button, ErrorNote, Fact, Mono, Panel, StepLadder, VerdictTag } from "../components/ui";
import JudgeConsole from "../components/JudgeConsole";

const ORDER = ["valid", "tamper", "replay", "expired", "unauthorized", "forged", "crosspass", "wrongsat", "flood", "overbudget"];

export default function AttackLab() {
  const { state, refreshState } = useLive();
  const [attacks, setAttacks] = useState<Record<string, Json>>({});
  const [results, setResults] = useState<Record<string, Json>>({});
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get("/api/config").then((c) => setAttacks(c.attacks));
  }, []);

  const flood = state?.onboard?.flood;
  const windowOpen = !!state?.link?.window_id;

  const fire = async (kind: string) => {
    setBusy(kind);
    setError(null);
    try {
      const r = await api.post(`/api/attack/${kind}`);
      setResults((x) => ({ ...x, [kind]: r }));
      setSelected(kind);
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(null);
      refreshState();
    }
  };
  const openWindow = async () => {
    setBusy("open");
    setError(null);
    try {
      await api.post("/api/pass/open", {});
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(null);
      refreshState();
    }
  };

  const r = selected ? results[selected] : null;
  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="max-w-3xl">
          <h1 className="font-cond text-3xl font-bold">Attack lab</h1>
          <p className="text-mute">
            Each button builds a hostile frame with real keys and library calls and sends it to the onboard process. The result shows the
            reason code the verifier returned and checks that no rejected frame moved the counter or wrote state.
          </p>
        </div>
        <div className="flex items-center gap-3 rounded border border-rule bg-panel px-3 py-2">
          <div className="text-sm">
            <div className="text-mute">Contact window</div>
            <div className="font-cond text-lg font-semibold">{windowOpen ? `#${state.link.window_id} open` : "closed"}</div>
          </div>
          <div className="text-sm">
            <div className="text-mute">Flood guard</div>
            <div className={`font-cond text-lg font-semibold ${flood?.locked ? "text-reject" : ""}`}>
              {flood ? `${flood.failures} of ${flood.limit}` : "—"} {flood?.locked && "locked"}
            </div>
          </div>
          <Button kind={flood?.locked || !windowOpen ? "primary" : "secondary"} busy={busy === "open"} onClick={openWindow}>
            {windowOpen ? "Start next window" : "Open contact window"}
          </Button>
        </div>
      </header>
      <ErrorNote error={error} onDismiss={() => setError(null)} />
      {windowOpen && flood?.locked && (
        <p className="rounded bg-reject/10 px-3 py-2 text-sm text-reject">
          This contact window is locked by the flood guard: every frame, genuine or hostile, is now dropped without signature work. Start the next
          window to test other attacks.
        </p>
      )}
      {!windowOpen && <p className="rounded bg-caution/10 px-3 py-2 text-sm text-caution">Open a contact window first: PASS_OPEN installs the QRNG pass nonce that every frame is bound to.</p>}

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {ORDER.filter((k) => attacks[k]).map((k) => {
          const res = results[k];
          return (
            <button
              key={k}
              disabled={!windowOpen || !!busy}
              onClick={() => fire(k)}
              className={`rounded border p-3 text-left transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-quantum disabled:cursor-not-allowed disabled:opacity-50 ${selected === k ? "border-ink bg-white" : "border-rule bg-panel hover:border-ink"} ${k === "flood" ? "ring-1 ring-reject/30" : ""}`}
            >
              <div className="flex items-start justify-between gap-2">
                <span className="font-cond text-lg font-semibold">{attacks[k].title}</span>
                {busy === k ? (
                  <span className="h-3 w-3 animate-spin rounded-full border-2 border-ink border-r-transparent" />
                ) : res ? (
                  <span className={res.passed ? "text-accept" : "text-reject"} title={res.passed ? "behaved as expected" : "unexpected result"}>
                    {res.passed ? "✓" : "✗"}
                  </span>
                ) : null}
              </div>
              <div className="mt-0.5 text-xs text-mute">{attacks[k].description}</div>
              <div className="mt-2 text-xs">
                <span className="text-mute">expects </span>
                <code className="font-mono">{attacks[k].expected}</code>
              </div>
            </button>
          );
        })}
      </div>

      {r && <Result r={r} />}

      <JudgeConsole windowOpen={windowOpen} />
    </div>
  );
}

function Result({ r }: { r: Json }) {
  const target = r.frames.filter((f: Json) => f.is_attack !== false);
  const main = target[target.length - 1] ?? r.frames[r.frames.length - 1];
  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_1.1fr]">
      <Panel title={r.title} aside={<span className={r.passed ? "font-semibold text-accept" : "font-semibold text-reject"}>{r.passed ? (r.attack === "valid" ? "✓ Accepted as expected" : r.attack === "overbudget" ? "✓ Refused at the budget" : "✓ Rejected as expected") : "✗ Unexpected result"}</span>}>
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Fact label="Expected">
            <span className="text-base">{r.expected}</span>
          </Fact>
          <Fact label="Observed">
            <span className="text-base">{r.observed.join(", ")}</span>
          </Fact>
          <Fact label="Signature checks spent">{r.sig_verifications_spent}</Fact>
          <Fact label="NV writes">{r.nv_writes_delta}</Fact>
        </dl>
        <p className={`mt-3 text-sm ${r.counter_check.startsWith("STATE") ? "text-reject" : "text-accept"}`}>{r.counter_check}.</p>
        <dl className="mt-3 grid gap-1 text-sm">
          <div>
            <dt className="inline text-mute">Counter before / after </dt>
            <dd className="inline tabular-nums">
              {r.before.last_counter} / {r.after.last_counter}
            </dd>
          </div>
          <div>
            <dt className="inline text-mute">Attack inputs drawn from </dt>
            <dd className="inline">{r.fuzz.source}</dd>
          </div>
          <div>
            <dt className="inline text-mute">Fuzz seed </dt>
            <dd className="inline">
              <Mono>{r.fuzz.fuzz_seed}</Mono>
            </dd>
          </div>
          {main?.mutation && (
            <div>
              <dt className="inline text-mute">Bit flipped </dt>
              <dd className="inline">
                byte {main.mutation.byte_offset}, bit {main.mutation.bit}
              </dd>
            </div>
          )}
        </dl>
        {r.flood_summary && <FloodChart s={r.flood_summary} />}
        <h3 className="mt-4 font-cond text-base font-semibold">Frames sent ({r.frame_count})</h3>
        <ul className="mt-1 space-y-1 text-sm">
          {r.frames.map((f: Json, i: number) => (
            <li key={i} className="flex flex-wrap items-center justify-between gap-2 border-b border-[#e3e9ef] pb-1">
              <span>
                {f.label} <span className="text-mute">{f.bytes} B</span>
              </span>
              {f.link_refused ? (
                <span className="text-sm font-semibold text-caution">Refused by ground link (never transmitted)</span>
              ) : (
                <span className="flex items-center gap-2">
                  <VerdictTag verdict={f.result?.verdict} reason={f.result?.reason} />
                  {f.result?.log_seq && <span className="text-xs text-mute">log #{f.result.log_seq}</span>}
                </span>
              )}
            </li>
          ))}
          {r.frame_count > r.frames.length && <li className="text-mute">…{r.frame_count - r.frames.length} more frames, all in the audit log</li>}
        </ul>
      </Panel>
      <Panel title="Verifier checks for the attack frame">
        {main?.result ? (
          <>
            <StepLadder steps={main.result.steps} animate key={`${r.attack}-${r.after.sig_verifications}-${r.frame_count}`} />
            <p className="mt-2 text-sm text-mute">{REASON_TEXT[main.result.reason]}</p>
          </>
        ) : (
          <p className="text-sm text-mute">{main?.error ?? "The frame never reached the spacecraft."}</p>
        )}
      </Panel>
    </div>
  );
}

function FloodChart({ s }: { s: Json }) {
  const data = Object.entries(s.by_reason).map(([k, v]) => ({ reason: k, frames: v as number }));
  return (
    <div className="mt-4">
      <h3 className="font-cond text-base font-semibold">
        {s.frames} junk frames: {s.signature_checks} signature checks, then lockout
      </h3>
      <p className="text-sm text-mute">
        Onboard time {s.onboard_total_ms} ms in total, of which signature verification {s.onboard_verify_ms} ms. Without the guard every junk
        frame would reach the signature check (see Resource budget).
      </p>
      <div className="mt-2 h-36" role="img" aria-label={data.map((d) => `${d.reason}: ${d.frames} frames`).join("; ")}>
        <ResponsiveContainer>
          <BarChart data={data} layout="vertical" margin={{ left: 20, right: 30 }}>
            <CartesianGrid horizontal={false} stroke="#e3e9ef" />
            <XAxis type="number" tick={{ fontSize: 12, fill: "#566580" }} />
            <YAxis type="category" dataKey="reason" width={130} tick={{ fontSize: 12, fill: "#14233F" }} />
            <Tooltip cursor={{ fill: "#e8edf2" }} />
            <Bar dataKey="frames" fill="#2a78d6" radius={[0, 4, 4, 0]} barSize={18} label={{ position: "right", fontSize: 12, fill: "#14233F" }} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
