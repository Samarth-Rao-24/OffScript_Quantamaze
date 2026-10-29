import { useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, short, type Json } from "../api";
import { useLive } from "../live";
import { Button, CopyId, ErrorNote, Fact, Mono, Panel, Provenance, randomnessKind } from "./ui";

/** Draws the exact circuit text that was submitted (OpenQASM 2.0) as a wire diagram. */
export function CircuitDiagram({ qasm }: { qasm: string }) {
  const { n, ops } = useMemo(() => {
    const qreg = /qreg\s+q\[(\d+)\]/.exec(qasm);
    const n = qreg ? Number(qreg[1]) : 0;
    const ops: { q: number; label: string; kind: "gate" | "measure" }[] = [];
    for (const raw of qasm.split(/[\n;]/)) {
      const line = raw.trim();
      const m = /^measure\s+q\[(\d+)\]\s*->\s*c\[(\d+)\]/.exec(line);
      if (m) {
        ops.push({ q: Number(m[1]), label: `c${m[2]}`, kind: "measure" });
        continue;
      }
      const g = /^([a-z]+)(?:\([^)]*\))?\s+q\[(\d+)\]$/.exec(line);
      if (g && !["qreg", "creg", "include"].includes(g[1])) ops.push({ q: Number(g[2]), label: g[1].toUpperCase(), kind: "gate" });
    }
    return { n, ops };
  }, [qasm]);
  if (!n) return <p className="text-sm text-mute">Circuit text not available.</p>;
  const perQ: Record<number, typeof ops> = {};
  ops.forEach((o) => (perQ[o.q] = [...(perQ[o.q] ?? []), o]));
  const cols = Math.max(...Object.values(perQ).map((a) => a.length), 1);
  const rowH = 30;
  const x0 = 46;
  const colW = 64;
  const width = x0 + cols * colW + 40;
  const height = n * rowH + 8;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full max-w-md" role="img" aria-label={`${n}-qubit circuit: ${ops.length} operations`}>
      {Array.from({ length: n }, (_, q) => {
        const y = 8 + q * rowH + rowH / 2 - 4;
        return (
          <g key={q}>
            <text x={4} y={y + 4} fontSize={11} fill="#566580" fontFamily="JetBrains Mono, monospace">
              q[{q}]
            </text>
            <line x1={x0 - 8} x2={width - 8} y1={y} y2={y} stroke="#9aa7b8" strokeWidth={1.5} />
            {(perQ[q] ?? []).map((o, i) => {
              const cx = x0 + i * colW + colW / 2;
              if (o.kind === "measure")
                return (
                  <g key={i}>
                    <rect x={cx - 13} y={y - 11} width={26} height={22} rx={3} fill="#14233F" />
                    <path d={`M ${cx - 8} ${y + 5} A 8 8 0 0 1 ${cx + 8} ${y + 5}`} stroke="white" strokeWidth={1.4} fill="none" />
                    <line x1={cx} y1={y + 5} x2={cx + 6} y2={y - 6} stroke="white" strokeWidth={1.4} />
                    <text x={cx + 17} y={y + 4} fontSize={10} fill="#566580">
                      {o.label}
                    </text>
                  </g>
                );
              return (
                <g key={i}>
                  <rect x={cx - 12} y={y - 11} width={24} height={22} rx={3} fill="#5A47D1" />
                  <text x={cx} y={y + 4} fontSize={12} fill="white" textAnchor="middle" fontWeight={600}>
                    {o.label}
                  </text>
                </g>
              );
            })}
          </g>
        );
      })}
    </svg>
  );
}

export default function QrngInspector() {
  const { state } = useLive();
  const [jobs, setJobs] = useState<Json[]>([]);
  const [file, setFile] = useState<string>("");
  const [detail, setDetail] = useState<Json | null>(null);
  const [verify, setVerify] = useState<Json | null>(null);
  const [refetch, setRefetch] = useState<Json | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const poolSize = state?.qrng?.entries?.length ?? 0;

  useEffect(() => {
    api.get("/api/qrng/jobs").then((r) => {
      setJobs(r.jobs);
      if (r.jobs.length && !r.jobs.some((j: Json) => j.file === file)) setFile(r.jobs[r.jobs.length - 1].file);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [poolSize]);
  useEffect(() => {
    if (!file) return;
    setRefetch(null);
    api.get(`/api/qrng/job/${encodeURIComponent(file)}`).then(setDetail).catch((e) => setError(e.message));
  }, [file]);

  const run = async (key: string, fn: () => Promise<void>) => {
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

  const rec = detail?.record;
  const st = detail?.stats;
  const hist = useMemo(() => {
    if (!st || !rec) return [];
    const n = rec.n_qubits;
    const byVal: Record<number, number> = {};
    st.histogram.forEach((h: Json) => (byVal[h.value] = h.count));
    return Array.from({ length: 2 ** n }, (_, v) => ({ value: v, outcome: v.toString(2).padStart(n, "0"), count: byVal[v] ?? 0 }));
  }, [st, rec]);

  return (
    <Panel
      title="QRNG job inspector"
      aside={
        jobs.length > 0 && (
          <select value={file} onChange={(e) => setFile(e.target.value)} aria-label="QRNG job">
            {jobs
              .slice()
              .reverse()
              .map((j) => (
                <option key={j.file} value={j.file}>
                  {j.job_id ? short(j.job_id, 8) : "local run"} on {j.device} {j.used_for_pass ? `(pass ${j.used_for_pass})` : j.nonce_used ? "" : "(unused)"}
                </option>
              ))}
          </select>
        )
      }
    >
      <ErrorNote error={error} onDismiss={() => setError(null)} />
      {!jobs.length && <p className="text-sm text-mute">No QRNG job recorded yet. Fetch one above (or with scripts\qpiai_runs.py qrng) and it will appear here.</p>}
      {rec && st && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
            <Provenance kind={randomnessKind(rec.randomness_class)} />
            <span>
              <span className="text-mute">Job </span>
              <CopyId value={rec.job_id} empty="none (local simulator)" />
            </span>
            <span>
              <span className="text-mute">Device </span>
              {rec.device}
            </span>
            <span>
              <span className="text-mute">Status </span>
              {rec.job_status ?? "—"}
            </span>
            <span>
              <span className="text-mute">Credits used </span>
              {rec.credits_used ?? "—"}
            </span>
            <span className="text-mute">{rec.started_utc?.slice(0, 19).replace("T", " ")} UTC</span>
          </div>

          <div className="grid gap-5 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.6fr)]">
            <div>
              <h3 className="font-cond text-base font-semibold">Circuit that was submitted</h3>
              <p className="mb-2 text-xs text-mute">
                Every qubit gets a Hadamard (equal superposition) and is measured, {rec.shots} times. Drawn from the stored OpenQASM text.
              </p>
              <CircuitDiagram qasm={detail.qasm} />
              <details className="mt-2 text-xs">
                <summary className="cursor-pointer text-mute">OpenQASM</summary>
                <pre className="mt-1 max-h-40 overflow-auto rounded bg-white p-2 font-mono ring-1 ring-rule">{detail.qasm}</pre>
              </details>
            </div>
            <div>
              <h3 className="font-cond text-base font-semibold">
                Measured outcomes: {st.outcomes_seen} of {st.outcomes_possible} seen in {st.shots} shots
              </h3>
              <p className="text-xs text-mute">Red dashed line: {st.expected_per_outcome} shots per outcome, what a perfectly uniform source would give.</p>
              <div className="h-48" role="img" aria-label={`Histogram of ${st.outcomes_possible} outcomes; expected ${st.expected_per_outcome} each`}>
                <ResponsiveContainer>
                  <BarChart data={hist} margin={{ top: 8, right: 8, left: -18, bottom: 0 }} barCategoryGap={0}>
                    <CartesianGrid vertical={false} stroke="#e3e9ef" />
                    <XAxis dataKey="value" tick={{ fontSize: 11, fill: "#566580" }} ticks={[0, 64, 128, 192, 2 ** rec.n_qubits - 1]} type="number" domain={[-0.5, 2 ** rec.n_qubits - 0.5]} />
                    <YAxis tick={{ fontSize: 11, fill: "#566580" }} allowDecimals={false} />
                    <Tooltip
                      cursor={{ fill: "#e8edf2" }}
                      formatter={(v: Json) => [`${v} shots`, "count"]}
                      labelFormatter={(v: Json) => `outcome ${Number(v).toString(2).padStart(rec.n_qubits, "0")} (${v})`}
                    />
                    <ReferenceLine y={st.expected_per_outcome} stroke="#C23A2F" strokeDasharray="4 3" />
                    <Bar dataKey="count" fill="#2a78d6" isAnimationActive={false} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <dl className="mt-2 grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Fact label="Chi-square vs uniform" hint={`${st.degrees_of_freedom} degrees of freedom`}>
                  {st.chi_square}
                </Fact>
                <Fact label="p-value">{st.chi_square_p_value ?? "—"}</Fact>
                <Fact label="Empirical Shannon">{st.empirical_shannon_bits} bits</Fact>
                <Fact label="Empirical min-entropy">{st.empirical_min_entropy_bits} bits</Fact>
              </dl>
              <div className="mt-2 text-sm">
                <span className="text-mute">Fraction of 1s per bit position (0.5 = unbiased): </span>
                {st.bit_one_frequency.map((f: number, i: number) => (
                  <span key={i} className={`mr-2 tabular-nums ${Math.abs(f - 0.5) > 0.05 ? "font-semibold text-caution" : ""}`}>
                    {f.toFixed(3)}
                  </span>
                ))}
              </div>
              <p className="mt-1 text-xs text-mute">{st.interpretation}</p>
            </div>
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <div className="rounded border border-rule bg-white p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="font-cond text-base font-semibold">Verify the onboard pass nonce</h3>
                <Button kind="secondary" busy={busy === "verify"} onClick={() => run("verify", async () => setVerify(await api.post("/api/nonce/verify", {})))}>
                  Verify current nonce
                </Button>
              </div>
              <p className="text-xs text-mute">Recomputes the satellite's current nonce from the recorded OS entropy, this job's counts and its job ID, then checks the audit log.</p>
              {verify && (
                <div className="mt-2 text-sm">
                  <p className={`font-semibold ${verify.verified ? "text-accept" : "text-reject"}`}>{verify.verified ? "✓ Nonce verified" : "✗ Verification failed"}</p>
                  <ul className="mt-1 space-y-1">
                    {verify.steps.map((s: Json, i: number) => (
                      <li key={i} className="grid grid-cols-[1.2rem_1fr] gap-1">
                        <span className={s.informational ? "text-mute" : s.ok ? "text-accept" : "text-reject"}>{s.informational ? "ℹ" : s.ok ? "✓" : "✗"}</span>
                        <span>
                          {s.label} <span className="text-mute">{s.detail}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                  {verify.formula && (
                    <p className="mt-2 text-xs text-mute">
                      {verify.formula} = <Mono>{short(verify.recomputed, 10)}</Mono>
                    </p>
                  )}
                </div>
              )}
            </div>
            <div className="rounded border border-rule bg-white p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="font-cond text-base font-semibold">Re-fetch from QCloud</h3>
                <Button kind="quantum" disabled={!rec.job_id} busy={busy === "refetch"} onClick={() => run("refetch", async () => setRefetch(await api.post(`/api/qrng/job/${encodeURIComponent(file)}/refetch`)))}>
                  Ask QCloud for this job
                </Button>
              </div>
              <p className="text-xs text-mute">
                {rec.job_id ? "Read-only request for the existing job by ID: status, credits and stored counts. No circuit is run." : "Local simulator runs have no QCloud job to fetch."}
              </p>
              {refetch && (
                <div className="mt-2 text-sm">
                  <p>
                    QCloud says job <Mono>{short(refetch.job_id, 8)}</Mono> is <b>{refetch.status.status}</b>, {refetch.status.credits_used ?? "?"} credits, created{" "}
                    {String(refetch.status.created_at ?? "").slice(0, 19).replace("T", " ")}.
                  </p>
                  {refetch.counts_match_recorded === null ? (
                    <p className="text-caution">Counts not returned{refetch.results_error ? `: ${refetch.results_error}` : "."}</p>
                  ) : (
                    <p className={refetch.counts_match_recorded ? "text-accept" : "text-reject"}>
                      {refetch.counts_match_recorded ? "✓ QCloud's stored counts are identical to our record" : "✗ QCloud's counts differ from our record"}
                    </p>
                  )}
                </div>
              )}
              {detail.refetches?.length > 0 && <p className="mt-1 text-xs text-mute">{detail.refetches.length} earlier re-fetch record(s) saved in evidence.</p>}
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}
