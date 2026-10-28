import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, fmtBytes, fmtUs, type Json } from "../api";
import { Button, ErrorNote, Panel, Provenance } from "../components/ui";

const AXIS = { fontSize: 12, fill: "#566580" };

function Target({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return <span className={`text-xs font-semibold ${ok ? "text-accept" : "text-reject"}`}>{ok ? "✓" : "✗"} {children}</span>;
}

function Metric({ label, value, target }: { label: string; value: React.ReactNode; target?: React.ReactNode }) {
  return (
    <div className="border-l-2 border-ink/15 pl-3">
      <div className="text-xs text-mute">{label}</div>
      <div className="font-cond text-2xl font-semibold tabular-nums leading-tight">{value}</div>
      {target}
    </div>
  );
}

export default function Resources() {
  const [m, setM] = useState<Json | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = () => api.get("/api/metrics").then(setM).catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post("/api/bench/run");
      await load();
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const me = m?.measure;
  const sc = m?.schemes;
  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="max-w-3xl">
          <h1 className="font-cond text-3xl font-bold">Resource budget</h1>
          <p className="text-mute">
            What authentication costs on the link and onboard. Every number is measured on this computer's CPU and labelled as an emulated host
            measurement; none of it claims to be flight-hardware performance.
          </p>
        </div>
        <Button onClick={run} busy={busy}>
          {me ? "Re-run benchmarks" : "Run benchmarks"}
        </Button>
      </header>
      <ErrorNote error={error} onDismiss={() => setError(null)} />
      {!me && !busy && <Panel title="No measurements yet"><p className="text-mute">Run the benchmarks (about 20 to 40 seconds). Results are saved to the evidence folder.</p></Panel>}
      {busy && <p className="text-sm text-mute">Measuring: 1,000 verifications, memory, NV writes, two flood scenarios and five signature schemes…</p>}

      {me && (
        <>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <Provenance kind="emulated" />
            <span className="text-mute">
              {me.host.cpu}, Python {me.host.python}, {me.host.platform}. Measured {new Date(me.created_utc).toLocaleString()}.
            </span>
          </div>
          <Panel title="Onboard and link budget, Falcon-padded-512">
            <div className="grid grid-cols-2 gap-5 md:grid-cols-4 xl:grid-cols-7">
              <Metric label="Auth overhead per frame" value={`${me.frame.auth_overhead_bytes} B`} target={<Target ok={me.frame.auth_overhead_bytes <= 682}>target ≤ 682 B</Target>} />
              <Metric label="Signature verify p50" value={fmtUs(me.verify_crypto_only.p50_us)} target={<span className="text-xs text-mute">p95 {fmtUs(me.verify_crypto_only.p95_us)}</span>} />
              <Metric label="Full pipeline p95" value={fmtUs(me.verify_pipeline.p95_us)} target={<Target ok={me.verify_pipeline.p95_us < 5000}>target &lt; 5 ms, incl. NV commit</Target>} />
              <Metric label="Peak RAM per verification" value={fmtBytes(me.peak_ram_bytes)} target={<Target ok={me.peak_ram_bytes < 65536}>target &lt; 64 KB</Target>} />
              <Metric label="NV writes, accepted" value={me.nv_writes_per_accepted} target={<Target ok={me.nv_writes_per_accepted === 1}>target exactly 1</Target>} />
              <Metric label="NV writes, rejected" value={me.nv_writes_per_rejected} target={<Target ok={me.nv_writes_per_rejected === 0}>target 0</Target>} />
              <Metric
                label="Signature checks in a 500-frame flood"
                value={`${me.flood_with_guard.signature_verifications}`}
                target={<Target ok={me.flood_with_guard.signature_verifications <= me.nfr06.limit}>≤ N = {me.nfr06.limit}; 500 without guard</Target>}
              />
            </div>
            <details className="mt-4 text-sm text-mute">
              <summary className="cursor-pointer text-ink">How these were measured</summary>
              <ul className="mt-2 list-disc space-y-1 pl-5">
                {Object.entries(me.method).map(([k, v]) => (
                  <li key={k}>
                    <b className="text-ink">{k}</b>: {String(v)}
                  </li>
                ))}
                <li>Whole-loop heap peak over 200 verifications: {fmtBytes(me.peak_ram_loop_bytes)} (includes not-yet-collected garbage).</li>
              </ul>
            </details>
          </Panel>

          <div className="grid gap-5 xl:grid-cols-2">
            <FloodPanel me={me} />
            <PassBytes runs={m.pass_runs} />
          </div>
        </>
      )}

      {sc && <SchemePanel sc={sc} />}
    </div>
  );
}

function FloodPanel({ me }: { me: Json }) {
  const data = [
    { name: "Random signatures, guard on", ms: me.flood_with_guard.total_ms, checks: me.flood_with_guard.signature_verifications },
    { name: "Random signatures, no guard", ms: me.flood_without_guard.total_ms, checks: me.flood_without_guard.signature_verifications },
    { name: "Attacker-key signatures, guard on", ms: me.flood_wellformed_with_guard?.total_ms, checks: me.flood_wellformed_with_guard?.signature_verifications },
    { name: "Attacker-key signatures, no guard", ms: me.flood_wellformed_without_guard?.total_ms, checks: me.flood_wellformed_without_guard?.signature_verifications },
  ].filter((d) => d.ms !== undefined);
  return (
    <Panel title="Onboard CPU under a 500-frame flood" aside="total verifier time, ms">
      <div className="h-56" role="img" aria-label={data.map((d) => `${d.name}: ${d.ms} ms, ${d.checks} signature checks`).join("; ")}>
        <ResponsiveContainer>
          <BarChart data={data} layout="vertical" margin={{ left: 10, right: 60 }}>
            <CartesianGrid horizontal={false} stroke="#e3e9ef" />
            <XAxis type="number" tick={AXIS} unit=" ms" />
            <YAxis type="category" dataKey="name" width={210} tick={{ fontSize: 12, fill: "#14233F" }} />
            <Tooltip formatter={(v: Json, _n: Json, p: Json) => [`${v} ms, ${p.payload.checks} signature checks`, "verifier time"]} cursor={{ fill: "#e8edf2" }} />
            <Bar dataKey="ms" radius={[0, 4, 4, 0]} barSize={18} label={{ position: "right", fontSize: 12, fill: "#14233F", formatter: (v: Json) => `${v} ms` }}>
              {data.map((d) => (
                <Cell key={d.name} fill={d.name.includes("guard on") ? "#2a78d6" : "#9aa7b8"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <p className="text-sm text-mute">
        Blue: flood guard on. Grey: guard off. The guard stops signature work after N failures per contact window, so cost stays flat however many junk frames arrive. Random bytes often fail early in Falcon's signature decoding; well-formed attacker-key signatures show the full cost.
      </p>
    </Panel>
  );
}

function PassBytes({ runs }: { runs: Json[] }) {
  if (!runs?.length)
    return (
      <Panel title="Uplink bytes per pass">
        <p className="text-sm text-mute">Run planned passes on the Live uplink screen to fill this chart.</p>
      </Panel>
    );
  const data = runs.slice(-8).map((r) => ({ name: `Pass ${r.pass} (w${r.window})`, bytes: r.bytes, budget: r.budget, frames: r.frames }));
  const maxBudget = Math.max(...data.map((d) => d.budget));
  return (
    <Panel title="Uplink bytes per pass" aside="delivered by the link simulator">
      <div className="h-56" role="img" aria-label={data.map((d) => `${d.name}: ${d.bytes} of ${d.budget} bytes`).join("; ")}>
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 10, right: 10 }}>
            <CartesianGrid vertical={false} stroke="#e3e9ef" />
            <XAxis dataKey="name" tick={AXIS} />
            <YAxis tick={AXIS} domain={[0, Math.ceil((maxBudget * 1.1) / 500) * 500]} />
            <Tooltip formatter={(v: Json, _n: Json, p: Json) => [`${v} B of ${p.payload.budget} B, ${p.payload.frames} frames`, "sent"]} cursor={{ fill: "#e8edf2" }} />
            {[...new Set(data.map((d) => d.budget))].map((b) => (
              <ReferenceLine key={b} y={b} stroke="#C23A2F" strokeDasharray="4 3" label={{ value: `budget ${b} B`, position: "insideTopRight", fontSize: 11, fill: "#C23A2F" }} />
            ))}
            <Bar dataKey="bytes" fill="#2a78d6" radius={[4, 4, 0, 0]} barSize={32} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
}

function SchemePanel({ sc }: { sc: Json }) {
  const rows = sc.schemes;
  const sizeData = rows.map((r: Json) => ({ name: r.scheme, bytes: r.signature_bytes.max, pq: r.quantum_safe, selected: r.selected }));
  const verifyData = rows.map((r: Json) => ({ name: r.scheme, us: r.verify.p50_us, p95: r.verify.p95_us, selected: r.selected }));
  const fill = (d: Json) => (d.selected ? "#2a78d6" : "#9aa7b8");
  return (
    <Panel title="Signature schemes on the same harness" aside={<Provenance kind="emulated" />}>
      <p className="mb-3 max-w-3xl text-sm text-mute">
        Falcon-padded-512 signatures are {sc.falcon_vs_mldsa_signature_saving_pct}% smaller than ML-DSA-44, which decides how many commands fit
        in a pass. ECDSA and Ed25519 are classical baselines only: small and fast, but not quantum-safe.
      </p>
      <div className="grid gap-5 lg:grid-cols-2">
        <div>
          <h3 className="font-cond text-base font-semibold">Signature size, bytes</h3>
          <div className="h-56" role="img" aria-label={sizeData.map((d: Json) => `${d.name}: ${d.bytes} bytes`).join("; ")}>
            <ResponsiveContainer>
              <BarChart data={sizeData} layout="vertical" margin={{ left: 10, right: 50 }}>
                <CartesianGrid horizontal={false} stroke="#e3e9ef" />
                <XAxis type="number" tick={AXIS} />
                <YAxis type="category" dataKey="name" width={170} tick={{ fontSize: 12, fill: "#14233F" }} />
                <Tooltip cursor={{ fill: "#e8edf2" }} formatter={(v: Json) => [`${v} B`, "signature"]} />
                <Bar dataKey="bytes" radius={[0, 4, 4, 0]} barSize={16} label={{ position: "right", fontSize: 12, fill: "#14233F" }}>
                  {sizeData.map((d: Json) => (
                    <Cell key={d.name} fill={fill(d)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div>
          <h3 className="font-cond text-base font-semibold">Verify time p50, µs</h3>
          <div className="h-56" role="img" aria-label={verifyData.map((d: Json) => `${d.name}: ${d.us} microseconds`).join("; ")}>
            <ResponsiveContainer>
              <BarChart data={verifyData} layout="vertical" margin={{ left: 10, right: 50 }}>
                <CartesianGrid horizontal={false} stroke="#e3e9ef" />
                <XAxis type="number" tick={AXIS} />
                <YAxis type="category" dataKey="name" width={170} tick={{ fontSize: 12, fill: "#14233F" }} />
                <Tooltip cursor={{ fill: "#e8edf2" }} formatter={(v: Json, _n: Json, p: Json) => [`p50 ${v} µs, p95 ${p.payload.p95} µs`, "verify"]} />
                <Bar dataKey="us" radius={[0, 4, 4, 0]} barSize={16} label={{ position: "right", fontSize: 12, fill: "#14233F" }}>
                  {verifyData.map((d: Json) => (
                    <Cell key={d.name} fill={d.selected ? "#2a78d6" : "#9aa7b8"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      <div className="mt-4 overflow-x-auto">
        <table className="data w-full text-sm">
          <thead>
            <tr>
              <th>Scheme</th>
              <th>Quantum-safe</th>
              <th className="text-right">Public key</th>
              <th className="text-right">Signature</th>
              <th className="text-right">Frame (12 B body)</th>
              <th className="text-right">Commands per 3,600 B pass</th>
              <th className="text-right">Sign p50</th>
              <th className="text-right">Verify p50 / p95</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r: Json) => (
              <tr key={r.scheme} className={r.selected ? "font-semibold" : ""}>
                <td>
                  {r.scheme}
                  {r.selected && <span className="ml-2 text-xs text-s1">selected</span>}
                  <div className="text-xs font-normal text-mute">{r.library}</div>
                </td>
                <td>{r.quantum_safe ? "✓ yes" : "✗ no"}</td>
                <td className="text-right tabular-nums">{r.public_key_bytes} B</td>
                <td className="text-right tabular-nums">
                  {r.signature_bytes.min === r.signature_bytes.max ? `${r.signature_bytes.max} B` : `${r.signature_bytes.min}–${r.signature_bytes.max} B`}
                </td>
                <td className="text-right tabular-nums">{r.frame_bytes_12B_body_worst_case} B</td>
                <td className="text-right tabular-nums">{r.frames_per_3600B_pass}</td>
                <td className="text-right tabular-nums">{fmtUs(r.sign.p50_us)}</td>
                <td className="text-right tabular-nums">
                  {fmtUs(r.verify.p50_us)} / {fmtUs(r.verify.p95_us)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
