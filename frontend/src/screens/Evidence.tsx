import { useEffect, useMemo, useState } from "react";
import { api, fmtBytes, short, type Json } from "../api";
import { CopyId, ErrorNote, Mono, Panel, Provenance, VerdictTag, randomnessKind } from "../components/ui";

const REASONS = ["", "OK", "E_FLOOD_LOCKOUT", "E_MALFORMED", "E_WRONG_SAT", "E_EXPIRED", "E_REPLAY", "E_BAD_SIG", "E_UNAUTHORIZED"];

export default function Evidence() {
  const [ev, setEv] = useState<Json | null>(null);
  const [log, setLog] = useState<Json[]>([]);
  const [verdict, setVerdict] = useState("");
  const [reason, setReason] = useState("");
  const [view, setView] = useState<Json | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadLog = () => {
    const q = new URLSearchParams({ limit: "1000" });
    if (verdict) q.set("verdict", verdict);
    if (reason) q.set("reason", reason);
    api.get(`/api/log?${q}`).then((r) => setLog(r.rows.reverse())).catch((e) => setError(e.message));
  };
  useEffect(() => {
    api.get("/api/evidence").then(setEv).catch((e) => setError(e.message));
  }, []);
  useEffect(loadLog, [verdict, reason]);

  const open = async (path: string) => {
    try {
      setView(await api.get(`/api/evidence/file?path=${encodeURIComponent(path)}`));
    } catch (e: Json) {
      setError(e.message);
    }
  };

  const counts = useMemo(() => {
    const c = { ACCEPT: 0, REJECT: 0 } as Record<string, number>;
    log.forEach((r) => (c[r.verdict] = (c[r.verdict] ?? 0) + 1));
    return c;
  }, [log]);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="max-w-3xl">
          <h1 className="font-cond text-3xl font-bold">Evidence</h1>
          <p className="text-mute">
            The onboard audit log, every QpiAI Opt and QCloud job this installation has run, the raw solver inputs and outputs, and a bundle that
            carries SHA-256 hashes of every file. Private keys and API keys are never included.
          </p>
        </div>
        <a
          href="/api/evidence.zip"
          className="inline-flex items-center rounded bg-ink px-3.5 py-2 text-sm font-semibold text-white hover:bg-[#1f3560] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-quantum"
        >
          Download evidence bundle (.zip)
        </a>
      </header>
      <ErrorNote error={error} onDismiss={() => setError(null)} />

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="QpiAI Opt jobs" aside={`${ev?.opt_jobs?.length ?? 0} run${ev?.opt_jobs?.length === 1 ? "" : "s"}`}>
          <JobsTable
            rows={ev?.opt_jobs ?? []}
            empty="No Opt runs yet. Optimize in the pass planner."
            cols={[
              ["Job ID", (r: Json) => <CopyId value={r.job_id} empty={r.execution_mode === "local" ? "local (no ID)" : "—"} />],
              ["Mode", (r: Json) => <Provenance kind={r.execution_mode === "platform" ? "platform" : r.execution_mode === "local" ? "opt_local" : "fixture"} />],
              ["Objective", (r: Json) => <span className="tabular-nums">{r.objective}</span>],
              ["Feasible", (r: Json) => (r.feasible ? "✓" : "✗")],
              ["When", (r: Json) => <span className="text-mute">{r.created_utc?.slice(0, 19).replace("T", " ")}</span>],
            ]}
            onOpen={open}
          />
        </Panel>
        <Panel title="QCloud jobs" aside={`${ev?.qcloud_jobs?.length ?? 0} record${ev?.qcloud_jobs?.length === 1 ? "" : "s"}`}>
          <JobsTable
            rows={ev?.qcloud_jobs ?? []}
            empty="No QCloud jobs yet. Fetch QRNG on the live uplink screen or run QAOA in the planner."
            cols={[
              ["Kind", (r: Json) => <span className="font-semibold uppercase">{r.kind}</span>],
              ["Job ID", (r: Json) => (r.job_ids?.length > 1 ? <span>{r.job_ids.length} circuit jobs</span> : <CopyId value={r.job_ids?.[0]} empty="local run" />)],
              ["Device", (r: Json) => <span className="text-sm">{r.device}</span>],
              ["Source", (r: Json) => <Provenance kind={r.kind === "qaoa" ? (r.execution_mode === "platform" ? "cloud" : "local") : randomnessKind(r.randomness_class)} />],
              ["When", (r: Json) => <span className="text-mute">{r.created_utc?.slice(0, 19).replace("T", " ")}</span>],
            ]}
            onOpen={open}
          />
        </Panel>
      </div>

      <Panel
        title="Onboard accept / reject log"
        aside={
          <span className="flex flex-wrap items-center gap-2">
            <span>
              {counts.ACCEPT} accepted, {counts.REJECT} rejected shown
            </span>
            <select value={verdict} onChange={(e) => setVerdict(e.target.value)} aria-label="Filter by verdict">
              <option value="">All verdicts</option>
              <option value="ACCEPT">Accepted</option>
              <option value="REJECT">Rejected</option>
            </select>
            <select value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Filter by reason">
              {REASONS.map((r) => (
                <option key={r} value={r}>
                  {r || "All reasons"}
                </option>
              ))}
            </select>
            <button className="text-ink underline" onClick={loadLog}>
              Refresh
            </button>
          </span>
        }
      >
        <div className="max-h-[28rem] overflow-auto">
          <table className="data w-full text-sm">
            <thead className="sticky top-0 bg-panel">
              <tr>
                <th>#</th>
                <th>Time (UTC)</th>
                <th>Window</th>
                <th className="text-right">Counter</th>
                <th>Opcode</th>
                <th>Verdict</th>
                <th>Context</th>
                <th className="text-right">Onboard time</th>
                <th>Frame SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {log.length === 0 && (
                <tr>
                  <td colSpan={9} className="text-mute">
                    No log lines match.
                  </td>
                </tr>
              )}
              {log.map((r) => (
                <tr key={r.seq}>
                  <td className="tabular-nums text-mute">{r.seq}</td>
                  <td className="whitespace-nowrap tabular-nums">{r.time_utc?.slice(11, 23)}</td>
                  <td className="tabular-nums">{r.window}</td>
                  <td className="text-right tabular-nums">{r.counter ?? "—"}</td>
                  <td>{r.opcode_name ?? "—"}</td>
                  <td>
                    <VerdictTag verdict={r.verdict} reason={r.reason} />
                  </td>
                  <td className="text-xs text-mute">{r.context ? Object.entries(r.context).map(([k, v]) => `${k}: ${v}`).join(", ") : ""}</td>
                  <td className="text-right tabular-nums">{r.total_us} µs</td>
                  <td className="whitespace-nowrap">
                    <Mono>{short(r.frame_sha256, 6)}</Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="Pass nonce derivations" aside="each nonce is recomputable from these inputs">
          <div className="max-h-72 overflow-auto">
            <table className="data w-full text-sm">
              <thead>
                <tr>
                  <th>Pass</th>
                  <th>Nonce</th>
                  <th>QCloud job</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {(ev?.nonce_derivations ?? []).length === 0 && (
                  <tr>
                    <td colSpan={4} className="text-mute">
                      No nonces derived yet.
                    </td>
                  </tr>
                )}
                {(ev?.nonce_derivations ?? [])
                  .slice()
                  .reverse()
                  .map((n: Json, i: number) => (
                    <tr key={i}>
                      <td className="tabular-nums">{n.pass}</td>
                      <td>
                        <Mono>{short(n.nonce, 6)}</Mono>
                      </td>
                      <td>
                        <CopyId value={n.job_id} empty="none" />
                      </td>
                      <td>
                        <Provenance kind={randomnessKind(n.randomness_class === "development-only" ? null : n.randomness_class)} />
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </Panel>
        <Panel title="Tests and reproduction">
          {ev?.tests ? (
            <p className="text-sm">
              Last pytest run {ev.tests.finished_utc?.slice(0, 19).replace("T", " ")} UTC:{" "}
              <b className="text-accept">{ev.tests.counts.passed ?? 0} passed</b>
              {ev.tests.counts.failed ? <b className="text-reject">, {ev.tests.counts.failed} failed</b> : null}
              {ev.tests.counts.skipped ? <span className="text-mute">, {ev.tests.counts.skipped} skipped (need API keys)</span> : null}.{" "}
              <button className="underline" onClick={() => open("tests/summary.json")}>
                View results
              </button>
            </p>
          ) : (
            <p className="text-sm text-mute">No test summary yet. Run the tests to record one.</p>
          )}
          <dl className="mt-3 space-y-2 text-sm">
            {ev &&
              Object.entries(ev.reproduce).map(([k, v]) => (
                <div key={k}>
                  <dt className="text-mute">{k}</dt>
                  <dd>
                    <Mono>{String(v)}</Mono>
                  </dd>
                </div>
              ))}
          </dl>
          {ev?.manifest?.host && (
            <p className="mt-3 text-xs text-mute">
              Host: {ev.manifest.host.cpu}, Python {ev.manifest.host.python}. Packages:{" "}
              {Object.entries(ev.manifest.host.packages)
                .map(([k, v]) => `${k} ${v}`)
                .join(", ")}
              .
            </p>
          )}
          <details className="mt-3 text-sm">
            <summary className="cursor-pointer">All evidence files ({ev?.manifest?.files?.length ?? 0})</summary>
            <ul className="mt-2 max-h-60 space-y-0.5 overflow-auto">
              {ev?.manifest?.files?.map((f: Json) => (
                <li key={f.path} className="flex justify-between gap-2">
                  <button className="truncate text-left underline-offset-2 hover:underline" onClick={() => open(f.path)}>
                    {f.path}
                  </button>
                  <span className="shrink-0 tabular-nums text-mute">{fmtBytes(f.bytes)}</span>
                </li>
              ))}
            </ul>
          </details>
        </Panel>
      </div>

      {view && (
        <Panel title={view.path} aside={<button className="underline" onClick={() => setView(null)}>Close</button>}>
          <pre className="max-h-[32rem] overflow-auto rounded bg-white p-3 font-mono text-xs ring-1 ring-rule">
            {JSON.stringify(view.content ?? view.rows ?? view.text, null, 2)}
          </pre>
        </Panel>
      )}
    </div>
  );
}

function JobsTable({ rows, cols, empty, onOpen }: { rows: Json[]; cols: [string, (r: Json) => React.ReactNode][]; empty: string; onOpen: (p: string) => void }) {
  if (!rows.length) return <p className="text-sm text-mute">{empty}</p>;
  return (
    <div className="max-h-72 overflow-auto">
      <table className="data w-full text-sm">
        <thead>
          <tr>
            {cols.map(([h]) => (
              <th key={h}>{h}</th>
            ))}
            <th />
          </tr>
        </thead>
        <tbody>
          {rows
            .slice()
            .reverse()
            .map((r) => (
              <tr key={r.file}>
                {cols.map(([h, f]) => (
                  <td key={h}>{f(r)}</td>
                ))}
                <td>
                  <button className="text-ink underline" onClick={() => onOpen(r.file)}>
                    Raw input/output
                  </button>
                </td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}
