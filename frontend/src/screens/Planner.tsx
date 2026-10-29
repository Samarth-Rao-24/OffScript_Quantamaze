import { useEffect, useMemo, useState } from "react";
import { api, fmtBytes, type Json } from "../api";
import { Button, CopyId, ErrorNote, Fact, Panel, Provenance } from "../components/ui";

const STATUS_TEXT: Record<string, [string, string]> = {
  SENT: ["Sent", "text-accept"],
  DEFERRED_BUDGET: ["Deferred: budget", "text-caution"],
  DEFERRED_TRADEOFF: ["Deferred: trade-off", "text-caution"],
  WAITING_DEPENDENCY: ["Waiting on dependency", "text-reject"],
  BLOCKED_DEADLINE: ["Blocked by deadline", "text-reject"],
};

function sameInstance(q: Json, plan: Json): boolean {
  if (!q || !plan?.instance) return false;
  const key = (cmds: Json[], passes: Json[]) =>
    JSON.stringify([
      cmds.map((c) => [c.id, c.priority, c.deadline_pass, [...(c.depends_on ?? [])].sort(), c.frame_bytes, c.role]),
      passes.map((p) => p.budget_bytes),
    ]);
  return key(q.commands, q.passes) === key(plan.instance.commands, plan.instance.passes);
}

export default function Planner() {
  const [queue, setQueue] = useState<Json | null>(null);
  const [draft, setDraft] = useState<Json | null>(null);
  const [plan, setPlan] = useState<Json | null>(null);
  const [mode, setMode] = useState<"platform" | "local">("platform");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    const [q, p, cfg] = await Promise.all([api.get("/api/queue"), api.get("/api/plan"), api.get("/api/config")]);
    setQueue(q);
    setDraft(structuredClone(q));
    setPlan(p && p.opt ? p : null);
    setMode(cfg.config.opt_mode);
  };
  useEffect(() => {
    load().catch((e) => setError(String(e.message ?? e)));
  }, []);

  const dirty = useMemo(() => JSON.stringify(draft) !== JSON.stringify(queue), [draft, queue]);
  const stale = plan && queue && !sameInstance(queue, plan);

  const save = async () => {
    setBusy("save");
    setError(null);
    try {
      const body = {
        commands: draft.commands.map((c: Json) => ({ ...c, depends_on: c.depends_on.filter(Boolean) })),
        budgets: draft.passes.map((p: Json) => Number(p.budget_bytes)),
      };
      const q = await api.put("/api/queue", body);
      setQueue(q);
      setDraft(structuredClone(q));
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  };

  const optimize = async () => {
    setBusy("opt");
    setError(null);
    try {
      setPlan(await api.post("/api/plan", { mode }));
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  };

  if (!draft) return <p className="text-mute">Loading queue…</p>;

  const setCmd = (i: number, k: string, v: Json) =>
    setDraft((d: Json) => ({ ...d, commands: d.commands.map((c: Json, j: number) => (j === i ? { ...c, [k]: v } : c)) }));

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="max-w-3xl">
          <h1 className="font-cond text-3xl font-bold">Pass planner</h1>
          <p className="text-mute">
            QpiAI Opt decides which queued commands are signed and sent in each of the next {draft.passes.length} passes,
            within each pass's byte budget, deadlines and dependencies. Every plan is re-checked before a frame is signed.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-sm text-mute" htmlFor="optmode">
            Solver run
          </label>
          <select id="optmode" value={mode} onChange={(e) => setMode(e.target.value as "platform" | "local")}>
            <option value="platform">Platform job (records job ID, may use credits)</option>
            <option value="local">Local QpiAI solver (free, no job ID)</option>
          </select>
          <Button onClick={optimize} busy={busy === "opt"} disabled={dirty} title={dirty ? "Save the queue first" : undefined}>
            Optimize with QpiAI Opt
          </Button>
        </div>
      </header>
      <ErrorNote error={error} onDismiss={() => setError(null)} />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <Panel
          title="Command queue"
          aside={
            <span className="flex gap-2">
              <Button kind="secondary" onClick={() => api.post("/api/queue/reset").then(load)}>
                Restore demo queue
              </Button>
              <Button kind="secondary" onClick={save} disabled={!dirty} busy={busy === "save"}>
                Save queue
              </Button>
            </span>
          }
        >
          <div className="mb-3 flex flex-wrap gap-3">
            {draft.passes.map((p: Json, i: number) => (
              <label key={p.index} className="text-sm">
                <span className="mr-1 text-mute">Pass {p.index} budget</span>
                <input
                  type="number"
                  min={800}
                  step={50}
                  className="w-24 tabular-nums"
                  value={p.budget_bytes}
                  onChange={(e) =>
                    setDraft((d: Json) => ({
                      ...d,
                      passes: d.passes.map((x: Json, j: number) => (j === i ? { ...x, budget_bytes: Number(e.target.value) } : x)),
                    }))
                  }
                />
                <span className="ml-1 text-mute">B</span>
              </label>
            ))}
          </div>
          <div className="overflow-x-auto">
            <table className="data w-full text-sm">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Command</th>
                  <th>Key</th>
                  <th title="1-100">Priority</th>
                  <th title="Latest pass it may be sent in">Deadline</th>
                  <th>After</th>
                  <th className="text-right">Frame</th>
                  <th>
                    <span className="sr-only">Remove</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {draft.commands.map((c: Json, i: number) => (
                  <tr key={c.id}>
                    <td className="font-cond font-semibold">{c.id}</td>
                    <td>
                      <div className="font-medium">{c.name}</div>
                      <div className="text-xs text-mute">{c.opcode_name}</div>
                    </td>
                    <td>
                      <span className={`inline-flex items-center gap-1 text-xs font-semibold ${c.role === "ADMIN" ? "text-[#137a55]" : "text-s1"}`}>
                        <span className={`h-2 w-2 rounded-sm ${c.role === "ADMIN" ? "bg-s3" : "bg-s1"}`} aria-hidden />
                        {c.role}
                      </span>
                    </td>
                    <td>
                      <input type="number" min={1} max={100} className="w-14 tabular-nums" value={c.priority} onChange={(e) => setCmd(i, "priority", Number(e.target.value))} aria-label={`${c.id} priority`} />
                    </td>
                    <td>
                      <select value={c.deadline_pass} onChange={(e) => setCmd(i, "deadline_pass", Number(e.target.value))} aria-label={`${c.id} deadline`}>
                        {draft.passes.map((p: Json) => (
                          <option key={p.index} value={p.index}>
                            pass {p.index}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <input
                        className="w-20"
                        value={(c.depends_on ?? []).join(", ")}
                        placeholder="none"
                        onChange={(e) => setCmd(i, "depends_on", e.target.value.split(",").map((s) => s.trim().toUpperCase()))}
                        aria-label={`${c.id} depends on`}
                      />
                    </td>
                    <td className="whitespace-nowrap text-right tabular-nums text-mute">{c.frame_bytes ? `${c.frame_bytes} B` : "on save"}</td>
                    <td>
                      <button
                        className="rounded px-1.5 text-mute hover:bg-reject/10 hover:text-reject focus-visible:outline focus-visible:outline-2 focus-visible:outline-quantum"
                        aria-label={`Remove ${c.id}`}
                        title={`Remove ${c.id}`}
                        onClick={() =>
                          setDraft((d: Json) => ({
                            ...d,
                            commands: d.commands
                              .filter((x: Json) => x.id !== c.id)
                              .map((x: Json) => ({ ...x, depends_on: (x.depends_on ?? []).filter((dep: string) => dep !== c.id) })),
                          }))
                        }
                      >
                        ✕
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <AddCommand draft={draft} onAdd={(c) => setDraft((d: Json) => ({ ...d, commands: [...d.commands, c] }))} />
          <p className="mt-3 text-xs text-mute">
            Each frame is a 16 B header, the command body and a 666 B Falcon signature. Every pass also carries a 715 B PASS_OPEN frame with the new QRNG nonce.
          </p>
        </Panel>

        <div className="space-y-5">
          {!plan ? (
            <Panel title="No plan yet">
              <p className="text-mute">
                Press <b>Optimize with QpiAI Opt</b>. The Opt result decides what the uplink sends; the greedy and brute-force baselines are shown only for comparison.
              </p>
            </Panel>
          ) : (
            <PlanResult plan={plan} stale={!!stale} />
          )}
        </div>
      </div>
      {plan && <WhyPanel plan={plan} />}
      <QaoaPanel />
    </div>
  );
}

function PlanResult({ plan, stale }: { plan: Json; stale: boolean }) {
  const o = plan.opt;
  const v = plan.validation;
  const inst = plan.instance;
  const byId: Record<string, Json> = Object.fromEntries(inst.commands.map((c: Json) => [c.id, c]));
  const maxBudget = Math.max(...inst.passes.map((p: Json) => p.budget_bytes));
  const fixture = o.execution_mode === "test-fixture";
  return (
    <>
      <Panel
        title="QpiAI Opt plan"
        aside={<Provenance kind={fixture ? "fixture" : o.execution_mode === "platform" ? "platform" : "opt_local"} />}
      >
        {stale && <p className="mb-3 rounded bg-caution/10 px-2 py-1 text-sm text-caution">The queue changed after this plan was made. Optimize again before running passes.</p>}
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
          <Fact label="Delivered priority">{v.objective}</Fact>
          <Fact label="Commands sent">
            {v.scheduled}/{v.scheduled + v.deferred}
          </Fact>
          <Fact label="Solver wall time">{o.wall_time_s ?? "—"} s</Fact>
          <Fact label="Feasibility re-check">
            <span className={v.feasible ? "text-accept" : "text-reject"}>{v.feasible ? "✓ Feasible" : "✗ Infeasible"}</span>
          </Fact>
        </dl>
        <dl className="mt-3 grid gap-1 text-sm sm:grid-cols-2">
          <div>
            <dt className="inline text-mute">Opt job ID </dt>
            <dd className="inline">
              <CopyId value={o.job_id} empty={o.execution_mode === "local" ? "local solve (no job ID)" : "none"} />
            </dd>
          </div>
          <div>
            <dt className="inline text-mute">Problem ID </dt>
            <dd className="inline">
              <CopyId value={o.problem_id} empty="—" />
            </dd>
          </div>
          <div>
            <dt className="inline text-mute">Model </dt>
            <dd className="inline">
              {o.model?.problem_class}, {o.model?.binary_variables} binaries, {o.model?.constraints} constraints
            </dd>
          </div>
          <div>
            <dt className="inline text-mute">Termination </dt>
            <dd className="inline">{o.info?.termination ?? o.model_status ?? "—"}</dd>
          </div>
        </dl>
        {!v.feasible && (
          <ul className="mt-2 list-disc pl-5 text-sm text-reject">
            {v.violations.map((x: string) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Pass timeline" aside={<span>bar length = bytes; full width = {fmtBytes(maxBudget)}</span>}>
        <div className="space-y-3">
          {inst.passes.map((p: Json) => {
            const ids = Object.entries(o.plan)
              .filter(([, t]) => t === p.index)
              .map(([id]) => id);
            const b = v.budgets.find((x: Json) => x.pass === p.index);
            const pct = (n: number) => `${(100 * n) / maxBudget}%`;
            return (
              <div key={p.index}>
                <div className="mb-1 flex justify-between text-sm">
                  <span className="font-cond font-semibold">Pass {p.index}</span>
                  <span className="tabular-nums text-mute">
                    {fmtBytes(b.used_bytes)} of {fmtBytes(p.budget_bytes)}, {fmtBytes(b.remaining_bytes)} left
                  </span>
                </div>
                <div className="relative flex h-9 gap-[2px] rounded bg-white ring-1 ring-rule" style={{ width: pct(p.budget_bytes) }}>
                  <div className="flex items-center justify-center rounded-l bg-s2 text-[0.7rem] font-semibold text-white" style={{ width: pct(p.pass_open_bytes) }} title={`PASS_OPEN ${p.pass_open_bytes} B`}>
                    open
                  </div>
                  {ids.map((id) => (
                    <div
                      key={id}
                      className={`flex items-center justify-center text-[0.72rem] font-semibold text-white ${byId[id].role === "ADMIN" ? "bg-s3" : "bg-s1"}`}
                      style={{ width: pct(byId[id].frame_bytes) }}
                      title={`${id} ${byId[id].name}: ${byId[id].frame_bytes} B`}
                    >
                      {id}
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
        <div className="mt-3 flex flex-wrap gap-4 text-xs text-mute">
          <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm bg-s2" /> PASS_OPEN (ADMIN, carries nonce)</span>
          <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm bg-s1" /> OPERATOR command</span>
          <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm bg-s3" /> ADMIN command</span>
        </div>
      </Panel>

      <Panel title="Against classical baselines" aside="comparison only, never executed">
        <table className="data w-full text-sm">
          <thead>
            <tr>
              <th>Method</th>
              <th className="text-right">Delivered priority</th>
              <th className="text-right">Sent</th>
              <th>Feasible</th>
              <th className="text-right">Runtime</th>
            </tr>
          </thead>
          <tbody>
            <tr className="font-semibold">
              <td>QpiAI Opt</td>
              <td className="text-right tabular-nums">{v.objective}</td>
              <td className="text-right tabular-nums">{v.scheduled}</td>
              <td className="text-accept">{v.feasible ? "✓" : "✗"}</td>
              <td className="text-right tabular-nums">{o.wall_time_s} s</td>
            </tr>
            {["greedy", "brute_force"].map((k) => {
              const b = plan.baselines[k];
              return (
                <tr key={k}>
                  <td>{k === "greedy" ? "Greedy (priority first)" : "Brute force (exhaustive)"}</td>
                  <td className="text-right tabular-nums">{b.objective ?? "—"}</td>
                  <td className="text-right tabular-nums">{b.validation?.scheduled ?? "—"}</td>
                  <td>{b.validation ? (b.validation.feasible ? "✓" : "✗") : b.note}</td>
                  <td className="text-right tabular-nums">{b.runtime_s !== undefined ? `${Number(b.runtime_s).toFixed(3)} s` : "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="mt-2 text-sm text-mute">
          {plan.comparison.opt_matches_brute_force
            ? "Opt reached the certified optimum found by exhaustive search."
            : plan.comparison.brute_force_objective !== null
              ? `Opt is ${(plan.comparison.brute_force_objective - v.objective).toFixed(2)} below the exhaustive optimum.`
              : "Exhaustive search not run for this queue size."}{" "}
          Opt delivers {plan.comparison.opt_vs_greedy >= 0 ? "+" : ""}
          {plan.comparison.opt_vs_greedy} priority versus greedy.
        </p>
      </Panel>
    </>
  );
}

function WhyPanel({ plan }: { plan: Json }) {
  const byId: Record<string, Json> = Object.fromEntries(plan.instance.commands.map((c: Json) => [c.id, c]));
  return (
    <Panel title="Why each command was sent or held">
      <ul className="grid gap-x-6 gap-y-2 md:grid-cols-2">
        {plan.explanations.map((e: Json) => {
          const [label, cls] = STATUS_TEXT[e.status] ?? [e.status, ""];
          return (
            <li key={e.id} className="grid grid-cols-[3rem_1fr] gap-2 border-b border-[#e3e9ef] pb-2 text-sm">
              <span className="font-cond text-base font-semibold">{e.id}</span>
              <span>
                <span className={`font-semibold ${cls}`}>{label}</span> <span className="text-mute">{byId[e.id]?.name}</span>
                <span className="block text-mute">{e.reason}</span>
              </span>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

function QaoaPanel() {
  const [rec, setRec] = useState<Json | null>(null);
  const [cfg, setCfg] = useState<Json | null>(null);
  const [mode, setMode] = useState("platform");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.get("/api/qaoa").then((r) => setRec(r?.qaoa ? r : null));
    api.get("/api/config").then((c) => {
      setCfg(c.config);
      setMode(c.config.qaoa_mode);
    });
  }, []);
  const run = async () => {
    if (mode === "platform" && !confirm(`Run QAOA on ${cfg?.qaoa_device}? Each optimizer step is a QCloud job (up to ~${(cfg?.qaoa_max_iterations ?? 30) + 2}) and may use credits.`)) return;
    setBusy(true);
    setError(null);
    try {
      setRec(await api.post("/api/qaoa/run", { mode }));
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const c = rec?.comparison;
  return (
    <Panel
      title="QAOA on a reduced instance"
      aside={
        <span className="flex flex-wrap items-center gap-2">
          <select value={mode} onChange={(e) => setMode(e.target.value)} aria-label="QAOA execution">
            <option value="platform">QCloud ({cfg?.qaoa_device ?? "simulator"})</option>
            <option value="local">Local QpiAI simulator (labelled)</option>
          </select>
          <Button kind="quantum" onClick={run} busy={busy}>
            Run QAOA
          </Button>
        </span>
      }
    >
      <p className="max-w-3xl text-sm text-mute">
        A slice of the live queue (5 commands, 2 passes, 2 frame slots per pass) is compiled to a QUBO by the Opt modeller and solved with
        QAOA through qpiai-opt[quantum], next to the classical Opt solver and exhaustive search on the same QUBO. QAOA is not expected to beat
        classical methods at this size; this is an honest comparison.
      </p>
      <ErrorNote error={error} onDismiss={() => setError(null)} />
      {rec && (
        <div className="mt-3 grid gap-4 lg:grid-cols-[1fr_1.2fr]">
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Fact label="Qubits">{rec.qubits}</Fact>
            <Fact label="Circuit jobs">{rec.qaoa.job_ids.length}</Fact>
            <Fact label="QAOA wall time">{rec.qaoa.wall_time_s} s</Fact>
            <Fact label="QAOA objective">{rec.qaoa.objective ?? "none"}</Fact>
            <Fact label="Classical Opt">{c.opt_objective ?? "—"}</Fact>
            <Fact label="Exact optimum">{c.brute_force_optimum}</Fact>
          </dl>
          <div className="text-sm">
            <div className="mb-1 flex items-center gap-2">
              <Provenance kind={rec.qaoa.execution_mode === "platform" ? "cloud" : "local"} />
              <span className="text-mute">{rec.qaoa.backend ?? rec.device_name}</span>
            </div>
            <p className={c.qaoa_reached_optimum ? "text-accept" : "text-caution"}>
              {c.qaoa_reached_optimum ? "✓ QAOA reached the exact optimum." : `QAOA gap to optimum: ${c.qaoa_gap_to_optimum ?? "no feasible sample"}.`}
            </p>
            <p className="mt-1 text-mute">QCloud circuit job IDs</p>
            <div className="max-h-28 overflow-y-auto">
              {rec.qaoa.job_ids.length ? rec.qaoa.job_ids.map((j: string) => <div key={j}><CopyId value={j} /></div>) : <span className="italic text-mute">none (local run)</span>}
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}

function AddCommand({ draft, onAdd }: { draft: Json; onAdd: (c: Json) => void }) {
  const ops = Object.entries(draft.opcodes ?? {})
    .map(([k, v]: [string, Json]) => ({ code: Number(k), ...v }))
    .filter((o) => o.name !== "PASS_OPEN");
  const nextId = () => {
    const nums = draft.commands.map((c: Json) => Number(String(c.id).replace(/\D/g, ""))).filter((n: number) => !Number.isNaN(n));
    return `C${String((nums.length ? Math.max(...nums) : 0) + 1).padStart(2, "0")}`;
  };
  const blank = () => ({ id: nextId(), name: "", opcode: ops[0]?.code ?? 16, args_hex: "", role: "OPERATOR", priority: 5, deadline_pass: draft.passes.length, after: "" });
  const [open, setOpen] = useState(false);
  const [f, setF] = useState<Json>(blank);
  const [err, setErr] = useState<string | null>(null);
  const op = ops.find((o) => o.code === Number(f.opcode));
  const add = () => {
    const id = String(f.id).trim().toUpperCase();
    if (!id) return setErr("Give the command an ID.");
    if (draft.commands.some((c: Json) => c.id === id)) return setErr(`${id} already exists.`);
    if (!/^([0-9a-fA-F]{2})*$/.test(f.args_hex.replace(/\s+/g, ""))) return setErr("Arguments must be hex bytes, e.g. 0b01.");
    if (f.args_hex.replace(/\s+/g, "").length / 2 > 31) return setErr("Arguments are limited to 31 bytes (32-byte body).");
    onAdd({
      id, name: f.name.trim() || op?.name || id, opcode: Number(f.opcode), args_hex: f.args_hex.replace(/\s+/g, "").toLowerCase(),
      role: f.role, priority: Number(f.priority), deadline_pass: Number(f.deadline_pass),
      depends_on: String(f.after).split(",").map((x: string) => x.trim().toUpperCase()).filter(Boolean), note: "added in planner",
    });
    setErr(null);
    setOpen(false);
  };
  if (!open)
    return (
      <div className="mt-3">
        <Button kind="secondary" onClick={() => { setF(blank()); setOpen(true); }}>
          Add command
        </Button>
      </div>
    );
  const set = (k: string, v: Json) => setF((x: Json) => ({ ...x, [k]: v }));
  return (
    <div className="mt-3 rounded border border-rule bg-white p-3">
      <div className="grid gap-2 sm:grid-cols-4">
        <label className="text-sm">
          <span className="block text-mute">ID</span>
          <input className="w-full" value={f.id} onChange={(e) => set("id", e.target.value)} />
        </label>
        <label className="text-sm sm:col-span-3">
          <span className="block text-mute">Name</span>
          <input className="w-full" value={f.name} onChange={(e) => set("name", e.target.value)} placeholder={op?.desc} />
        </label>
        <label className="text-sm sm:col-span-2">
          <span className="block text-mute">Opcode</span>
          <select className="w-full" value={f.opcode} onChange={(e) => set("opcode", Number(e.target.value))}>
            {ops.map((o) => (
              <option key={o.code} value={o.code}>
                0x{o.code.toString(16).padStart(2, "0")} {o.name}
                {o.admin_only ? " (admin only)" : ""}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm sm:col-span-2">
          <span className="block text-mute">Arguments (hex)</span>
          <input className="w-full font-mono" value={f.args_hex} onChange={(e) => set("args_hex", e.target.value)} placeholder="none" />
        </label>
        <label className="text-sm">
          <span className="block text-mute">Signing key</span>
          <select className="w-full" value={f.role} onChange={(e) => set("role", e.target.value)}>
            <option>OPERATOR</option>
            <option>ADMIN</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="block text-mute">Priority (1-100)</span>
          <input className="w-full" type="number" min={1} max={100} value={f.priority} onChange={(e) => set("priority", e.target.value)} />
        </label>
        <label className="text-sm">
          <span className="block text-mute">Deadline</span>
          <select className="w-full" value={f.deadline_pass} onChange={(e) => set("deadline_pass", e.target.value)}>
            {draft.passes.map((p: Json) => (
              <option key={p.index} value={p.index}>
                pass {p.index}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="block text-mute">After (IDs)</span>
          <input className="w-full" value={f.after} onChange={(e) => set("after", e.target.value)} placeholder="none" />
        </label>
      </div>
      {op?.admin_only && f.role === "OPERATOR" && (
        <p className="mt-2 text-sm text-caution">{op.name} is admin-only: signed with the OPERATOR key it will be scheduled but rejected onboard with E_UNAUTHORIZED.</p>
      )}
      {err && <p className="mt-2 text-sm text-reject">{err}</p>}
      <div className="mt-2 flex gap-2">
        <Button onClick={add}>Add to queue</Button>
        <Button kind="secondary" onClick={() => setOpen(false)}>
          Cancel
        </Button>
      </div>
      <p className="mt-1 text-xs text-mute">Then press Save queue; the server checks body size, IDs, dependencies and cycles.</p>
    </div>
  );
}
