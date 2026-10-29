import { useEffect, useState } from "react";
import { api, REASON_TEXT, type Json } from "../api";
import { useLive } from "../live";
import { Button, ErrorNote, Fact, Panel, StepLadder, VerdictTag } from "./ui";

type Tab = "compose" | "raw" | "cases";

const OPCODES: [string, string][] = [
  ["NOOP_PING", "0x10 NOOP_PING"],
  ["SET_ATTITUDE_MODE", "0x11 SET_ATTITUDE_MODE"],
  ["CAPTURE_IMAGE", "0x12 CAPTURE_IMAGE"],
  ["DOWNLINK_DATA", "0x13 DOWNLINK_DATA"],
  ["SET_HEATER", "0x14 SET_HEATER"],
  ["ORBIT_BURN", "0x20 ORBIT_BURN (admin only)"],
  ["SET_SAFE_MODE", "0x21 SET_SAFE_MODE (admin only)"],
  ["REBOOT_SUBSYSTEM", "0x22 REBOOT_SUBSYSTEM (admin only)"],
  ["PATCH_FIRMWARE", "0x23 PATCH_FIRMWARE (admin only)"],
  ["PASS_OPEN", "0x01 PASS_OPEN (admin only, 32-byte nonce arg)"],
];

function Decoded({ d }: { d: Json }) {
  if (!d) return null;
  const rows: [string, React.ReactNode][] = [
    ["Length", `${d.length} B${d.length_consistent === false ? " (inconsistent with header)" : ""}`],
  ];
  if (d.version !== undefined)
    rows.push(
      ["Version / sat / key_id", `${d.version} / ${d.sat_id} / ${d.key_id}`],
      ["Counter", d.counter],
      ["Expiry", `${d.expiry} (${d.expiry_in_s >= 0 ? `in ${d.expiry_in_s} s` : `${-d.expiry_in_s} s ago`})`],
      ["Command", d.opcode_name ? `${d.opcode_name} args ${d.args_hex || "none"}` : "none"],
      ["Signature", `${d.signature_len} B, starts ${d.signature_prefix}`],
    );
  return (
    <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-0.5 text-sm">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-mute">{k}</dt>
          <dd className="tabular-nums">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function FrameResult({ r, onEdit }: { r: Json; onEdit?: (hex: string) => void }) {
  const v = r.verdict;
  return (
    <div className="mt-4 grid gap-4 lg:grid-cols-2">
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <VerdictTag verdict={v.verdict} reason={v.reason} />
          <span className="text-sm text-mute">{REASON_TEXT[v.reason]}</span>
        </div>
        <p className="text-sm">
          <span className="text-mute">Counter before / after </span>
          <span className="tabular-nums">
            {r.counter_before} / {r.counter_after}
          </span>
          <span className="text-mute">, NV writes </span>
          {v.nv_writes}
          {v.log_seq && <span className="text-mute">, audit log #{v.log_seq}</span>}
        </p>
        {r.built && (
          <p className="text-sm text-mute">
            Signed with the {r.built.key} under the {r.built.signed_under}; counter {r.built.counter} ({r.built.counter_source})
            {r.built.mutations?.length ? `; then ${r.built.mutations.join(", ")}` : ""}.
          </p>
        )}
        <Decoded d={r.decoded} />
        <div>
          <div className="flex items-center justify-between text-xs text-mute">
            <span>Frame bytes ({r.frame_hex.length / 2} B)</span>
            {onEdit && (
              <button className="text-ink underline" onClick={() => onEdit(r.frame_hex)}>
                Edit these bytes
              </button>
            )}
          </div>
          <pre className="mt-1 max-h-28 overflow-auto whitespace-pre-wrap break-all rounded bg-white p-2 font-mono text-[0.72rem] ring-1 ring-rule">{r.frame_hex}</pre>
        </div>
      </div>
      <div>
        <h4 className="mb-1 font-cond text-base font-semibold">Onboard checks</h4>
        <StepLadder steps={v.steps} animate key={r.frame_hex + v.log_seq} />
      </div>
    </div>
  );
}

function L({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="block text-mute">{label}</span>
      {children}
      {hint && <span className="block text-xs text-mute">{hint}</span>}
    </label>
  );
}

function Compose({ onSent, satDefault }: { onSent: (r: Json) => void; satDefault: number }) {
  const [f, setF] = useState({
    key: "OPERATOR", opcode: "CAPTURE_IMAGE", args_hex: "0b01", sat_id: String(satDefault), expiry_offset_s: "600",
    counter: "auto", counterValue: "", nonce: "current", nonceHex: "", key_id: "", flip_bit: "",
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (k: string, v: string) => setF((x) => ({ ...x, [k]: v }));
  useEffect(() => set("sat_id", String(satDefault)), [satDefault]);
  const send = async () => {
    setBusy(true);
    setError(null);
    try {
      const body: Json = {
        key: f.key, opcode: f.opcode, args_hex: f.args_hex, sat_id: f.sat_id, expiry_offset_s: f.expiry_offset_s,
        counter: f.counter === "auto" ? "auto" : f.counterValue, nonce: f.nonce === "hex" ? f.nonceHex : f.nonce,
      };
      if (f.key_id !== "") body.key_id = f.key_id;
      if (f.flip_bit !== "") body.mutate = { flip_bit: f.flip_bit };
      onSent(await api.post("/api/judge/compose", body));
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <L label="Signing key">
          <select className="w-full" value={f.key} onChange={(e) => set("key", e.target.value)}>
            <option value="OPERATOR">Ground OPERATOR key</option>
            <option value="ADMIN">Ground ADMIN key</option>
            <option value="ATTACKER">Attacker's own key (unknown onboard)</option>
          </select>
        </L>
        <L label="Opcode">
          <select className="w-full" value={f.opcode} onChange={(e) => set("opcode", e.target.value)}>
            {OPCODES.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </L>
        <L label="Arguments (hex)" hint="up to 31 bytes; PASS_OPEN needs exactly 32">
          <input className="w-full font-mono" value={f.args_hex} onChange={(e) => set("args_hex", e.target.value)} placeholder="none" />
        </L>
        <L label="Satellite ID" hint={`this spacecraft is ${satDefault}`}>
          <input className="w-full" type="number" min={0} max={255} value={f.sat_id} onChange={(e) => set("sat_id", e.target.value)} />
        </L>
        <L label="Expiry, seconds from now" hint="negative = already expired">
          <input className="w-full" type="number" value={f.expiry_offset_s} onChange={(e) => set("expiry_offset_s", e.target.value)} />
        </L>
        <L label="Counter">
          <div className="flex gap-2">
            <select value={f.counter} onChange={(e) => set("counter", e.target.value)}>
              <option value="auto">next ground counter</option>
              <option value="set">set value</option>
            </select>
            {f.counter === "set" && <input className="w-full" type="number" min={0} value={f.counterValue} onChange={(e) => set("counterValue", e.target.value)} />}
          </div>
        </L>
        <L label="Sign under nonce">
          <div className="flex gap-2">
            <select value={f.nonce} onChange={(e) => set("nonce", e.target.value)}>
              <option value="current">current pass</option>
              <option value="previous">previous pass</option>
              <option value="random">random</option>
              <option value="hex">custom hex</option>
            </select>
            {f.nonce === "hex" && <input className="w-full font-mono" value={f.nonceHex} onChange={(e) => set("nonceHex", e.target.value)} placeholder="64 hex digits" />}
          </div>
        </L>
        <L label="Advanced" hint="key_id override; bit to flip after signing (0 = first bit)">
          <div className="flex gap-2">
            <input className="w-20" placeholder="key_id" value={f.key_id} onChange={(e) => set("key_id", e.target.value)} />
            <input className="w-24" placeholder="flip bit" value={f.flip_bit} onChange={(e) => set("flip_bit", e.target.value)} />
          </div>
        </L>
      </div>
      <div className="mt-3">
        <Button onClick={send} busy={busy}>
          Sign and send to the satellite
        </Button>
      </div>
      <div className="mt-2">
        <ErrorNote error={error} onDismiss={() => setError(null)} />
      </div>
    </div>
  );
}

function Raw({ hex, setHex, onSent }: { hex: string; setHex: (h: string) => void; onSent: (r: Json) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [bit, setBit] = useState("");
  const clean = hex.replace(/\s+/g, "");
  const flip = () => {
    const b = Number(bit);
    if (!Number.isInteger(b) || b < 0 || b >= (clean.length / 2) * 8) return setError(`bit must be 0 to ${(clean.length / 2) * 8 - 1}`);
    const bytes = clean.match(/.{2}/g)!.map((x) => parseInt(x, 16));
    bytes[Math.floor(b / 8)] ^= 1 << (7 - (b % 8));
    setHex(bytes.map((x) => x.toString(16).padStart(2, "0")).join(""));
    setError(null);
  };
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-sm">
        <Button kind="secondary" onClick={() => api.get("/api/judge/last").then((r) => (r.frame_hex ? setHex(r.frame_hex) : setError("No frame has been sent yet.")))}>
          Load last frame sent
        </Button>
        <span className="text-mute">Header: bytes 0–15, body from byte 16, Falcon signature = last 666 bytes.</span>
      </div>
      <textarea className="h-28 w-full font-mono text-xs" value={hex} onChange={(e) => setHex(e.target.value)} placeholder="Paste frame bytes as hex" spellCheck={false} />
      <div className="mt-2 flex flex-wrap items-center gap-2 text-sm">
        <span className="text-mute">{clean.length / 2} bytes</span>
        <input className="w-24" placeholder="bit #" value={bit} onChange={(e) => setBit(e.target.value)} aria-label="Bit to flip" />
        <Button kind="secondary" onClick={flip} disabled={!clean}>
          Flip bit
        </Button>
        <Button
          busy={busy}
          disabled={!clean}
          onClick={async () => {
            setBusy(true);
            setError(null);
            try {
              onSent(await api.post("/api/judge/raw", { hex }));
            } catch (e: Json) {
              setError(e.message);
            } finally {
              setBusy(false);
            }
          }}
        >
          Send these bytes
        </Button>
      </div>
      <div className="mt-2">
        <ErrorNote error={error} onDismiss={() => setError(null)} />
      </div>
    </div>
  );
}

function Cases() {
  const [text, setText] = useState("");
  const [run, setRun] = useState<Json | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [format, setFormat] = useState<"json" | "csv">("json");
  const loadSample = async (fmt: "json" | "csv") => {
    const s = await api.get("/api/judge/sample");
    setFormat(fmt);
    setText(fmt === "json" ? JSON.stringify(s.cases, null, 2) : s.csv);
  };
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      let body: Json;
      const t = text.trim();
      if (t.startsWith("[") || t.startsWith("{")) {
        const parsed = JSON.parse(t);
        body = Array.isArray(parsed) ? { cases: parsed } : parsed;
      } else body = { csv: text };
      setRun(await api.post("/api/judge/cases", body));
    } catch (e: Json) {
      setError(e instanceof SyntaxError ? `JSON could not be parsed: ${e.message}` : e.message);
    } finally {
      setBusy(false);
    }
  };
  const download = () => {
    const blob = new Blob([JSON.stringify(run, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `judge-run-${run.created_utc.slice(0, 19).replace(/[:T]/g, "")}.json`;
    a.click();
  };
  const t = run?.totals;
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-sm">
        <label className="inline-flex cursor-pointer items-center rounded border border-rule bg-white px-3 py-2 font-semibold hover:border-ink">
          Upload .json or .csv
          <input
            type="file"
            accept=".json,.csv,application/json,text/csv"
            className="sr-only"
            onChange={async (e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              setText(await file.text());
              setFormat(file.name.toLowerCase().endsWith(".csv") ? "csv" : "json");
              e.target.value = "";
            }}
          />
        </label>
        <Button kind="secondary" onClick={() => loadSample("json")}>
          Load JSON sample
        </Button>
        <Button kind="secondary" onClick={() => loadSample("csv")}>
          Load CSV sample
        </Button>
        <span className="text-mute">{format.toUpperCase()} detected from content when you run</span>
      </div>
      <textarea className="h-44 w-full font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} placeholder='[{"id": "J1", "key": "OPERATOR", "opcode": "CAPTURE_IMAGE", "args_hex": "0b01", "expect": "ACCEPT"}]' />
      <details className="mt-1 text-xs text-mute">
        <summary className="cursor-pointer">Case fields</summary>
        <p className="mt-1">
          <b>expect</b> (required): ACCEPT, REJECT, or a reason code such as E_REPLAY. One of: compose fields (<b>key</b> OPERATOR / ADMIN / ATTACKER, <b>opcode</b>,{" "}
          <b>args_hex</b>, <b>sat_id</b>, <b>expiry_offset_s</b>, <b>counter</b> "auto" or a number, <b>nonce</b> current / previous / random / hex, <b>key_id</b>), or{" "}
          <b>raw_hex</b>, or <b>replay_of</b> (id of an earlier case). Optional: <b>mutate</b> {`{"flip_bit": n}`} (CSV column flip_bit), <b>new_window</b> true to start a fresh
          contact window first, <b>description</b>.
        </p>
      </details>
      <div className="mt-2">
        <Button onClick={go} busy={busy} disabled={!text.trim()}>
          Run cases against the satellite
        </Button>
      </div>
      <div className="mt-2">
        <ErrorNote error={error} onDismiss={() => setError(null)} />
      </div>
      {run && (
        <div className="mt-4 space-y-3">
          <dl className="grid grid-cols-3 gap-3 sm:grid-cols-7">
            <Fact label="Cases">{t.cases}</Fact>
            <Fact label="Matched expectation">
              <span className="text-accept">{t.passed}</span>
            </Fact>
            <Fact label="Did not match">{t.failed}</Fact>
            <Fact label="False accepts" hint="Judge expected a rejection, the satellite accepted. Must be 0.">
              <span className={t.false_accepts ? "text-reject" : "text-accept"}>{t.false_accepts}</span>
            </Fact>
            <Fact label="False rejects">{t.false_rejects}</Fact>
            <Fact label="Other reason">{t.wrong_reason}</Fact>
            <Fact label="Case errors">{t.errors}</Fact>
          </dl>
          <p className="text-sm text-mute">
            {(t.pass_rate * 100).toFixed(1)}% of cases matched the judges' expected outcome. Saved as evidence/{run.evidence_file}.{" "}
            <button className="text-ink underline" onClick={download}>
              Download results
            </button>
          </p>
          <div className="max-h-[26rem] overflow-auto">
            <table className="data w-full text-sm">
              <thead className="sticky top-0 bg-panel">
                <tr>
                  <th>Case</th>
                  <th>Expected</th>
                  <th>Satellite said</th>
                  <th>Result</th>
                  <th className="text-right">Counter</th>
                  <th>Log #</th>
                </tr>
              </thead>
              <tbody>
                {run.results.map((c: Json) => (
                  <tr key={c.id}>
                    <td>
                      <span className="font-cond font-semibold">{c.id}</span> <span className="text-mute">{c.description}</span>
                      {c.error && <div className="text-xs text-reject">{c.error}</div>}
                    </td>
                    <td>
                      <code className="font-mono text-xs">{c.expect}</code>
                    </td>
                    <td>{c.verdict ? <VerdictTag verdict={c.verdict} reason={c.reason} /> : "—"}</td>
                    <td className={c.passed ? "font-semibold text-accept" : "font-semibold text-reject"}>
                      {c.passed ? "✓ " : "✗ "}
                      {c.outcome}
                    </td>
                    <td className="text-right tabular-nums">{c.counter_before !== undefined ? `${c.counter_before} → ${c.counter_after}` : "—"}</td>
                    <td className="tabular-nums">{c.log_seq ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default function JudgeConsole({ windowOpen }: { windowOpen: boolean }) {
  const { state, refreshState } = useLive();
  const [tab, setTab] = useState<Tab>("compose");
  const [result, setResult] = useState<Json | null>(null);
  const [hex, setHex] = useState("");
  const sat = state?.onboard?.sat_id ?? 42;
  const onSent = (r: Json) => {
    setResult(r);
    refreshState();
  };
  const tabs: [Tab, string][] = [
    ["compose", "Compose a frame"],
    ["raw", "Raw bytes"],
    ["cases", "Case file"],
  ];
  return (
    <Panel title="Judge console" aside="your own frames and test cases, checked by the real satellite process">
      {!windowOpen && <p className="mb-3 rounded bg-caution/10 px-3 py-2 text-sm text-caution">Open a contact window first (or set new_window on the first case in a case file).</p>}
      <div role="tablist" className="mb-4 flex flex-wrap gap-1 border-b border-rule">
        {tabs.map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={`-mb-px rounded-t border px-3 py-1.5 text-sm font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-quantum ${tab === id ? "border-rule border-b-panel bg-panel text-ink" : "border-transparent text-mute hover:text-ink"}`}
          >
            {label}
          </button>
        ))}
      </div>
      {tab === "compose" && <Compose onSent={onSent} satDefault={sat} />}
      {tab === "raw" && <Raw hex={hex} setHex={setHex} onSent={onSent} />}
      {tab === "cases" && <Cases />}
      {tab !== "cases" && result && (
        <FrameResult
          r={result}
          onEdit={(h) => {
            setHex(h);
            setTab("raw");
          }}
        />
      )}
    </Panel>
  );
}
