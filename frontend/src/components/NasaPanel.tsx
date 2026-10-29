import { useEffect, useState } from "react";
import { api, fmtBytes, type Json } from "../api";
import { Button, ErrorNote, Fact, Mono, Panel } from "./ui";

const fmtTime = (iso?: string) =>
  iso ? new Date(iso).toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "—";

export default function NasaPanel({ budgetSource, onApplied }: { budgetSource?: Json; onApplied: () => void }) {
  const [rec, setRec] = useState<Json | null>(null);
  const [cfg, setCfg] = useState<Json | null>(null);
  const [bps, setBps] = useState("");
  const [minEl, setMinEl] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get("/api/nasa").then((r) => {
      setRec(r.latest);
      setCfg(r.config);
      setBps(String(r.config.uplink_bps));
      setMinEl(String(r.config.min_elevation_deg));
    });
  }, []);

  const fetchNasa = async () => {
    setBusy("fetch");
    setError(null);
    try {
      setRec(await api.post("/api/nasa/fetch", { uplink_bps: bps, min_elevation_deg: minEl }));
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  };
  const apply = async () => {
    setBusy("apply");
    setError(null);
    try {
      await api.post("/api/nasa/apply", { evidence_file: rec?.evidence_file });
      onApplied();
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  };

  const applied = budgetSource?.kind === "nasa" && rec && budgetSource.evidence_file === rec.evidence_file;
  const sw = rec?.space_weather;
  const gs = cfg?.ground_station;
  return (
    <Panel
      title="Pass windows from NASA orbit data"
      aside={
        <span className="flex flex-wrap items-center gap-2 text-sm">
          <span className={cfg?.nasa_key_configured ? "text-accept" : "text-mute"}>
            {cfg?.nasa_key_configured ? "✓ NASA key" : "DEMO_KEY (rate-limited)"}
          </span>
          {applied ? (
            <span className="rounded bg-accept/10 px-2 py-0.5 text-xs font-semibold text-accept">Budgets in use</span>
          ) : budgetSource?.kind === "nasa" ? (
            <span className="rounded bg-ink/10 px-2 py-0.5 text-xs font-semibold">Budgets from an earlier pull</span>
          ) : (
            <span className="rounded bg-ink/10 px-2 py-0.5 text-xs font-semibold">Queue uses manual budgets</span>
          )}
        </span>
      }
    >
      <p className="max-w-4xl text-sm text-mute">
        Real orbit, simulated satellite: the latest TLE for NORAD {cfg?.norad_id ?? "25544"} (ISS as a stand-in) from the TLE API in the
        api.nasa.gov catalogue gives the real passes over {gs?.name ?? "the ground station"}. Each pass budget is contact time × command-uplink
        allocation ÷ 8, minus a space-weather reserve after NASA DONKI reports a geomagnetic storm or X-class flare.
      </p>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="block text-mute">Command uplink allocation</span>
          <input className="w-24 tabular-nums" type="number" min={8} step={8} value={bps} onChange={(e) => setBps(e.target.value)} /> bit/s
        </label>
        <label className="text-sm">
          <span className="block text-mute">Minimum elevation</span>
          <input className="w-20 tabular-nums" type="number" min={0} max={60} value={minEl} onChange={(e) => setMinEl(e.target.value)} /> °
        </label>
        <Button kind="secondary" busy={busy === "fetch"} onClick={fetchNasa}>
          Fetch from NASA
        </Button>
        <Button busy={busy === "apply"} disabled={!rec?.complete || !!applied} onClick={apply} title={!rec?.complete ? "Need 4 usable passes" : undefined}>
          Use these budgets
        </Button>
      </div>
      <ErrorNote error={error} onDismiss={() => setError(null)} />
      {!rec && <p className="mt-3 text-sm text-mute">No NASA pull yet. Fetch to compute the next four real passes.</p>}
      {rec && (
        <div className="mt-4 grid gap-4 xl:grid-cols-[1.5fr_1fr]">
          <div>
            <table className="data w-full text-sm">
              <thead>
                <tr>
                  <th>Pass</th>
                  <th>AOS (your time)</th>
                  <th className="text-right">Contact</th>
                  <th className="text-right">Max elev.</th>
                  <th className="text-right">Raw budget</th>
                  <th className="text-right">Budget</th>
                </tr>
              </thead>
              <tbody>
                {rec.passes.map((p: Json) => (
                  <tr key={p.index}>
                    <td className="font-cond font-semibold">{p.index}</td>
                    <td>{fmtTime(p.aos_utc)}</td>
                    <td className="text-right tabular-nums">{(p.duration_s / 60).toFixed(1)} min</td>
                    <td className="text-right tabular-nums">{p.max_elevation_deg}°</td>
                    <td className="text-right tabular-nums text-mute">{fmtBytes(p.raw_budget_bytes)}</td>
                    <td className="text-right font-semibold tabular-nums">{fmtBytes(p.budget_bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rec.skipped_short?.length > 0 && (
              <p className="mt-1 text-xs text-mute">
                {rec.skipped_short.length} shorter pass(es) skipped: too little contact for PASS_OPEN plus one command.
              </p>
            )}
            {!rec.complete && <p className="mt-2 text-sm text-caution">Only {rec.passes.length} usable passes found; lower the minimum elevation or raise the allocation.</p>}
          </div>
          <div className="space-y-3 text-sm">
            <dl className="grid grid-cols-2 gap-3">
              <Fact label="Spacecraft orbit">{rec.tle.name}</Fact>
              <Fact label="TLE epoch" hint={rec.tle_stale ? "older than 14 days" : undefined}>
                {fmtTime(rec.tle.epoch_utc)} <span className="text-xs text-mute">({rec.tle_age_days} d old)</span>
              </Fact>
              <Fact label="Space-weather factor">×{sw?.factor}</Fact>
              <Fact label="Max Kp, last 72 h">{sw?.kp_max_72h ?? "—"}</Fact>
            </dl>
            <ul className="list-disc pl-5 text-mute">
              {sw?.reasons?.map((r: string) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
            {rec.errors?.donki && <p className="text-caution">DONKI unavailable, no margin applied: {rec.errors.donki}</p>}
            <p className="text-xs text-mute">
              Source: {rec.tle.source}
              {rec.donki ? `; DONKI via ${rec.donki.gst.source ?? "api.nasa.gov"}: GST ${rec.donki.gst.events.length} storm(s), FLR ${rec.donki.flr.events.length} flare(s) in ${rec.donki.window.start}..${rec.donki.window.end}` : ""}.
              Evidence: <Mono>{rec.evidence_file}</Mono>
            </p>
          </div>
        </div>
      )}
    </Panel>
  );
}
