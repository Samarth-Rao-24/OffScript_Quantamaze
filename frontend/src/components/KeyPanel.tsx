import { useCallback, useEffect, useState } from "react";
import { api, short, type Json } from "../api";
import { useLive } from "../live";
import { Button, ErrorNote, Panel } from "./ui";

const STATE_CLS: Record<string, string> = {
  active: "bg-accept/10 text-accept",
  standby: "bg-ink/10 text-ink",
  revoked: "bg-reject/10 text-reject",
  retired: "bg-reject/10 text-reject",
  "not provisioned": "bg-caution/10 text-caution",
};

function Chip({ s }: { s: string }) {
  return <span className={`rounded px-2 py-0.5 text-xs font-semibold ${STATE_CLS[s] ?? "bg-ink/10"}`}>{s}</span>;
}

export default function KeyPanel({ windowOpen }: { windowOpen: boolean }) {
  const { subscribe, refreshState } = useLive();
  const [k, setK] = useState<Json | null>(null);
  const [role, setRole] = useState("OPERATOR");
  const [target, setTarget] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [last, setLast] = useState<Json | null>(null);

  const load = useCallback(() => api.get("/api/keys").then(setK).catch(() => undefined), []);
  useEffect(() => {
    load();
    return subscribe((e) => {
      if (["keys", "reset"].includes(e.type)) load();
    });
  }, [load, subscribe]);

  const standby = (k?.keys ?? []).filter((x: Json) => x.role === role && x.ground_state === "standby" && x.onboard_state === "standby");
  useEffect(() => {
    setTarget(standby[0] ? String(standby[0].key_id) : "");
  }, [role, k]); // eslint-disable-line react-hooks/exhaustive-deps

  const rotate = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.post("/api/keys/rotate", { role, to_kid: Number(target), pace_ms: 250 });
      setLast(r);
      await load();
      refreshState();
      window.dispatchEvent(new Event("plan-changed"));
    } catch (e: Json) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title="Key management and algorithm migration"
      aside={
        k && (
          <span className={`rounded px-2 py-0.5 text-xs font-semibold ${k.encrypted_at_rest ? "bg-accept/10 text-accept" : "bg-caution/10 text-caution"}`}>
            {k.encrypted_at_rest ? "Private keys encrypted at rest" : "Private keys in plaintext: set QUPLINK_KEY_PASSPHRASE"}
          </span>
        )
      }
    >
      <p className="max-w-4xl text-sm text-mute">
        Eight keys were pre-loaded onboard before launch: a primary and a spare Falcon-512 key per role, plus ML-DSA-44 (FIPS 204) and hybrid
        Ed25519 + Falcon-512 keys for migration. Rotating sends two ADMIN-signed frames: KEY_ACTIVATE for the new key, then KEY_REVOKE for the
        old one. The algorithm is tied to the key, so a frame can never pick a weaker one.
      </p>
      <ErrorNote error={error} onDismiss={() => setError(null)} />
      {k?.needs_reset && (
        <p className="mt-2 rounded bg-caution/10 px-2 py-1 text-sm text-caution">
          This satellite was provisioned before the key ring existed. Click Reset demo state (sidebar) once to pre-load all eight keys.
        </p>
      )}
      <div className="mt-3 overflow-x-auto">
        <table className="data w-full text-sm">
          <thead>
            <tr>
              <th>Key</th>
              <th>Role</th>
              <th>Algorithm</th>
              <th>Standard</th>
              <th className="text-right">Signature</th>
              <th>Onboard</th>
              <th>Ground</th>
              <th>Public key SHA-256</th>
            </tr>
          </thead>
          <tbody>
            {(k?.keys ?? []).map((x: Json) => (
              <tr key={x.key_id} className={x.signing ? "bg-quantum/5" : ""}>
                <td className="font-cond font-semibold tabular-nums">
                  {x.key_id}
                  {x.signing && <span className="ml-1 text-xs font-sans font-normal text-quantum">signing</span>}
                </td>
                <td>{x.role}</td>
                <td>{x.algorithm}</td>
                <td className="text-xs text-mute">{x.standard}</td>
                <td className="text-right tabular-nums">{x.signature_bytes} B</td>
                <td>
                  <Chip s={x.onboard_state} />
                </td>
                <td>
                  <Chip s={x.ground_state} />
                </td>
                <td>
                  <code className="font-mono text-xs">{short(x.public_key_sha256, 6)}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="block text-mute">Role</span>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="OPERATOR">OPERATOR</option>
            <option value="ADMIN">ADMIN</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="block text-mute">Rotate or migrate to</span>
          <select value={target} onChange={(e) => setTarget(e.target.value)} disabled={!standby.length}>
            {standby.length === 0 && <option value="">no standby key left</option>}
            {standby.map((x: Json) => (
              <option key={x.key_id} value={x.key_id}>
                key {x.key_id}: {x.algorithm} ({x.signature_bytes} B)
              </option>
            ))}
          </select>
        </label>
        <Button busy={busy} disabled={!windowOpen || !target} onClick={rotate} title={!windowOpen ? "Open a contact window first" : undefined}>
          Rotate key
        </Button>
        {!windowOpen && <span className="text-sm text-mute">Open a contact window first: key commands travel over the link.</span>}
      </div>
      {k && (
        <p className="mt-3 text-sm">
          <span className="text-mute">Current sizes: </span>
          OPERATOR frame (12 B command) <b className="tabular-nums">{k.frame_bytes_typical.OPERATOR} B</b>, ADMIN frame{" "}
          <b className="tabular-nums">{k.frame_bytes_typical.ADMIN} B</b>, PASS_OPEN <b className="tabular-nums">{k.pass_open_bytes} B</b>. About{" "}
          <b className="tabular-nums">{k.operator_commands_per_3600B_pass}</b> OPERATOR commands fit in a 3,600 B pass.
        </p>
      )}
      {last && (
        <div className="mt-3 rounded border border-accept/30 bg-accept/5 px-3 py-2 text-sm">
          {last.role} now signs with key {last.to_kid}; key {last.from_kid} is revoked onboard (
          {last.frames.map((f: Json) => `${f.label}: ${f.verdict}`).join(", ")}). Try the <b>Revoked key</b> attack above, and re-optimise in the Pass
          planner: plans are now sized for {last.after.frame_bytes_typical[last.role]} B {last.role} frames.
        </div>
      )}
    </Panel>
  );
}
