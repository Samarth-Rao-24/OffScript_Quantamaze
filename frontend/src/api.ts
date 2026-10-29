// Thin client for the FastAPI backend. Same origin in production (served by
// FastAPI) and proxied by Vite in development. No secrets ever live here.

/* eslint-disable @typescript-eslint/no-explicit-any */
export type Json = any;

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function call(method: string, path: string, body?: unknown): Promise<Json> {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data: Json = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text };
  }
  if (!res.ok) {
    const msg = data?.error ?? data?.detail ?? `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data;
}

export const api = {
  get: (p: string) => call("GET", p),
  post: (p: string, b: unknown = {}) => call("POST", p, b),
  put: (p: string, b: unknown) => call("PUT", p, b),
};

export type Step = {
  step: number | null;
  name: string;
  label: string;
  status: "pass" | "fail" | "skipped";
  detail: string;
  us: number | null;
};

export type Verdict = {
  verdict: "ACCEPT" | "REJECT";
  reason: string;
  steps: Step[];
  counter: number | null;
  opcode_name: string | null;
  sig_checked: boolean;
  verify_us?: number;
  total_us: number;
  nv_writes: number;
  last_counter_after: number;
  executed?: string | null;
  log?: { seq: number };
  log_seq?: number;
};

export const REASON_TEXT: Record<string, string> = {
  OK: "Accepted",
  E_FLOOD_LOCKOUT: "Dropped by flood guard, no signature work",
  E_MALFORMED: "Frame could not be parsed",
  E_WRONG_SAT: "Addressed to another spacecraft",
  E_EXPIRED: "Expiry is before the onboard clock",
  E_REPLAY: "Counter not above the last accepted",
  E_BAD_SIG: "Signature invalid for this key and pass nonce",
  E_UNAUTHORIZED: "Key's role may not issue this command",
  E_KEY_REVOKED: "Signing key has been revoked",
  E_KEY_INACTIVE: "Signing key is pre-loaded but not activated",
  E_KEY_POLICY: "Key-management command breaks the key policy",
  LINK_REFUSED: "Ground link refused: pass byte budget reached",
};

export function short(hex: string | null | undefined, n = 10): string {
  if (!hex) return "—";
  return hex.length > n * 2 ? `${hex.slice(0, n)}…${hex.slice(-6)}` : hex;
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  return n >= 10000 ? `${(n / 1024).toFixed(1)} KB` : `${n.toLocaleString()} B`;
}

export function fmtUs(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  return n >= 1000 ? `${(n / 1000).toFixed(2)} ms` : `${n.toFixed(1)} µs`;
}
