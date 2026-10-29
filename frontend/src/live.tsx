import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, type Json } from "./api";

type LiveCtx = {
  events: Json[];
  connected: boolean;
  state: Json | null;
  refreshState: () => Promise<void>;
  subscribe: (fn: (e: Json) => void) => () => void;
};

const Ctx = createContext<LiveCtx | null>(null);

export function LiveProvider({ children }: { children: ReactNode }) {
  const [events, setEvents] = useState<Json[]>([]);
  const [connected, setConnected] = useState(false);
  const [state, setState] = useState<Json | null>(null);
  const subs = useRef(new Set<(e: Json) => void>());

  const refreshState = useCallback(async () => {
    try {
      setState(await api.get("/api/state"));
    } catch {
      setState(null);
    }
  }, []);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stop = false;
    let timer: number | undefined;
    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws/frames`);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!stop) timer = window.setTimeout(connect, 1500);
      };
      ws.onmessage = (m) => {
        const e = JSON.parse(m.data);
        if (e.type === "hello") {
          setEvents(e.recent ?? []);
          return;
        }
        setEvents((prev) => [...prev.slice(-299), e]);
        subs.current.forEach((fn) => fn(e));
        if (e.type === "frame" && e.phase === "verdict") refreshState();
        if (["pass_done", "reset", "attack", "qrng", "plan", "alert", "nasa"].includes(e.type)) refreshState();
      };
    };
    connect();
    refreshState();
    const poll = window.setInterval(refreshState, 8000);
    return () => {
      stop = true;
      window.clearTimeout(timer);
      window.clearInterval(poll);
      ws?.close();
    };
  }, [refreshState]);

  const subscribe = useCallback((fn: (e: Json) => void) => {
    subs.current.add(fn);
    return () => {
      subs.current.delete(fn);
    };
  }, []);

  return <Ctx.Provider value={{ events, connected, state, refreshState, subscribe }}>{children}</Ctx.Provider>;
}

export function useLive(): LiveCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useLive outside provider");
  return c;
}
