"""Real pass windows from NASA data (orbit + space weather).

Our satellite is simulated, but its contact windows do not have to be invented.
This module takes a real spacecraft's orbit and real space-weather events and
turns them into the per-pass byte budgets that QpiAI Opt schedules against:

1. Orbit: the latest two-line element set (TLE) from the TLE API listed in the
   api.nasa.gov catalogue (tle.ivanstanojevic.me, no key needed). CelesTrak is
   a fallback. The default spacecraft is the ISS (NORAD 25544) as a stand-in.
2. Passes: SGP4 propagation with skyfield (a vetted library) finds the next
   passes over the ground station (default Bengaluru) above a minimum elevation.
3. Budget: contact seconds x command-uplink allocation (bit/s) / 8. The
   allocation is an explicit, adjustable assumption: the share of a low-rate
   TT&C link given to authenticated commands.
4. Space weather: NASA DONKI geomagnetic storms (Kp index) and solar flares
   from the last 7 days. Our margin policy holds back part of each budget
   after strong storms (ionospheric scintillation can cost link margin).

Every pull is saved to evidence/nasa/ with the raw responses (API key removed),
their SHA-256, the parameters and the derived passes, so budgets can be traced.
"""

from __future__ import annotations

import hashlib
import json
import math
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..common.atomic import atomic_write_json
from .queue import PASS_OPEN_FRAME_BYTES

TLE_SOURCES = [
    ("NASA TLE API (api.nasa.gov catalogue)", "https://tle.ivanstanojevic.me/api/tle/{norad}"),
    ("CelesTrak GP (fallback)", "https://celestrak.org/NORAD/elements/gp.php?CATNR={norad}&FORMAT=TLE"),
]
DONKI_URL = "https://api.nasa.gov/DONKI/{kind}?startDate={start}&endDate={end}&api_key={key}"
# NASA CCMC's own DONKI web service (same data, no key): used when the api.nasa.gov gateway fails
DONKI_CCMC_URL = "https://kauai.ccmc.gsfc.nasa.gov/DONKI/WS/get/{kind}?startDate={start}&endDate={end}"
RETRY_DELAYS_S = (2.0, 5.0)  # transient 5xx / 429 / 508 and network errors are retried twice
MIN_COMMAND_FRAME = 683  # smallest command frame (16 B header + 1 B body + 666 B signature)
MIN_USEFUL_BUDGET = PASS_OPEN_FRAME_BYTES + MIN_COMMAND_FRAME
USER_AGENT = "q-uplink-mission-control/1.0 (hackathon prototype)"


class NasaUnavailable(RuntimeError):
    pass


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _redact(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q = [(k, "***" if k.lower() == "api_key" and v != "DEMO_KEY" else v) for k, v in q]
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(q)))


def _http_once(url: str, timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/plain"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
        return r.status, r.read()


def http_get(url: str, timeout: float = 20.0, delays: tuple[float, ...] = RETRY_DELAYS_S) -> tuple[int, bytes]:
    import time

    last: Exception | None = None
    for attempt in range(len(delays) + 1):
        try:
            return _http_once(url, timeout)
        except urllib.error.HTTPError as exc:
            body = exc.read()[:200].decode("utf-8", "replace").replace("\n", " ")
            last = NasaUnavailable(f"HTTP {exc.code} from {_redact(url)}: {body.strip()}")
            if not (exc.code >= 500 or exc.code == 429):
                break  # 4xx (bad key, bad request) will not fix itself
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = NasaUnavailable(f"could not reach {_redact(url)}: {exc}")
        if attempt < len(delays):
            time.sleep(delays[attempt])
    assert last is not None
    raise last


# ------------------------------------------------------------------ TLE
def tle_checksum_ok(line: str) -> bool:
    if len(line) < 69 or not line[68].isdigit():
        return False
    s = sum(int(ch) if ch.isdigit() else 1 if ch == "-" else 0 for ch in line[:68])
    return s % 10 == int(line[68])


def tle_epoch(line1: str) -> datetime:
    yy = int(line1[18:20])
    day = float(line1[20:32])
    year = 2000 + yy if yy < 57 else 1900 + yy
    return datetime(year, 1, 1, tzinfo=timezone.utc) + timedelta(days=day - 1)


def parse_tle_payload(raw: bytes, source: str) -> dict:
    text = raw.decode("utf-8", "replace").strip()
    if text.startswith("{"):
        d = json.loads(text)
        name, l1, l2 = d.get("name"), d.get("line1"), d.get("line2")
    else:
        lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
        if len(lines) >= 3 and not lines[0].startswith("1 "):
            name, l1, l2 = lines[0].strip(), lines[1], lines[2]
        elif len(lines) >= 2:
            name, l1, l2 = None, lines[0], lines[1]
        else:
            raise NasaUnavailable(f"{source}: no TLE in response")
    if not (l1 and l2 and l1.startswith("1 ") and l2.startswith("2 ")):
        raise NasaUnavailable(f"{source}: response is not a two-line element set")
    if not (tle_checksum_ok(l1) and tle_checksum_ok(l2)):
        raise NasaUnavailable(f"{source}: TLE checksum failed")
    return {"name": name or f"NORAD {l1[2:7].strip()}", "line1": l1, "line2": l2}


def fetch_tle(norad: int) -> dict:
    errors = []
    for source, tmpl in TLE_SOURCES:
        url = tmpl.format(norad=int(norad))
        try:
            status, raw = http_get(url)
            tle = parse_tle_payload(raw, source)
            ep = tle_epoch(tle["line1"])
            return {**tle, "norad": int(norad), "source": source, "url": _redact(url), "http_status": status,
                    "raw": raw.decode("utf-8", "replace"), "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    "epoch_utc": ep.isoformat(), "fallback_errors": errors}
        except NasaUnavailable as exc:
            errors.append(str(exc))
    raise NasaUnavailable("no TLE source reachable: " + " | ".join(errors))


# ------------------------------------------------------------------ DONKI
def fetch_donki(api_key: str | None, *, days: int = 7, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    key = api_key or "DEMO_KEY"
    start, end = (now - timedelta(days=days)).date().isoformat(), now.date().isoformat()
    out: dict = {"window": {"start": start, "end": end}, "key_used": "DEMO_KEY" if key == "DEMO_KEY" else "NASA_API_KEY"}
    for kind in ("GST", "FLR"):
        url = DONKI_URL.format(kind=kind, start=start, end=end, key=urllib.parse.quote(key))
        try:
            status, raw = http_get(url)
        except NasaUnavailable as exc:
            # same DONKI database, served directly by NASA CCMC without the api.nasa.gov gateway
            url_ccmc = DONKI_CCMC_URL.format(kind=kind, start=start, end=end)
            out.setdefault("gateway_errors", []).append(str(exc))
            url = url_ccmc
            status, raw = http_get(url)
        text = raw.decode("utf-8", "replace").strip()
        data = json.loads(text) if text else []
        if not isinstance(data, list):
            raise NasaUnavailable(f"DONKI {kind}: unexpected response {text[:200]}")
        out[kind.lower()] = {"url": _redact(url), "http_status": status, "events": data,
                             "source": "NASA CCMC DONKI web service" if "ccmc" in url else "api.nasa.gov DONKI",
                             "raw_sha256": hashlib.sha256(raw).hexdigest()}
    return out


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.strptime(s[:16], "%Y-%m-%dT%H:%M")
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def space_weather_margin(donki: dict | None, *, now: datetime | None = None) -> dict:
    """Our margin policy (not a NASA product): budgets keep a reserve after strong
    geomagnetic storms (Kp >= 5 in the last 72 h) and recent X-class flares."""
    now = now or datetime.now(timezone.utc)
    if not donki:
        return {"factor": 1.0, "kp_max_72h": None, "reasons": ["space weather not fetched: no margin applied"],
                "storms": [], "flares": []}
    kps = []
    storms = []
    for g in (donki.get("gst") or {}).get("events", []):
        for k in g.get("allKpIndex") or []:
            t = _ts(k.get("observedTime"))
            try:
                kp = float(k.get("kpIndex"))
            except (TypeError, ValueError):
                continue
            if t and now - t <= timedelta(hours=72):
                kps.append(kp)
        storms.append({"id": g.get("gstID"), "start": g.get("startTime"),
                       "kp_max": max([float(k.get("kpIndex") or 0) for k in g.get("allKpIndex") or []] or [0]),
                       "link": g.get("link")})
    flares = []
    for f in (donki.get("flr") or {}).get("events", []):
        flares.append({"id": f.get("flrID"), "class": f.get("classType"), "peak": f.get("peakTime") or f.get("beginTime"),
                       "region": f.get("activeRegionNum"), "link": f.get("link")})
    kp_max = max(kps) if kps else 0.0
    factor, reasons = 1.0, []
    if kp_max >= 7:
        factor *= 0.70
        reasons.append(f"severe geomagnetic storm in the last 72 h (Kp {kp_max:g}): keep 30% margin")
    elif kp_max >= 5:
        factor *= 0.85
        reasons.append(f"geomagnetic storm in the last 72 h (Kp {kp_max:g}): keep 15% margin")
    recent_x = [f for f in flares if (f["class"] or "").upper().startswith("X")
                and (_ts(f["peak"]) and now - _ts(f["peak"]) <= timedelta(hours=24))]
    if recent_x:
        factor *= 0.90
        reasons.append(f"X-class flare in the last 24 h ({recent_x[0]['class']}): keep a further 10% margin")
    if not reasons:
        reasons.append(f"quiet: max Kp {kp_max:g} in the last 72 h and no X-class flare in 24 h, no margin needed")
    return {"factor": round(factor, 4), "kp_max_72h": kp_max, "reasons": reasons,
            "storms": storms[-10:], "flares": flares[-10:]}


# ------------------------------------------------------------------ passes
def predict_passes(line1: str, line2: str, name: str, *, lat: float, lon: float, alt_m: float,
                   start: datetime, hours: float = 72.0, min_el: float = 10.0) -> list[dict]:
    from skyfield.api import EarthSatellite, load, wgs84

    ts = load.timescale()
    sat = EarthSatellite(line1, line2, name, ts)
    gs = wgs84.latlon(lat, lon, elevation_m=alt_m)
    t0 = ts.from_datetime(start)
    t1 = ts.from_datetime(start + timedelta(hours=hours))
    times, events = sat.find_events(gs, t0, t1, altitude_degrees=min_el)
    passes, cur = [], None
    for t, e in zip(times, events):
        if e == 0:
            cur = {"aos": t}
        elif e == 1 and cur is not None:
            alt, az, dist = (sat - gs).at(t).altaz()
            if alt.degrees > cur.get("max_el", -90):
                cur.update(tca=t, max_el=alt.degrees, range_km=dist.km)
        elif e == 2 and cur is not None and "tca" in cur:
            aos, los = cur["aos"].utc_datetime(), t.utc_datetime()
            passes.append({"aos_utc": aos.isoformat(), "tca_utc": cur["tca"].utc_datetime().isoformat(),
                           "los_utc": los.isoformat(), "duration_s": round((los - aos).total_seconds(), 1),
                           "max_elevation_deg": round(cur["max_el"], 1), "range_at_tca_km": round(cur["range_km"], 0)})
            cur = None
    return passes


def budgets_from_passes(passes: list[dict], *, uplink_bps: float, factor: float, n: int) -> dict:
    chosen, skipped = [], []
    for p in passes:
        raw = int(math.floor(p["duration_s"] * uplink_bps / 8.0))
        budget = int(math.floor(raw * factor))
        row = {**p, "raw_budget_bytes": raw, "budget_bytes": budget}
        if budget < MIN_USEFUL_BUDGET:
            skipped.append({**row, "why": f"{budget} B < {MIN_USEFUL_BUDGET} B (PASS_OPEN + one command)"})
            continue
        if len(chosen) < n:
            chosen.append({**row, "index": len(chosen) + 1})
    return {"passes": chosen, "skipped_short": skipped}


def pass_label(p: dict, satname: str, gs_name: str) -> str:
    return (f"AOS {p['aos_utc'][:16].replace('T', ' ')} UTC · {p['duration_s'] / 60:.1f} min · "
            f"max {p['max_elevation_deg']:.0f}°")


def nasa_pull(*, evidence_dir: Path, api_key: str | None, norad: int, gs: dict, uplink_bps: float, min_el: float,
              n_passes: int = 4, hours: float = 72.0, now: datetime | None = None,
              tle: dict | None = None, donki: dict | None = None) -> dict:
    """Fetch (unless tle/donki are supplied, e.g. by tests), derive passes and budgets, record evidence."""
    now = now or datetime.now(timezone.utc)
    errors = {}
    if tle is None:
        tle = fetch_tle(norad)  # an orbit is mandatory
    if donki is None:
        try:
            donki = fetch_donki(api_key, now=now)
        except NasaUnavailable as exc:  # space weather is optional: no margin, clearly reported
            errors["donki"] = str(exc)
            donki = None
    age_days = (now - datetime.fromisoformat(tle["epoch_utc"])).total_seconds() / 86400
    margin = space_weather_margin(donki, now=now)
    all_passes = predict_passes(tle["line1"], tle["line2"], tle["name"], lat=gs["lat"], lon=gs["lon"],
                                alt_m=gs.get("alt_m", 0.0), start=now, hours=hours, min_el=min_el)
    b = budgets_from_passes(all_passes, uplink_bps=uplink_bps, factor=margin["factor"], n=n_passes)
    for p in b["passes"]:
        p["label"] = pass_label(p, tle["name"], gs["name"])
    rec = {
        "kind": "nasa_pass_windows",
        "created_utc": now.isoformat(),
        "spacecraft_note": "Orbit of a real spacecraft used as a stand-in; the satellite in this system is simulated.",
        "tle": {k: tle.get(k) for k in ("name", "norad", "line1", "line2", "epoch_utc", "source", "url",
                                        "http_status", "raw", "raw_sha256", "fallback_errors")},
        "tle_age_days": round(age_days, 2),
        "tle_stale": age_days > 14,
        "ground_station": gs,
        "parameters": {"uplink_bps": uplink_bps, "min_elevation_deg": min_el, "n_passes": n_passes,
                       "search_hours": hours, "min_useful_budget_bytes": MIN_USEFUL_BUDGET,
                       "budget_formula": "floor(floor(contact_s x uplink_bps / 8) x space_weather_factor)"},
        "space_weather": margin,
        "donki": ({"window": donki.get("window"), "key_used": donki.get("key_used"),
                   "gateway_errors": donki.get("gateway_errors", []),
                   "gst": {k: donki["gst"].get(k) for k in ("url", "source", "http_status", "raw_sha256", "events")},
                   "flr": {k: donki["flr"].get(k) for k in ("url", "source", "http_status", "raw_sha256", "events")}}
                  if donki else None),
        "errors": errors,
        "all_passes_found": len(all_passes),
        "passes": b["passes"],
        "skipped_short": b["skipped_short"][:10],
        "budgets": [p["budget_bytes"] for p in b["passes"]],
        "complete": len(b["passes"]) == n_passes,
    }
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    fname = f"nasa_{stamp}_{norad}.json"
    rec["evidence_file"] = f"nasa/{fname}"
    atomic_write_json(Path(evidence_dir) / "nasa" / fname, rec)
    return rec
