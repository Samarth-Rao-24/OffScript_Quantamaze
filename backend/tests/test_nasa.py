"""NASA pass windows: TLE parsing, pass prediction, space-weather margin, budgets.

These tests run offline on a *synthetic* ISS-like TLE and a synthetic DONKI
payload shaped like the documented API responses. They check our parsing and
arithmetic; the live fetch is exercised by scripts/final_run.py on a machine
with internet access.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("skyfield")

from satauth.ground import nasa  # noqa: E402


def _cs(body: str) -> str:
    s = sum(int(c) if c.isdigit() else 1 if c == "-" else 0 for c in body)
    return body + str(s % 10)


# synthetic ISS-like elements (inclination 51.64 deg, ~15.5 rev/day), epoch 2026 day 301.5
L1 = _cs("1 25544U 98067A   26301.50000000  .00016717  00000-0  30306-3 0  999")
L2 = _cs("2 25544  51.6400 120.0000 0003500  90.0000 270.0000 15.5000000040000")
EPOCH = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
GS = {"name": "Bengaluru", "lat": 12.9716, "lon": 77.5946, "alt_m": 920}


def test_synthetic_tle_is_well_formed():
    assert len(L1) == 69 and len(L2) == 69
    assert nasa.tle_checksum_ok(L1) and nasa.tle_checksum_ok(L2)
    assert nasa.tle_epoch(L1) == EPOCH


def test_parse_both_payload_shapes_and_reject_bad_checksum():
    js = json.dumps({"@id": "x", "satelliteId": 25544, "name": "ISS (ZARYA)", "date": "2026-10-28T12:00:00+00:00",
                     "line1": L1, "line2": L2}).encode()
    a = nasa.parse_tle_payload(js, "json")
    b = nasa.parse_tle_payload(f"ISS (ZARYA)\n{L1}\n{L2}\n".encode(), "celestrak")
    assert a == b == {"name": "ISS (ZARYA)", "line1": L1, "line2": L2}
    broken = L1[:-1] + str((int(L1[-1]) + 1) % 10)
    with pytest.raises(nasa.NasaUnavailable):
        nasa.parse_tle_payload(f"{broken}\n{L2}".encode(), "bad")


def test_pass_prediction_is_physical():
    passes = nasa.predict_passes(L1, L2, "ISS", lat=GS["lat"], lon=GS["lon"], alt_m=GS["alt_m"],
                                 start=EPOCH, hours=72, min_el=10)
    assert len(passes) >= 3  # an ISS-like orbit passes over 13 deg N several times in 3 days
    for p in passes:
        assert 60 <= p["duration_s"] <= 12 * 60  # LEO passes above 10 deg last minutes, not hours
        assert 10 <= p["max_elevation_deg"] <= 90
        assert p["aos_utc"] < p["tca_utc"] < p["los_utc"]


def test_budget_formula_and_short_pass_filter():
    passes = [{"duration_s": 360.0}, {"duration_s": 60.0}, {"duration_s": 300.0}]
    b = nasa.budgets_from_passes(passes, uplink_bps=80, factor=1.0, n=4)
    assert [p["budget_bytes"] for p in b["passes"]] == [3600, 3000]  # 360 s x 80 bit/s / 8
    assert b["skipped_short"][0]["budget_bytes"] == 600  # too small for PASS_OPEN + one command
    b2 = nasa.budgets_from_passes(passes, uplink_bps=80, factor=0.85, n=4)
    assert b2["passes"][0]["budget_bytes"] == 3060


def _donki(kp: float, flare: str, now: datetime) -> dict:
    t = (now - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%MZ")
    return {"gst": {"events": [{"gstID": "2026-10-28T03:00:00-GST-001", "startTime": t,
                                "allKpIndex": [{"observedTime": t, "kpIndex": kp, "source": "NOAA"}]}]},
            "flr": {"events": [{"flrID": "f1", "beginTime": t, "peakTime": t, "classType": flare,
                                "activeRegionNum": 14000}]}}


def test_space_weather_margin_policy():
    now = EPOCH
    assert nasa.space_weather_margin(_donki(3, "C2.1", now), now=now)["factor"] == 1.0
    assert nasa.space_weather_margin(_donki(5.33, "M1.0", now), now=now)["factor"] == 0.85
    assert nasa.space_weather_margin(_donki(7, "X1.2", now), now=now)["factor"] == pytest.approx(0.63)
    assert nasa.space_weather_margin(None)["factor"] == 1.0


def test_pull_records_evidence_without_secrets(tmp_path):
    tle = {"name": "ISS (ZARYA)", "line1": L1, "line2": L2, "norad": 25544, "source": "fixture",
           "url": "fixture://tle", "http_status": 200, "raw": "{}", "raw_sha256": "0" * 64,
           "epoch_utc": EPOCH.isoformat(), "fallback_errors": []}
    donki = {"window": {}, "key_used": "NASA_API_KEY", **{k: {"url": "https://api.nasa.gov/DONKI/X?api_key=***",
                                                             "http_status": 200, "raw_sha256": "0" * 64, **v}
                                                         for k, v in _donki(3, "C1.0", EPOCH).items()}}
    rec = nasa.nasa_pull(evidence_dir=tmp_path, api_key="secret-key-value", norad=25544, gs=GS, uplink_bps=80,
                         min_el=10, now=EPOCH, tle=tle, donki=donki)
    assert rec["complete"] and len(rec["budgets"]) == 4
    assert all(b >= nasa.MIN_USEFUL_BUDGET for b in rec["budgets"])
    text = (tmp_path / rec["evidence_file"]).read_text()
    assert "secret-key-value" not in text
    assert nasa._redact("https://api.nasa.gov/DONKI/GST?startDate=1&api_key=abc") .endswith("api_key=%2A%2A%2A")


def test_http_retries_transient_errors_then_gives_up(monkeypatch):
    import io
    import urllib.error

    calls = []

    def flaky(url, timeout):
        calls.append(url)
        if len(calls) < 3:
            raise urllib.error.HTTPError(url, 508, "Resource Limit Is Reached", {}, io.BytesIO(b"busy"))
        return 200, b"ok"

    monkeypatch.setattr(nasa, "_http_once", flaky)
    assert nasa.http_get("https://example.invalid/x", delays=(0, 0)) == (200, b"ok") and len(calls) == 3
    calls.clear()

    def bad_key(url, timeout):
        calls.append(url)
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, io.BytesIO(b"API_KEY_INVALID"))

    monkeypatch.setattr(nasa, "_http_once", bad_key)
    with pytest.raises(nasa.NasaUnavailable, match="403"):
        nasa.http_get("https://api.nasa.gov/x?api_key=abc", delays=(0, 0))
    assert len(calls) == 1  # a 4xx is not retried


def test_donki_falls_back_to_ccmc_when_gateway_fails(monkeypatch):
    def fake(url, timeout=20.0, delays=()):
        if "api.nasa.gov" in url:
            raise nasa.NasaUnavailable("HTTP 503 from gateway")
        return 200, b"[]"

    monkeypatch.setattr(nasa, "http_get", fake)
    d = nasa.fetch_donki("k", now=EPOCH)
    assert d["gst"]["source"] == "NASA CCMC DONKI web service" and d["gst"]["events"] == []
    assert len(d["gateway_errors"]) == 2
