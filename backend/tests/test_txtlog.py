"""Notepad-friendly logs: every QpiAI call and every website test lands in evidence/txt, without secrets."""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

from satauth.common import txtlog


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    root = tmp_path_factory.mktemp("txt")
    mp = pytest.MonkeyPatch()
    mp.setenv("QUPLINK_DATA_DIR", str(root / "data"))
    mp.setenv("QUPLINK_EVIDENCE_DIR", str(root / "evidence"))
    mp.setenv("QUPLINK_ALLOW_DEV_NONCE", "true")
    mp.setenv("QUPLINK_NO_DOTENV", "1")
    for k in ("QPIAI_OPT_API_KEY", "QPIAI_QCLOUD_API_KEY", "QCLOUD_API_KEY", "QUPLINK_KEY_PASSPHRASE"):
        mp.delenv(k, raising=False)
    import satauth.api.main as main
    import satauth.config

    importlib.reload(satauth.config)
    main = importlib.reload(main)
    with TestClient(main.app) as c:
        yield c, root / "evidence"
    mp.undo()


def test_website_tests_and_qpiai_calls_are_written_as_text(env):
    c, ev = env
    assert c.post("/api/plan", json={}).status_code == 503  # no Opt key: a failed QpiAI call
    c.post("/api/pass/open", json={})
    assert c.post("/api/attack/replay").json()["passed"]
    c.post("/api/judge/compose", json={"key": "OPERATOR", "opcode": "NOOP_PING", "sat_id": 7})
    run = c.post("/api/judge/cases", json={"cases": [{"id": "X1", "key": "OPERATOR", "opcode": "NOOP_PING", "expect": "ACCEPT"}]}).json()
    assert run["totals"]["passed"] == 1
    tests_txt = (ev / "txt" / "test_data_log.txt").read_text(encoding="utf-8")
    assert "Attack lab  |  " in tests_txt and "PASSED" in tests_txt
    assert "Judge console  |  Compose a frame  |  REJECT" in tests_txt and "E_WRONG_SAT" in tests_txt
    assert "case file, 1 case(s)" in tests_txt and "X1" in tests_txt
    q_txt = (ev / "txt" / "qpiai_usage_log.txt").read_text(encoding="utf-8")
    assert "QpiAI Opt  |  FAILED" in q_txt and "QPIAI_OPT_API_KEY is not set" in q_txt


def test_secrets_are_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("QPIAI_OPT_API_KEY", "sk-very-secret-123456")
    txtlog.record_event(tmp_path, "qpiai", {"tool": "opt", "status": "failed", "requested": "x",
                                            "error": "401 for key sk-very-secret-123456"})
    text = (tmp_path / "txt" / "qpiai_usage_log.txt").read_text(encoding="utf-8")
    assert "sk-very-secret-123456" not in text and "[redacted]" in text
    assert "sk-very-secret-123456" not in (tmp_path / "logs" / "qpiai_calls.jsonl").read_text(encoding="utf-8")
