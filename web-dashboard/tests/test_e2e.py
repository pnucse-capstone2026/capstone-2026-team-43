from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import uvicorn

from backend import main


playwright = pytest.importorskip("playwright.sync_api")
sync_playwright = playwright.sync_playwright

TEST_AGENT_TOKEN = "browser-test-agent-token-32-characters"


def make_log(event_id: str, *, index: int = 0, status: str = "SUCCESS") -> dict:
    return {
        "event_id": event_id,
        "agent_id": "browser-agent",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_ip": "192.168.10.42",
        "hostname": "browser-host",
        "user_id": "browser-user",
        "department": "QA",
        "file_name": f"browser-file-{index:02d}.txt",
        "file_path": f"C:\\Browser\\browser-file-{index:02d}.txt",
        "process_name": "browser.exe",
        "leak_channel": "WEB_UPLOAD",
        "detection_type": "HYBRID" if status == "SUCCESS" else "RULE_BASED",
        "analysis_status": status,
        "ai_score": 0.91 if status == "SUCCESS" else None,
        "model_version": "koelectra-dlp-v7" if status == "SUCCESS" else "unavailable",
        "matched_keywords": ["browser-test"],
        "policy_id": "DLP-BROWSER-001",
        "action_taken": "BLOCKED" if status == "SUCCESS" else "ALLOWED",
        "decision_reason": "Browser end-to-end test event.",
        "evidence_summary": "Browser end-to-end test evidence.",
        "latency_ms": 20 if status == "SUCCESS" else None,
    }


@pytest.fixture
def live_dashboard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[str]:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "browser-test.db")
    monkeypatch.setattr(main, "AGENT_API_TOKEN", TEST_AGENT_TOKEN)
    monkeypatch.setattr(main, "AGENT_API_TOKENS", {})
    monkeypatch.setattr(main, "DASHBOARD_AUTH_ENABLED", False)
    monkeypatch.setattr(main, "AI_SERVER_URL", "")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    server = uvicorn.Server(
        uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{base_url}/health", timeout=0.2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.02)
    else:
        server.should_exit = True
        thread.join(timeout=2)
        pytest.fail("Dashboard test server did not start.")

    yield base_url

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def browser_page():
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(headless=True)
        page = browser.new_page()
        page.route("https://cdn.jsdelivr.net/**", lambda route: route.abort())
        yield page
        browser.close()


def post_log(base_url: str, payload: dict) -> None:
    response = httpx.post(
        f"{base_url}/api/v1/logs",
        headers={
            "X-Agent-Token": TEST_AGENT_TOKEN,
            "X-Agent-ID": payload["agent_id"],
        },
        json=payload,
        timeout=2,
    )
    assert response.status_code == 201, response.text


def test_filter_pagination_detail_keyboard_and_api_error(
    live_dashboard: str,
    browser_page,
) -> None:
    for index in range(12):
        post_log(live_dashboard, make_log(f"browser-page-{index}", index=index))
    post_log(
        live_dashboard,
        make_log("browser-failed-analysis", index=99, status="FAILED"),
    )

    browser_page.goto(f"{live_dashboard}/logs", wait_until="domcontentloaded")
    browser_page.locator("#logTableWrap .log-row").first.wait_for()
    assert browser_page.locator("#logTableWrap .log-row").count() == 10

    browser_page.get_by_role("button", name="다음").click()
    browser_page.get_by_text("2 / 2 페이지").wait_for()

    browser_page.locator("#analysisStatusFilter").select_option("FAILED")
    browser_page.wait_for_timeout(1000)
    assert "browser-file-99.txt" in browser_page.locator("#logTableWrap").inner_text(), (
        browser_page.locator("#analysisStatusFilter").input_value(),
        browser_page.locator("#logMeta").inner_text(),
        browser_page.locator("#logTableWrap").inner_text(),
    )
    row = browser_page.locator("#logTableWrap .log-row").first
    row.focus()
    row.press("Enter")
    browser_page.locator("#logDetailPanel h4").get_by_text(
        "browser-file-99.txt", exact=True
    ).wait_for()
    assert "FAILED · -" in browser_page.locator("#logDetailPanel").inner_text()

    browser_page.route(
        "**/api/v1/logs?*",
        lambda route: route.fulfill(status=500, content_type="application/json", body="{}"),
    )
    browser_page.get_by_role("button", name="새로고침").click()
    browser_page.get_by_role("alert").get_by_text("API 연결에 실패했습니다").wait_for()


def test_stale_search_response_cannot_overwrite_latest_results(
    live_dashboard: str,
    browser_page,
) -> None:
    browser_page.goto(f"{live_dashboard}/logs", wait_until="domcontentloaded")
    browser_page.locator("#logTableWrap").wait_for()
    browser_page.evaluate(
        """
        () => {
            const originalFetch = window.fetch.bind(window);
            window.fetch = (url, options) => {
                const value = String(url);
                const response = name => new Response(JSON.stringify({
                    items: [{
                        log_id: name === 'slow' ? 901 : 902,
                        event_id: name,
                        agent_id: 'browser-agent',
                        timestamp: new Date().toISOString(),
                        host_ip: '127.0.0.1',
                        hostname: 'browser-host',
                        user_id: 'browser-user',
                        department: 'QA',
                        file_name: `${name}.txt`,
                        file_path: null,
                        process_name: 'browser.exe',
                        leak_channel: 'WEB_UPLOAD',
                        detection_type: 'HYBRID',
                        analysis_status: 'SUCCESS',
                        ai_score: 0.5,
                        model_version: 'test',
                        matched_keywords: [],
                        policy_id: null,
                        action_taken: 'WARNED',
                        decision_reason: 'test',
                        evidence_summary: 'test',
                        latency_ms: 1
                    }],
                    total: 1,
                    count: 1,
                    limit: 10,
                    offset: 0
                }), {status: 200, headers: {'Content-Type': 'application/json'}});
                if (value.includes('/api/v1/logs?') && value.includes('q=slow')) {
                    return new Promise(resolve => setTimeout(() => resolve(response('slow')), 800));
                }
                if (value.includes('/api/v1/logs?') && value.includes('q=fast')) {
                    return Promise.resolve(response('fast'));
                }
                return originalFetch(url, options);
            };
        }
        """
    )

    search = browser_page.locator("#searchInput")
    search.fill("slow")
    browser_page.wait_for_timeout(300)
    search.fill("fast")
    log_table = browser_page.locator("#logTableWrap")
    browser_page.wait_for_timeout(1000)
    assert "fast.txt" in log_table.inner_text(), (
        search.input_value(),
        browser_page.locator("#logMeta").inner_text(),
        log_table.inner_text(),
    )
    browser_page.wait_for_timeout(900)

    final_table_text = log_table.inner_text()
    assert "fast.txt" in final_table_text
    assert "slow.txt" not in final_table_text


def test_new_blocked_event_shows_toast_and_plays_warning_tone(
    live_dashboard: str,
    browser_page,
) -> None:
    browser_page.add_init_script(
        """
        window.__toneStarts = 0;
        class FakeAudioContext {
            constructor() { this.state = 'running'; this.currentTime = 0; this.destination = {}; }
            resume() { this.state = 'running'; return Promise.resolve(); }
            createOscillator() {
                return {
                    type: '', frequency: {setValueAtTime() {}}, connect() {},
                    start() { window.__toneStarts += 1; }, stop() {}
                };
            }
            createGain() {
                return {gain: {setValueAtTime() {}, exponentialRampToValueAtTime() {}}, connect() {}};
            }
        }
        window.AudioContext = FakeAudioContext;
        """
    )
    browser_page.goto(f"{live_dashboard}/dashboard", wait_until="domcontentloaded")
    browser_page.wait_for_function(
        "document.querySelector('#lastRefreshed').textContent !== '--:--:--'"
    )

    post_log(live_dashboard, make_log("browser-live-alert", index=77))

    alert = browser_page.locator("#realtimeRiskAlert")
    alert.wait_for(state="visible", timeout=7000)
    assert "browser-file-77.txt" in alert.inner_text()
    assert browser_page.evaluate("window.__toneStarts") >= 1
