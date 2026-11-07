import http.server
import json
import socket
import socketserver
import threading
import time
import urllib.request
import pytest

from auditor_proxy import (
    PassiveScanEngine,
    ProxyStore,
    SecurityProxyManager,
)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DummyOriginHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/test-headers":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.send_header("Set-Cookie", "sessionid=xyz123; Path=/")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Hello Safe Page</h1></body></html>")
        elif self.path == "/error-page":
            self.send_response(500)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"Traceback (most recent call last):\n  File 'app.py', line 42, in index\nZeroDivisionError")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")


@pytest.fixture(scope="module")
def dummy_origin_server():
    port = get_free_port()
    server = socketserver.TCPServer(("127.0.0.1", port), DummyOriginHandler)
    server.allow_reuse_address = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_passive_scan_engine_missing_headers():
    tx = {
        "id": 1,
        "url": "https://example.com/",
        "method": "GET",
        "status_code": 200,
        "response_headers": {
            "content-type": "text/html",
        },
        "raw_set_cookies": [],
        "response_body_sample": "<html><body>Hello</body></html>",
    }
    alerts = PassiveScanEngine.inspect(tx)
    titles = [a["title"] for a in alerts]
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("nosniff" in t for t in titles)
    assert any("Clickjacking" in t for t in titles)
    assert any("HSTS" in t for t in titles)


def test_passive_scan_engine_cookies_and_leak():
    tx = {
        "id": 2,
        "url": "https://example.com/login",
        "method": "POST",
        "status_code": 200,
        "response_headers": {
            "content-type": "text/html",
            "server": "nginx/1.18.0",
            "x-powered-by": "Express",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
        "raw_set_cookies": ["auth_token=abc12345; Path=/"],
        "response_body_sample": "<html>Logged In</html>",
    }
    alerts = PassiveScanEngine.inspect(tx)
    titles = [a["title"] for a in alerts]
    risks = [a["risk"] for a in alerts]

    assert any("HttpOnly" in t for t in titles)
    assert any("Secure" in t for t in titles)
    assert any("SameSite" in t for t in titles)
    assert any("Server" in t for t in titles)
    assert any("X-Powered-By" in t for t in titles)
    assert any("CORS com Origem Irrestrita" in t for t in titles)
    assert "Alto" in risks


def test_passive_scan_engine_stacktrace():
    tx = {
        "id": 3,
        "url": "http://example.com/api/crash",
        "method": "GET",
        "status_code": 500,
        "response_headers": {"content-type": "text/plain"},
        "response_body_sample": "Traceback (most recent call last):\n  File 'main.py', line 10\nZeroDivisionError",
    }
    alerts = PassiveScanEngine.inspect(tx)
    assert any("Stacktrace" in a["title"] for a in alerts)
    assert any(a["risk"] == "Alto" for a in alerts)


def test_proxy_store():
    store = ProxyStore(max_transactions=10)
    tx = {"url": "http://test.com", "method": "GET", "timestamp": "2026-11-06 10:00:00"}
    alerts = [
        {"risk": "Alto", "title": "Falha Critica"},
        {"risk": "Médio", "title": "Falha Media"},
    ]
    added = store.add_transaction(tx, alerts)
    assert added["id"] == 1
    assert added["alert_count"] == 2

    history = store.get_history()
    assert len(history) == 1

    high_alerts = store.get_alerts(risk="Alto")
    assert len(high_alerts) == 1
    assert high_alerts[0]["title"] == "Falha Critica"

    summary = store.get_summary()
    assert summary["total_transactions"] == 1
    assert summary["total_alerts"] == 2
    assert summary["risk_counts"]["Alto"] == 1

    store.clear()
    assert len(store.get_history()) == 0
    assert len(store.get_alerts()) == 0


def test_proxy_manager_lifecycle_and_traffic(dummy_origin_server):
    proxy_port = get_free_port()
    manager = SecurityProxyManager()

    start_res = manager.start(host="127.0.0.1", port=proxy_port)
    assert start_res["success"] is True
    assert manager.is_running() is True

    # Fazer requisição através do proxy configurando proxy handler do urllib
    proxy_handler = urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{proxy_port}",
    })
    opener = urllib.request.build_opener(proxy_handler)

    target_url = f"{dummy_origin_server}/test-headers"
    req = urllib.request.Request(target_url)
    with opener.open(req, timeout=5) as resp:
        body = resp.read()
        assert resp.status == 200
        assert b"Hello Safe Page" in body

    # Pequena pausa para garantir processamento assíncrono
    time.sleep(0.1)

    status = manager.get_status()
    assert status["running"] is True
    assert status["summary"]["total_transactions"] >= 1

    history = manager.get_history()
    assert len(history) >= 1
    tx = history[0]
    assert tx["status_code"] == 200
    assert tx["url"] == target_url

    # Deve ter detectado ausência de cabeçalhos de segurança e Server header
    alerts = manager.get_alerts()
    assert len(alerts) > 0
    alert_titles = [a["title"] for a in alerts]
    assert any("Server" in t for t in alert_titles)
    assert any("HttpOnly" in t for t in alert_titles)

    stop_res = manager.stop()
    assert stop_res["success"] is True
    assert manager.is_running() is False
