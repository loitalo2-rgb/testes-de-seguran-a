"""auditor_proxy.py - Proxy HTTP Interceptador e Motor de Auditoria Passiva estilo OWASP ZAP.

Fornece:
1. ProxyServer HTTP/HTTPS local multithreaded que captura e inspeciona requisições/respostas.
2. Motor de Varredura Passiva (Passive Scan Engine) em tempo real.
3. Classificação de riscos (Alto, Médio, Baixo, Informativo) com referências OWASP/CWE.
4. Histórico de transações e repositório de alertas pesquisável.
"""

from __future__ import annotations

import http.client
import json
import logging
import re
import select
import socket
import socketserver
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional

logger = logging.getLogger("auditor_proxy")

# Regras Passivas Pré-definidas
SECURITY_HEADERS = {
    "content-security-policy": {
        "title": "Ausência de Content-Security-Policy (CSP)",
        "risk": "Médio",
        "cwe": "CWE-693",
        "description": "O cabeçalho CSP ajuda a mitigar ataques de Cross-Site Scripting (XSS) e injeção de dados.",
        "solution": "Configure o cabeçalho 'Content-Security-Policy' restringindo as origens permitidas para scripts, estilos e conexões.",
    },
    "x-content-type-options": {
        "title": "Ausência de X-Content-Type-Options: nosniff",
        "risk": "Baixo",
        "cwe": "CWE-16",
        "description": "Sem 'nosniff', o navegador pode tentar adivinhar o tipo MIME do arquivo (MIME sniffing), facilitando XSS.",
        "solution": "Adicione o cabeçalho 'X-Content-Type-Options: nosniff' nas respostas HTTP.",
    },
    "x-frame-options": {
        "title": "Ausência de Proteção contra Clickjacking (X-Frame-Options / frame-ancestors)",
        "risk": "Médio",
        "cwe": "CWE-1021",
        "description": "A página pode ser incorporada em um iframe malicioso, facilitando ataques de Clickjacking.",
        "solution": "Adicione 'X-Frame-Options: DENY' ou 'SAMEORIGIN', ou utilize a diretiva 'frame-ancestors' no CSP.",
    },
    "strict-transport-security": {
        "title": "Ausência de HTTP Strict Transport Security (HSTS)",
        "risk": "Baixo",
        "cwe": "CWE-523",
        "description": "HSTS força o navegador a comunicar-se exclusivamente via HTTPS, prevenindo downgrade attacks (SSL-stripping).",
        "solution": "Adicione 'Strict-Transport-Security: max-age=31536000; includeSubDomains' nas respostas HTTPS.",
    },
}

INFO_LEAK_HEADERS = [
    ("server", "Divulgação de Software/Versão do Servidor (Server header)", "Informativo", "CWE-200"),
    ("x-powered-by", "Divulgação de Tecnologia de Backend (X-Powered-By)", "Informativo", "CWE-200"),
    ("x-aspnet-version", "Divulgação de Versão ASP.NET", "Baixo", "CWE-200"),
    ("x-generator", "Divulgação de Framework/CMS (X-Generator)", "Informativo", "CWE-200"),
]


class PassiveScanEngine:
    """Motor de análise passiva estilo ZAP: inspeciona respostas capturadas sem gerar novo tráfego."""

    @staticmethod
    def inspect(tx: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        url = tx.get("url", "")
        method = tx.get("method", "GET")
        status_code = tx.get("status_code", 0)
        resp_headers = {k.lower(): v for k, v in tx.get("response_headers", {}).items()}
        body_text = tx.get("response_body_sample", "") or ""

        # Ignorar erros de proxy interno ou transações sem resposta
        if not status_code or status_code == 502:
            return alerts

        is_html = "text/html" in resp_headers.get("content-type", "").lower()
        is_https = url.startswith("https://")

        # 1. Checagem de Cabeçalhos de Segurança (apenas em páginas HTML / respostas 2xx/3xx)
        if is_html and 200 <= status_code < 400:
            for header_name, meta in SECURITY_HEADERS.items():
                if header_name == "strict-transport-security" and not is_https:
                    continue  # HSTS só é aplicável em HTTPS
                if header_name not in resp_headers:
                    alerts.append({
                        "tx_id": tx.get("id"),
                        "url": url,
                        "risk": meta["risk"],
                        "cwe": meta["cwe"],
                        "title": meta["title"],
                        "description": meta["description"],
                        "solution": meta["solution"],
                        "evidence": f"Cabeçalho '{header_name}' ausente na resposta HTTP {status_code}.",
                    })

        # 2. Divulgação de Informações (Information Leakage)
        for hname, title, risk, cwe in INFO_LEAK_HEADERS:
            if hname in resp_headers:
                val = resp_headers[hname]
                alerts.append({
                    "tx_id": tx.get("id"),
                    "url": url,
                    "risk": risk,
                    "cwe": cwe,
                    "title": title,
                    "description": f"O cabeçalho '{hname}' revela detalhes da pilha de tecnologia utilizada.",
                    "solution": f"Remova ou mascare o cabeçalho '{hname}' nas configurações do servidor web ou gateway.",
                    "evidence": f"{hname}: {val}",
                })

        # 3. Cookies Inseguros (Set-Cookie)
        set_cookie_headers = tx.get("raw_set_cookies", [])
        if not set_cookie_headers and "set-cookie" in resp_headers:
            set_cookie_headers = [resp_headers["set-cookie"]]

        for cookie in set_cookie_headers:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip() if "=" in cookie else "Cookie"

            if "httponly" not in cookie_lower:
                alerts.append({
                    "tx_id": tx.get("id"),
                    "url": url,
                    "risk": "Médio",
                    "cwe": "CWE-1004",
                    "title": f"Cookie sem Flag 'HttpOnly' ({cookie_name})",
                    "description": "O atributo 'HttpOnly' impede que scripts de cliente acessem o cookie de sessão via document.cookie, mitigando roubo em ataques XSS.",
                    "solution": f"Adicione a flag '; HttpOnly' ao definir o cookie '{cookie_name}'.",
                    "evidence": cookie[:120],
                })

            if is_https and "secure" not in cookie_lower:
                alerts.append({
                    "tx_id": tx.get("id"),
                    "url": url,
                    "risk": "Médio",
                    "cwe": "CWE-614",
                    "title": f"Cookie de Conexão Segura sem Flag 'Secure' ({cookie_name})",
                    "description": "O atributo 'Secure' garante que o cookie seja transmitido unicamente por túneis criptografados TLS/HTTPS.",
                    "solution": f"Adicione a flag '; Secure' ao definir o cookie '{cookie_name}'.",
                    "evidence": cookie[:120],
                })

            if "samesite" not in cookie_lower:
                alerts.append({
                    "tx_id": tx.get("id"),
                    "url": url,
                    "risk": "Baixo",
                    "cwe": "CWE-1275",
                    "title": f"Cookie sem Atributo 'SameSite' ({cookie_name})",
                    "description": "O atributo SameSite (Lax/Strict) ajuda a proteger a aplicação contra ataques de Cross-Site Request Forgery (CSRF).",
                    "solution": f"Adicione a flag '; SameSite=Lax' ou '; SameSite=Strict' ao cookie '{cookie_name}'.",
                    "evidence": cookie[:120],
                })

        # 4. CORS Permissivo com Credenciais
        acao = resp_headers.get("access-control-allow-origin", "")
        acac = resp_headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            alerts.append({
                "tx_id": tx.get("id"),
                "url": url,
                "risk": "Alto",
                "cwe": "CWE-346",
                "title": "CORS com Origem Irrestrita (*) e Credenciais Habilitadas",
                "description": "Configuração perigosa de CORS que permite que qualquer site faça requisições autenticadas em nome da vítima.",
                "solution": "Não utilize '*' em conjunto com Access-Control-Allow-Credentials: true. Defina origens confiáveis explícitas.",
                "evidence": f"ACAO: {acao} | ACAC: {acac}",
            })
        elif acao == "*" and ("/api/" in url or "/auth" in url or "/user" in url):
            alerts.append({
                "tx_id": tx.get("id"),
                "url": url,
                "risk": "Baixo",
                "cwe": "CWE-346",
                "title": "CORS Excessivamente Aberto (*) em Endpoint de API",
                "description": "O endpoint de API permite leitura irrestrita por qualquer origem web.",
                "solution": "Avalie se este endpoint realmente deve ser público para qualquer domínio.",
                "evidence": f"Access-Control-Allow-Origin: {acao}",
            })

        # 5. Cache de Dados Sensíveis
        cache_control = resp_headers.get("cache-control", "").lower()
        pragma = resp_headers.get("pragma", "").lower()
        if ("/auth" in url.lower() or "/login" in url.lower() or "/token" in url.lower() or "/perfil" in url.lower()) and 200 <= status_code < 300:
            if "no-store" not in cache_control and "no-cache" not in cache_control:
                alerts.append({
                    "tx_id": tx.get("id"),
                    "url": url,
                    "risk": "Baixo",
                    "cwe": "CWE-525",
                    "title": "Endpoint Sensível/Autenticado com Cache Permissivo",
                    "description": "Endpoints de autenticação ou dados privados não devem ser armazenados em cache de navegador ou proxies intermediários.",
                    "solution": "Adicione o cabeçalho 'Cache-Control: no-store, no-cache, must-revalidate'.",
                    "evidence": f"Cache-Control: {cache_control or '(ausente)'}",
                })

        # 6. Exposição de Stack Traces ou Erros Críticos no Body
        if body_text:
            error_patterns = [
                (r"Traceback \(most recent call last\):", "Python Traceback Exposto"),
                (r"Fatal error:.*in\s+.*\.php", "PHP Fatal Error Exposto"),
                (r"org\.apache\.catalina\..*Exception", "Java/Tomcat Stacktrace Exposto"),
                (r"Microsoft OLE DB Provider for SQL Server", "Erro SQL Server Exposto"),
                (r"SyntaxError:.*at\s+", "Node.js Stacktrace Exposto"),
            ]
            for pat, err_title in error_patterns:
                match = re.search(pat, body_text, re.IGNORECASE)
                if match:
                    alerts.append({
                        "tx_id": tx.get("id"),
                        "url": url,
                        "risk": "Alto",
                        "cwe": "CWE-209",
                        "title": f"Vazamento de Mensagem de Erro / Stacktrace: {err_title}",
                        "description": "Mensagens de depuração e pilha de execução técnica revelam caminhos de arquivos internos, arquitetura e bibliotecas vulneráveis.",
                        "solution": "Desative o modo de depuração (debug=False) e configure páginas genéricas de erro 500/404.",
                        "evidence": body_text[max(0, match.start() - 20) : min(len(body_text), match.end() + 100)].strip(),
                    })
                    break

        return alerts


class ProxyStore:
    """Repositório thread-safe de histórico de tráfego e alertas."""

    def __init__(self, max_transactions: int = 500) -> None:
        self.lock = threading.Lock()
        self.max_transactions = max_transactions
        self._tx_counter = 0
        self._alert_counter = 0
        self.transactions: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []

    def add_transaction(self, tx: Dict[str, Any], new_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        with self.lock:
            self._tx_counter += 1
            tx["id"] = self._tx_counter
            tx["alert_count"] = len(new_alerts)

            for a in new_alerts:
                self._alert_counter += 1
                a["id"] = self._alert_counter
                a["timestamp"] = tx.get("timestamp")
                self.alerts.append(a)

            self.transactions.insert(0, tx)
            if len(self.transactions) > self.max_transactions:
                self.transactions.pop()
            return tx

    def get_history(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        with self.lock:
            return self.transactions[offset : offset + limit]

    def get_alerts(self, risk: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self.lock:
            if not risk:
                return self.alerts[-limit:][::-1]
            risk_lower = risk.lower()
            filtered = [a for a in self.alerts if a.get("risk", "").lower() == risk_lower]
            return filtered[-limit:][::-1]

    def get_summary(self) -> Dict[str, Any]:
        with self.lock:
            counts = {"Alto": 0, "Médio": 0, "Baixo": 0, "Informativo": 0}
            for a in self.alerts:
                r = a.get("risk", "Informativo")
                if r in counts:
                    counts[r] += 1
                else:
                    counts[r] = 1
            return {
                "total_transactions": len(self.transactions),
                "total_alerts": len(self.alerts),
                "risk_counts": counts,
            }

    def clear(self) -> None:
        with self.lock:
            self.transactions.clear()
            self.alerts.clear()
            self._tx_counter = 0
            self._alert_counter = 0


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """Handler HTTP que intercepta requisições comuns e túneis CONNECT (HTTPS)."""

    server: "ThreadingProxyServer"  # type annotation para o servidor vinculado

    def log_message(self, format: str, *args: Any) -> None:
        # Suprime logs normais do BaseHTTPRequestHandler para não poluir terminal
        pass

    def do_CONNECT(self) -> None:
        """Suporte a túneis HTTPS (HTTP CONNECT)."""
        address = self.path.split(":")
        host = address[0]
        port = int(address[1]) if len(address) > 1 else 443

        start_time = time.time()
        tx = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "method": "CONNECT",
            "url": f"https://{host}:{port}",
            "client_ip": self.client_address[0],
            "status_code": 200,
            "request_headers": dict(self.headers),
            "response_headers": {},
            "raw_set_cookies": [],
            "response_body_sample": "",
            "bytes_sent": 0,
            "bytes_received": 0,
            "duration_ms": 0,
        }

        try:
            target_sock = socket.create_connection((host, port), timeout=8)
            self.send_response(200, "Connection Established")
            self.end_headers()
            # Registra imediatamente a transação CONNECT para visualização no dashboard
            self.server.store.add_transaction(tx, [])
        except Exception as e:
            self.send_error(502, f"Não foi possível conectar ao host de destino {host}:{port}: {e}")
            tx["status_code"] = 502
            self.server.store.add_transaction(tx, [])
            return

        # Tunelamento bidirecional assíncrono com select
        conns = [self.connection, target_sock]
        total_in = 0
        total_out = 0
        try:
            while True:
                rlist, _, xlist = select.select(conns, [], conns, 10)
                if xlist or not rlist:
                    break
                for s in rlist:
                    other = target_sock if s is self.connection else self.connection
                    data = s.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
                    if s is self.connection:
                        total_out += len(data)
                    else:
                        total_in += len(data)
        except Exception:
            pass
        finally:
            try:
                target_sock.close()
            except Exception:
                pass
            tx["duration_ms"] = int((time.time() - start_time) * 1000)
            tx["bytes_sent"] = total_out
            tx["bytes_received"] = total_in

    def do_GET(self) -> None:
        self._handle_http_request("GET")

    def do_POST(self) -> None:
        self._handle_http_request("POST")

    def do_PUT(self) -> None:
        self._handle_http_request("PUT")

    def do_DELETE(self) -> None:
        self._handle_http_request("DELETE")

    def do_HEAD(self) -> None:
        self._handle_http_request("HEAD")

    def do_OPTIONS(self) -> None:
        self._handle_http_request("OPTIONS")

    def _handle_http_request(self, method: str) -> None:
        start_time = time.time()
        url = self.path

        # Normaliza URL se o cliente enviou apenas o path relativo
        if not url.startswith("http://") and not url.startswith("https://"):
            host_header = self.headers.get("Host", "localhost")
            url = f"http://{host_header}{url}"

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # Ler corpo da requisição (se houver)
        req_body = b""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            req_body = self.rfile.read(content_length)

        # Preparar cabeçalhos para o destino (filtrar hop-by-hop)
        forward_headers = {}
        hop_by_hop = {"proxy-connection", "connection", "keep-alive", "transfer-encoding"}
        for k, v in self.headers.items():
            if k.lower() not in hop_by_hop:
                forward_headers[k] = v

        tx: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "method": method,
            "url": url,
            "client_ip": self.client_address[0],
            "status_code": 0,
            "request_headers": dict(self.headers),
            "response_headers": {},
            "raw_set_cookies": [],
            "response_body_sample": "",
            "bytes_sent": len(req_body),
            "bytes_received": 0,
            "duration_ms": 0,
        }

        # Encaminhar ao servidor de destino
        try:
            conn: http.client.HTTPConnection
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=10)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=10)

            conn.request(method, path, body=req_body or None, headers=forward_headers)
            resp = conn.getresponse()
            resp_body = resp.read()

            tx["status_code"] = resp.status
            tx["response_headers"] = dict(resp.getheaders())
            tx["raw_set_cookies"] = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
            tx["bytes_received"] = len(resp_body)

            # Salvar amostra de texto para auditoria passiva (até 64KB)
            content_type = tx["response_headers"].get("Content-Type", "")
            if any(t in content_type.lower() for t in ["text", "json", "javascript", "xml", "html"]):
                try:
                    tx["response_body_sample"] = resp_body[:65536].decode("utf-8", errors="replace")
                except Exception:
                    tx["response_body_sample"] = ""

            # Responder ao cliente original
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in hop_by_hop:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp_body)
            conn.close()

        except Exception as exc:
            self.send_error(502, f"Erro de Proxy ao contatar {host}:{port}: {exc}")
            tx["status_code"] = 502
            tx["response_body_sample"] = str(exc)

        finally:
            tx["duration_ms"] = int((time.time() - start_time) * 1000)
            # Executar análise passiva
            alerts = PassiveScanEngine.inspect(tx)
            self.server.store.add_transaction(tx, alerts)


class ThreadingProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, store: ProxyStore):
        self.store = store
        super().__init__(server_address, RequestHandlerClass)


class SecurityProxyManager:
    """Gerenciador central do Proxy DAST: controle de ciclo de vida e consulta."""

    def __init__(self) -> None:
        self.store = ProxyStore()
        self.server: Optional[ThreadingProxyServer] = None
        self.thread: Optional[threading.Thread] = None
        self.host = "127.0.0.1"
        self.port = 8090
        self._is_running = False

    def is_running(self) -> bool:
        return self._is_running and self.server is not None

    def start(self, host: str = "127.0.0.1", port: int = 8090) -> Dict[str, Any]:
        if self.is_running():
            return {
                "success": True,
                "message": f"Proxy já está em execução em {self.host}:{self.port}",
                "host": self.host,
                "port": self.port,
            }

        self.host = host
        self.port = port
        try:
            self.server = ThreadingProxyServer((self.host, self.port), ProxyRequestHandler, self.store)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            self._is_running = True
            return {
                "success": True,
                "message": f"Proxy DAST iniciado com sucesso em {self.host}:{self.port}",
                "host": self.host,
                "port": self.port,
            }
        except Exception as exc:
            self._is_running = False
            self.server = None
            return {
                "success": False,
                "message": f"Falha ao iniciar proxy na porta {port}: {exc}",
                "error": str(exc),
            }

    def stop(self) -> Dict[str, Any]:
        if not self.is_running():
            return {"success": True, "message": "Proxy não está em execução."}

        try:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
            self.server = None
            self.thread = None
            self._is_running = False
            return {"success": True, "message": "Proxy finalizado com sucesso."}
        except Exception as exc:
            return {"success": False, "message": f"Erro ao parar proxy: {exc}"}

    def get_status(self) -> Dict[str, Any]:
        summary = self.store.get_summary()
        return {
            "running": self.is_running(),
            "host": self.host,
            "port": self.port,
            "summary": summary,
        }

    def get_history(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        return self.store.get_history(limit=limit, offset=offset)

    def get_alerts(self, risk: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        return self.store.get_alerts(risk=risk, limit=limit)

    def clear(self) -> Dict[str, Any]:
        self.store.clear()
        return {"success": True, "message": "Histórico e alertas limpos com sucesso."}


# Instância singleton global para ser utilizada pelo servidor de aplicação
proxy_manager = SecurityProxyManager()


def launch_proxy_browser(host: str = "127.0.0.1", port: int = 8090, target_url: str = "http://example.com") -> Dict[str, Any]:
    """Abre uma instância do navegador (Edge ou Chrome) apontando para o proxy local."""
    import os
    import tempfile

    target = target_url.strip() if target_url else "http://example.com"
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    user_dir = os.path.join(tempfile.gettempdir(), "security_suite_proxy_browser")

    # Tenta usar msedge via start (nativo do Windows, sempre abre em primeiro plano)
    edge_cmd = f'start msedge --proxy-server=http://{host}:{port} --new-window --ignore-certificate-errors --user-data-dir="{user_dir}" "{target}"'
    ret = os.system(edge_cmd)
    if ret == 0:
        return {
            "success": True,
            "browser": "Microsoft Edge",
            "message": f"Navegador Edge aberto com proxy {host}:{port}!",
        }

    # Fallback para Chrome
    chrome_cmd = f'start chrome --proxy-server=http://{host}:{port} --new-window --ignore-certificate-errors --user-data-dir="{user_dir}" "{target}"'
    ret_chrome = os.system(chrome_cmd)
    if ret_chrome == 0:
        return {
            "success": True,
            "browser": "Google Chrome",
            "message": f"Navegador Chrome aberto com proxy {host}:{port}!",
        }

    return {"success": False, "message": "Não foi possível abrir o navegador automaticamente via Windows Shell."}

