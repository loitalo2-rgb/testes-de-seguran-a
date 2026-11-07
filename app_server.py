import http.server
import socketserver
import json
import re
import urllib.parse
import webbrowser
import os
import requests

from auditor_headers import SecurityHeaderAuditor
from auditor_ssl import get_ssl_info
import fuzzer_moderno
import scanner_visual
from auditor_recon_dns import check_dns_email_security, inspect_recon_files, inspect_cookies_privacy
from auditor_avancado import scan_ports, check_sensitive_files, detect_js_libraries, save_scan_history
from auditor_nmap import run_nmap_scan
from auditor_sub_methods import enumerate_subdomains_crtsh, check_http_methods
from auditor_whois_geo import get_domain_whois_rdap, get_ip_geolocation
from auditor_pii_lgpd import scan_pii_and_pix
from auditor_secrets import scan_secrets
from auditor_jwt import scan_jwts
from auditor_injecao_avancada import run_advanced_injection
from auditor_logs import analyze_logs
from auditor_crawler import crawl_site, crawl_summary
from auditor_proxy import proxy_manager

PORT = 5000
MAX_LOG_BYTES = 5 * 1024 * 1024


def _page_has_inputs(url, html):
    """Só vale a pena rodar injeções em páginas com parâmetros ou campos."""
    if urllib.parse.urlparse(url).query:
        return True
    return bool(re.search(r"<(form|input|textarea|select)\b", html or "", re.IGNORECASE))

class PentestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/history':
            history_file = "historico_scans.json"
            history = []
            if os.path.exists(history_file):
                try:
                    with open(history_file, 'r', encoding='utf-8') as f:
                        history = json.load(f)
                except Exception:
                    pass
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(history, ensure_ascii=False).encode('utf-8'))
        elif self.path == '/api/proxy/status':
            status = proxy_manager.get_status()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(status, ensure_ascii=False).encode('utf-8'))
        elif self.path.startswith('/api/proxy/history'):
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            limit = int(qs.get('limit', ['100'])[0])
            history = proxy_manager.get_history(limit=limit)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(history, ensure_ascii=False).encode('utf-8'))
        elif self.path.startswith('/api/proxy/alerts'):
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            risk = qs.get('risk', [None])[0]
            limit = int(qs.get('limit', ['100'])[0])
            alerts = proxy_manager.get_alerts(risk=risk, limit=limit)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(alerts, ensure_ascii=False).encode('utf-8'))
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/api/scan':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                target_url = data.get('url', '').strip()
                nmap_mode = data.get('nmap_mode', 'fast')
                crawl_enabled = bool(data.get('crawl', True))
                try:
                    crawl_max_pages = max(1, min(int(data.get('max_pages', 8)), 15))
                except (TypeError, ValueError):
                    crawl_max_pages = 8
            except Exception:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "JSON invalido"}')
                return

            if not target_url:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "URL obrigatoria"}')
                return

            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url

            parsed = urllib.parse.urlparse(target_url)
            hostname = parsed.hostname or target_url

            print(f"\n[+] Executando Auditoria Global [{nmap_mode.upper()}] em: {target_url}...")

            # 1. Auditoria Defensiva de Headers OWASP
            auditor = SecurityHeaderAuditor(target_url)
            auditor.run_audit()

            # 2. Auditoria SSL/TLS
            ssl_res = get_ssl_info(hostname, parsed.port or 443)

            # 3. DNS, SPF, DMARC e Proteção de E-mail
            dns_res = check_dns_email_security(hostname)

            # 4. Reconhecimento de Robots.txt e Sitemap.xml
            recon_res = inspect_recon_files(target_url)

            # 5. Auditoria de Cookies da URL e Captura do HTML
            raw_cookies = []
            html_body = ""
            try:
                c_resp = requests.get(target_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                raw_cookies = c_resp.cookies
                html_body = c_resp.text
            except Exception:
                pass
            cookies_res = inspect_cookies_privacy(raw_cookies, target_url)

            # 5.1. Varredura de PII, Chaves PIX e Conformidade LGPD no HTML
            pii_findings = scan_pii_and_pix(html_body)

            # 5.2. Varredura de Segredos Expostos (chaves, tokens e senhas) no HTML e JS
            secret_findings = scan_secrets(html_body, target_url)

            # 5.3. Análise e quebra offline de tokens JWT (segredo fraco, alg none, claims)
            jwt_findings = scan_jwts(html_body, target_url)

            # 6. Detecção de Componentes Frontend (JS Libraries)
            js_libs = detect_js_libraries(html_body)

            # 7. Scanner de Arquivos Sensíveis (.git, .env, backups)
            sensitive_findings = check_sensitive_files(target_url)

            # 8. Detecção de Métodos HTTP Inseguros (TRACE, PUT, DELETE)
            http_methods_res = check_http_methods(target_url)

            # 9. Enumeração Passiva de Subdomínios (Certificate Transparency crt.sh)
            subdomains_res = enumerate_subdomains_crtsh(hostname)

            # 10. Inteligência de Domínio WHOIS/RDAP e Geolocalização de Servidor
            whois_res = get_domain_whois_rdap(hostname)
            geo_res = get_ip_geolocation(hostname)

            # 11. Auditoria com Nmap (fast, advanced ou deep)
            nmap_res = run_nmap_scan(hostname, mode=nmap_mode)

            # 12. Scanner Rápido de Portas / Serviços Expostos
            open_ports = scan_ports(hostname)

            # 13. Fuzzing e Busca de Pastas & Subpastas
            fuzz_results = fuzzer_moderno.start_fuzzing(target_url, recursive=True)

            # 14. Scanner de Vulnerabilidades (XSS e SQLi)
            payloads = scanner_visual.load_payloads("payloads.json")
            vuln_results = []
            if payloads:
                vuln_results = scanner_visual.run_scanner(target_url, payloads)

            # 15. Injeção Avançada (SSTI, LFI/Path Traversal e Command Injection)
            advanced_injections = run_advanced_injection(target_url, html_body)

            # 16. Crawler same-origin e varredura multi-página
            crawl_res = {
                "enabled": crawl_enabled,
                "start_url": target_url,
                "total": 0,
                "truncated": False,
                "errors": [],
                "pages": [],
                "inputs_tested": 0,
                "injection_findings": 0,
                "web_findings": 0,
            }
            if crawl_enabled:
                crawled = crawl_site(
                    target_url,
                    max_pages=crawl_max_pages,
                    max_depth=2,
                    seed_html=html_body,
                )
                crawl_res = crawl_summary(crawled)
                crawl_res["enabled"] = True
                crawl_res["inputs_tested"] = 0
                crawl_res["injection_findings"] = 0
                crawl_res["web_findings"] = 0

                seen_pii = {json.dumps(p, sort_keys=True, ensure_ascii=False) for p in pii_findings}
                injection_keys = {
                    (f.get("type"), f.get("parameter"), f.get("payload"), f.get("url"))
                    for f in advanced_injections.get("findings", [])
                }

                for page in crawled["pages"][1:]:
                    page_url = page["url"]
                    page_html = page.get("html") or ""
                    if not page_html:
                        continue

                    for p in scan_pii_and_pix(page_html):
                        key = json.dumps(p, sort_keys=True, ensure_ascii=False)
                        if key not in seen_pii:
                            seen_pii.add(key)
                            pii_findings.append(p)

                    if not _page_has_inputs(page_url, page_html):
                        continue

                    crawl_res["inputs_tested"] += 1

                    page_adv = run_advanced_injection(page_url, page_html)
                    advanced_injections["tested"] += page_adv.get("tested", 0)
                    advanced_injections["parameters"].extend(
                        f"{page_url} :: {param}" for param in page_adv.get("parameters", [])
                    )
                    for finding in page_adv.get("findings", []):
                        key = (
                            finding.get("type"), finding.get("parameter"),
                            finding.get("payload"), finding.get("url"),
                        )
                        if key in injection_keys:
                            continue
                        injection_keys.add(key)
                        finding["page"] = page_url
                        advanced_injections["findings"].append(finding)
                        crawl_res["injection_findings"] += 1

                    if payloads:
                        page_vulns = scanner_visual.run_scanner(page_url, payloads)
                        vuln_results.extend(page_vulns)
                        crawl_res["web_findings"] += sum(
                            1 for v in page_vulns if 'Vulnerável' in v.get('Status', '')
                        )

            # Cálculo de Métricas
            criticos = sum(1 for f in auditor.findings if f['status'] == 'FAIL' and f['severity'] == 'Alta')
            medios = sum(1 for f in auditor.findings if f['status'] == 'FAIL' and f['severity'] == 'Média')
            criticos += sum(1 for v in vuln_results if 'Vulnerável' in v.get('Status', ''))
            criticos += len(sensitive_findings)
            criticos += sum(1 for p in pii_findings if p.get('severity') == 'ALTA')
            medios += sum(1 for p in pii_findings if p.get('severity') == 'MÉDIA')
            criticos += sum(1 for s in secret_findings if s.get('severity') == 'ALTA')
            medios += sum(1 for s in secret_findings if s.get('severity') == 'MÉDIA')
            criticos += sum(1 for j in jwt_findings if j.get('severity') == 'ALTA')
            medios += sum(1 for j in jwt_findings if j.get('severity') == 'MÉDIA')
            criticos += len(advanced_injections.get('findings', []))

            if dns_res["spf"]["status"] == "FAIL":
                medios += 1
            if dns_res["dmarc"]["status"] == "FAIL":
                medios += 1
            if http_methods_res["status"] == "FAIL":
                medios += 1

            final_score = max(0, auditor.score - (len(sensitive_findings) * 20))
            final_score = max(0, final_score - (sum(1 for p in pii_findings if p.get('severity') == 'ALTA') * 10))
            final_score = max(0, final_score - (sum(1 for s in secret_findings if s.get('severity') == 'ALTA') * 15))
            final_score = max(0, final_score - (sum(1 for j in jwt_findings if j.get('severity') == 'ALTA') * 15))
            final_score = max(0, final_score - (len(advanced_injections.get('findings', [])) * 20))
            if http_methods_res["trace_enabled"]:
                final_score = max(0, final_score - 10)

            response_payload = {
                "target": target_url,
                "hostname": hostname,
                "score": final_score,
                "criticos": criticos,
                "medios": medios,
                "headers": auditor.findings,
                "server_info": auditor.server_info,
                "ssl": ssl_res,
                "dns": dns_res,
                "recon": recon_res,
                "cookies": cookies_res,
                "pii": pii_findings,
                "secrets": secret_findings,
                "jwt": jwt_findings,
                "injections_advanced": advanced_injections,
                "crawl": crawl_res,
                "sensitive_files": sensitive_findings,
                "http_methods": http_methods_res,
                "subdomains": subdomains_res,
                "whois": whois_res,
                "geo": geo_res,
                "ports": open_ports,
                "nmap": nmap_res,
                "js_libraries": js_libs,
                "fuzzing": fuzz_results,
                "vulnerabilidades": vuln_results
            }

            save_scan_history(response_payload)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(response_payload, ensure_ascii=False).encode('utf-8'))
        elif self.path == '/api/logs':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_LOG_BYTES:
                self.send_response(413)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(b'{"error": "Arquivo muito grande (limite de 5 MB)"}')
                return

            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
                content = data.get('content', '')
                log_type = data.get('log_type', 'auto')
            except Exception:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "JSON invalido"}')
                return

            if not str(content).strip():
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Conteudo do log obrigatorio"}')
                return

            try:
                result = analyze_logs(content, log_type)
            except Exception as exc:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Falha ao analisar: {exc}"}).encode('utf-8'))
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(result, ensure_ascii=False).encode('utf-8'))
        elif self.path == '/api/proxy/start':
            content_length = int(self.headers.get('Content-Length', 0))
            data = {}
            if content_length > 0:
                try:
                    data = json.loads(self.rfile.read(content_length).decode('utf-8'))
                except Exception:
                    pass
            host = data.get('host', '127.0.0.1')
            try:
                port = int(data.get('port', 8090))
            except (ValueError, TypeError):
                port = 8090
            res = proxy_manager.start(host=host, port=port)
            status_code = 200 if res.get('success') else 400
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(res, ensure_ascii=False).encode('utf-8'))
        elif self.path == '/api/proxy/stop':
            res = proxy_manager.stop()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(res, ensure_ascii=False).encode('utf-8'))
        elif self.path == '/api/proxy/clear':
            res = proxy_manager.clear()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(res, ensure_ascii=False).encode('utf-8'))
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'{"error": "Rota nao encontrada"}')

def run_server():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    socketserver.TCPServer.allow_reuse_address = True

    class ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        # Uma conexão ociosa (ex.: preconnect do navegador) não pode travar o painel
        daemon_threads = True

    with ThreadingServer(("", PORT), PentestHandler) as httpd:
        print("="*60)
        print(f"🚀 PAINEL DE CONTROLE DE SEGURANÇA UNIFICADO!")
        print(f"👉 Acesse no seu navegador: http://localhost:{PORT}")
        print("="*60)
        try:
            webbrowser.open(f"http://localhost:{PORT}")
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Servidor finalizado.")

if __name__ == "__main__":
    run_server()
