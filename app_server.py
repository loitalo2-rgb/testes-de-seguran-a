import http.server
import socketserver
import json
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

PORT = 5000

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

            # 6. Detecção de Componentes Frontend (JS Libraries)
            js_libs = detect_js_libraries(html_body)

            # 7. Scanner de Arquivos Sensíveis (.git, .env, backups)
            sensitive_findings = check_sensitive_files(target_url)

            # 8. Detecção de Métodos HTTP Inseguros (TRACE, PUT, DELETE)
            http_methods_res = check_http_methods(target_url)

            # 9. Enumeração Passiva de Subdomínios (Certificate Transparency crt.sh)
            subdomains_res = enumerate_subdomains_crtsh(hostname)

            # 10. Auditoria com Nmap (fast, advanced ou deep)
            nmap_res = run_nmap_scan(hostname, mode=nmap_mode)

            # 11. Scanner Rápido de Portas / Serviços Expostos
            open_ports = scan_ports(hostname)

            # 12. Fuzzing e Busca de Pastas & Subpastas
            fuzz_results = fuzzer_moderno.start_fuzzing(target_url, recursive=True)

            # 13. Scanner de Vulnerabilidades (XSS e SQLi)
            payloads = scanner_visual.load_payloads("payloads.json")
            vuln_results = []
            if payloads:
                vuln_results = scanner_visual.run_scanner(target_url, payloads)

            # Cálculo de Métricas
            criticos = sum(1 for f in auditor.findings if f['status'] == 'FAIL' and f['severity'] == 'Alta')
            medios = sum(1 for f in auditor.findings if f['status'] == 'FAIL' and f['severity'] == 'Média')
            criticos += sum(1 for v in vuln_results if 'Vulnerável' in v.get('Status', ''))
            criticos += len(sensitive_findings)

            if dns_res["spf"]["status"] == "FAIL":
                medios += 1
            if dns_res["dmarc"]["status"] == "FAIL":
                medios += 1
            if http_methods_res["status"] == "FAIL":
                medios += 1

            final_score = max(0, auditor.score - (len(sensitive_findings) * 20))
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
                "sensitive_files": sensitive_findings,
                "http_methods": http_methods_res,
                "subdomains": subdomains_res,
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
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), PentestHandler) as httpd:
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
