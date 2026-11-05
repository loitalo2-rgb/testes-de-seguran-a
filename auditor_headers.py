import requests
import json
from datetime import datetime
import urllib.parse

class SecurityHeaderAuditor:
    """
    Auditor defensivo de cabeçalhos de segurança HTTP e boas práticas de configuração.
    Baseado nas recomendações do OWASP Secure Headers Project.
    """

    CRITERIA = {
        "Strict-Transport-Security": {
            "name": "HSTS (Strict-Transport-Security)",
            "severity": "Alta",
            "description": "Força navegadores a se comunicarem apenas via HTTPS, prevenindo ataques de SSL Stripping.",
            "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        },
        "Content-Security-Policy": {
            "name": "CSP (Content-Security-Policy)",
            "severity": "Alta",
            "description": "Controla a origem de scripts, estilos e recursos executáveis, mitigando ataques de XSS e injeção de dados.",
            "recommendation": "Definir uma diretiva CSP restritiva, evitando 'unsafe-inline' e 'unsafe-eval'."
        },
        "X-Frame-Options": {
            "name": "Proteção Anti-Clickjacking (X-Frame-Options)",
            "severity": "Média",
            "description": "Impede que a aplicação seja embutida em iframes maliciosos.",
            "recommendation": "X-Frame-Options: DENY ou SAMEORIGIN (ou frame-ancestors via CSP)"
        },
        "X-Content-Type-Options": {
            "name": "Anti-MIME Sniffing (X-Content-Type-Options)",
            "severity": "Média",
            "description": "Impede navegadores de adivinharem o MIME-type de arquivos, reduzindo riscos de execução acidental de scripts.",
            "recommendation": "X-Content-Type-Options: nosniff"
        },
        "Referrer-Policy": {
            "name": "Controle de Vazamento de Referência (Referrer-Policy)",
            "severity": "Baixa",
            "description": "Controla quanta informação sobre a URL de origem é repassada em requisições de saída.",
            "recommendation": "Referrer-Policy: strict-origin-when-cross-origin ou no-referrer"
        },
        "Permissions-Policy": {
            "name": "Políticas de Recursos do Navegador (Permissions-Policy)",
            "severity": "Baixa",
            "description": "Permite habilitar/desabilitar recursos do dispositivo (câmera, microfone, geolocalização).",
            "recommendation": "Permissions-Policy: geolocation=(), camera=(), microphone=()"
        }
    }

    LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

    def __init__(self, target_url):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url
        self.findings = []
        self.server_info = {}
        self.cookie_findings = []
        self.score = 100

    def run_audit(self):
        print(f"\n[*] Iniciando Auditoria Defensiva em: {self.target_url}")
        try:
            headers = {
                "User-Agent": "SecQA-DefensiveAuditor/1.0 (OWASP-Header-Inspector)"
            }
            response = requests.get(self.target_url, timeout=10, headers=headers, allow_redirects=True)
            resp_headers = response.headers
            cookies = response.cookies

            # 1. Auditoria de Cabeçalhos de Segurança Recomendados
            for header_key, meta in self.CRITERIA.items():
                val = resp_headers.get(header_key)
                if val:
                    self.findings.append({
                        "header": header_key,
                        "title": meta["name"],
                        "status": "PASS",
                        "severity": meta["severity"],
                        "value": val,
                        "detail": "Presente e configurado.",
                        "recommendation": meta["recommendation"]
                    })
                else:
                    deduction = 20 if meta["severity"] == "Alta" else (10 if meta["severity"] == "Média" else 5)
                    self.score = max(0, self.score - deduction)
                    self.findings.append({
                        "header": header_key,
                        "title": meta["name"],
                        "status": "FAIL",
                        "severity": meta["severity"],
                        "value": "Ausente",
                        "detail": meta["description"],
                        "recommendation": meta["recommendation"]
                    })

            # 2. Detecção de Exposição de Informações (Fingerprinting)
            for leak in self.LEAK_HEADERS:
                val = resp_headers.get(leak)
                if val:
                    self.server_info[leak] = val
                    self.score = max(0, self.score - 5)

            # 3. Auditoria de Flags em Cookies (Secure, HttpOnly, SameSite)
            for cookie in cookies:
                cookie_issues = []
                if not cookie.secure and self.target_url.startswith("https://"):
                    cookie_issues.append("Falta flag 'Secure'")
                if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, 'httponly', False):
                    cookie_issues.append("Falta flag 'HttpOnly'")
                
                self.cookie_findings.append({
                    "name": cookie.name,
                    "issues": cookie_issues if cookie_issues else ["Configuração Segura"]
                })

            return True

        except requests.exceptions.RequestException as e:
            print(f"[-] Erro ao conectar ao alvo: {e}")
            return False

    def print_summary(self):
        print("\n" + "="*50)
        print(f"  RESULTADO DA AUDITORIA DEFENSIVA")
        print("="*50)
        print(f"Alvo: {self.target_url}")
        print(f"Pontuação de Conformidade: {self.score}/100")
        print("-" * 50)

        for f in self.findings:
            icon = "[✓]" if f["status"] == "PASS" else "[✗]"
            print(f"{icon} {f['title']} ({f['severity']}): {f['status']}")
            if f["status"] == "FAIL":
                print(f"    Recomendação: {f['recommendation']}")

        if self.server_info:
            print("\n[!] Exposição de Versão/Tecnologia (Recomenda-se ocultar):")
            for k, v in self.server_info.items():
                print(f"    {k}: {v}")
        else:
            print("\n[✓] Nenhum cabeçalho identificador de versão exposto.")
        print("="*50 + "\n")

    def export_html(self, output_file="relatorio_auditoria_headers.html"):
        rows = ""
        for f in self.findings:
            is_pass = f["status"] == "PASS"
            status_cls = "pass" if is_pass else "fail"
            rows += f"""
            <tr>
                <td><b>{f['title']}</b></td>
                <td><span class='badge {f['severity'].lower()}'>{f['severity']}</span></td>
                <td><span class='status {status_cls}'>{f['status']}</span></td>
                <td><code>{f['value']}</code></td>
                <td>{f['recommendation']}</td>
            </tr>
            """

        leaks_html = ""
        if self.server_info:
            leaks_html = "<h3>⚠️ Exposição de Tecnologias Detectada:</h3><ul>"
            for k, v in self.server_info.items():
                leaks_html += f"<li><b>{k}:</b> <code>{v}</code> (Recomenda-se desativar)</li>"
            leaks_html += "</ul>"

        html_content = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <title>Relatório de Auditoria Defensiva - OWASP Headers</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f172a; color: #f8fafc; margin: 30px; }}
                .container {{ max-width: 1000px; margin: auto; }}
                .header-box {{ background: #1e293b; padding: 25px; border-radius: 12px; margin-bottom: 25px; border: 1px solid #334155; }}
                .score {{ font-size: 32px; font-weight: bold; color: {'#34d399' if self.score >= 70 else '#f87171'}; }}
                table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; }}
                th, td {{ padding: 12px 16px; border: 1px solid #334155; text-align: left; font-size: 14px; }}
                th {{ background: #090d16; color: #94a3b8; font-size: 12px; text-transform: uppercase; }}
                .badge {{ padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; }}
                .badge.alta {{ background: rgba(239, 68, 68, 0.2); color: #f87171; }}
                .badge.média {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; }}
                .badge.baixa {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; }}
                .status.pass {{ color: #34d399; font-weight: bold; }}
                .status.fail {{ color: #f87171; font-weight: bold; }}
                code {{ background: #090d16; padding: 2px 6px; border-radius: 4px; color: #cbd5e1; font-family: monospace; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header-box">
                    <h1>Auditoria Defensiva de Cabeçalhos HTTP</h1>
                    <p><b>Alvo Auditado:</b> {self.target_url}</p>
                    <p><b>Data:</b> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                    <div class="score">Conformidade: {self.score}/100</div>
                    {leaks_html}
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Cabeçalho / Controle</th>
                            <th>Criticidade</th>
                            <th>Status</th>
                            <th>Valor Atual</th>
                            <th>Recomendação Técnica</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] Relatório exportado com sucesso: {output_file}")

if __name__ == "__main__":
    target = input("Informe o domínio ou URL para auditoria (ex: https://example.com): ").strip()
    if target:
        auditor = SecurityHeaderAuditor(target)
        if auditor.run_audit():
            auditor.print_summary()
            auditor.export_html()
