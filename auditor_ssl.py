import ssl
import socket
from datetime import datetime

def get_ssl_info(hostname, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                return {
                    "hostname": hostname,
                    "version": version,
                    "cipher": cipher[0] if cipher else "N/A",
                    "cipher_bits": cipher[2] if cipher else "N/A",
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "notAfter": cert.get('notAfter', 'N/A')
                }
    except Exception as e:
        return {"error": str(e), "hostname": hostname}

def generate_html_report(info):
    filename = "relatorio_ssl.html"
    if "error" in info:
        content = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <title>Erro Auditoria SSL</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
                .card {{ background: #1e293b; padding: 25px; border-radius: 12px; border: 1px solid #ef4444; }}
                h2 {{ color: #ef4444; }}
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Falha ao auditar SSL de {info.get('hostname')}</h2>
                <p><b>Erro:</b> {info['error']}</p>
            </div>
        </body>
        </html>
        """
    else:
        content = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <title>Relatório SSL/TLS - {info['hostname']}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
                .card {{ background: #1e293b; padding: 30px; border-radius: 12px; border: 1px solid #334155; max-width: 600px; margin: auto; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
                h2 {{ color: #38bdf8; margin-top: 0; }}
                p {{ font-size: 15px; margin: 10px 0; }}
                b {{ color: #94a3b8; }}
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Auditoria SSL/TLS: {info['hostname']}</h2>
                <p><b>Versão do Protocolo:</b> {info['version']}</p>
                <p><b>Cifra Utilizada:</b> {info['cipher']} ({info['cipher_bits']} bits)</p>
                <p><b>Data de Expiração:</b> {info['notAfter']}</p>
                <p><b>Autoridade Emissora (CA):</b> {info['issuer'].get('commonName', 'N/A')}</p>
                <p><b>Organização:</b> {info['issuer'].get('organizationName', 'N/A')}</p>
            </div>
        </body>
        </html>
        """
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Relatório SSL gerado: {filename}")

if __name__ == "__main__":
    host = input("Digite o hostname (ex: google.com): ").strip()
    print("[*] Auditando SSL...")
    info = get_ssl_info(host)
    generate_html_report(info)
