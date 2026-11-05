import requests
import json
import os
from datetime import datetime

def load_payloads(file_path):
    if not os.path.exists(file_path):
        return {}
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def run_scanner(target_url, payloads):
    results = []
    print(f"\n[*] Iniciando varredura em: {target_url}")

    for categoria, lista in payloads.items():
        print(f"[+] Testando categoria {categoria.upper()} ({len(lista)} payloads)...")
        for payload in lista:
            delim = '&' if '?' in target_url else '?'
            test_url = f"{target_url}{delim}q={requests.utils.quote(payload)}"
            try:
                response = requests.get(test_url, timeout=5)

                status = "Seguro"
                # Detecção de SQLi
                sqli_signatures = ["SQL syntax", "mysql_fetch", "ORA-01756", "SQLite/JDBCDriver", "PostgreSQL query failed"]
                if any(sig.lower() in response.text.lower() for sig in sqli_signatures):
                    status = "Vulnerável (SQLi)"
                # Detecção de XSS
                elif payload in response.text:
                    status = "Vulnerável (XSS)"

                results.append({
                    "URL": test_url,
                    "Payload": payload,
                    "Categoria": categoria,
                    "Status": status
                })
            except Exception as e:
                print(f"  [-] Erro ao testar payload {payload[:15]}: {e}")
    return results

def generate_html_report(results):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = ""
    for r in results:
        is_vuln = "Vulnerável" in r['Status']
        css_class = "vulneravel" if is_vuln else "seguro"
        rows += f"""
        <tr>
            <td style="word-break: break-all;">{r['URL']}</td>
            <td><code>{r['Payload']}</code></td>
            <td>{r['Categoria']}</td>
            <td class='{css_class}'>{r['Status']}</td>
        </tr>"""

    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <title>Relatório de Pentest</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
            h1 {{ color: #38bdf8; }}
            table {{ border-collapse: collapse; width: 100%; background: #1e293b; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 14px; border: 1px solid #334155; text-align: left; font-size: 14px; }}
            th {{ background-color: #1e293b; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 12px; }}
            .vulneravel {{ background-color: rgba(239, 68, 68, 0.2); color: #f87171; font-weight: bold; }}
            .seguro {{ color: #34d399; font-weight: 600; }}
            code {{ background: #090d16; padding: 3px 6px; border-radius: 4px; color: #fbbf24; font-family: monospace; }}
        </style>
    </head>
    <body>
        <h1>Relatório de Scan de Vulnerabilidades</h1>
        <p><b>Data:</b> {timestamp}</p>
        <table>
            <tr><th>URL Testada</th><th>Payload</th><th>Categoria</th><th>Status</th></tr>
            {rows}
        </table>
    </body>
    </html>
    """
    with open("relatorio_seguranca.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    print("\n[+] Relatório visual gerado: relatorio_seguranca.html")

if __name__ == "__main__":
    TARGET = input("Digite a URL base (ex: http://testphp.vulnweb.com/listproducts.php): ").strip()
    PAYLOADS = load_payloads("payloads.json")

    if not PAYLOADS:
        print("[-] Erro: Arquivo payloads.json não encontrado ou vazio.")
    else:
        resultados = run_scanner(TARGET, PAYLOADS)
        generate_html_report(resultados)
        print("\n[*] Scan finalizado com sucesso.")
