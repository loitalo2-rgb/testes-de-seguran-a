import requests
import json
import os
import csv
from datetime import datetime

def load_payloads(file_path):
    if not os.path.exists(file_path):
        return {}
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def run_scanner(target_url, payloads):
    report_data = []
    print(f"\n[*] Iniciando varredura no alvo: {target_url}")

    for categoria, lista in payloads.items():
        print(f"\n[+] Testando Categoria: {categoria.upper()}")
        for payload in lista:
            test_url = f"{target_url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=3)

                status = "Seguro"
                # Lógica básica de detecção
                if "SQL syntax" in response.text or "mysql_fetch" in response.text:
                    status = "Vulnerável (SQLi)"
                elif payload in response.text:
                    status = "Vulnerável (XSS)"

                print(f"  [-] Testado: {payload[:20]}... -> {status}")

                report_data.append({
                    "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "URL": test_url,
                    "Payload": payload,
                    "Categoria": categoria,
                    "Status": status
                })
            except Exception as e:
                print(f"  [-] Erro na requisição: {e}")

    return report_data

def save_report(data):
    filename = f"relatorio_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    keys = data[0].keys() if data else []

    with open(filename, 'w', newline='', encoding='utf-8') as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)

    print(f"\n[*] Relatório salvo com sucesso em: {filename}")

if __name__ == "__main__":
    TARGET = input("Digite a URL base (ex: http://testphp.vulnweb.com/listproducts.php): ").strip()
    PAYLOADS = load_payloads("payloads.json")

    resultados = run_scanner(TARGET, PAYLOADS)

    if resultados:
        save_report(resultados)

    print("\n[*] Varredura concluída.")
