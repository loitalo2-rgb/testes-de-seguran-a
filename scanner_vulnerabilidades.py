import requests
import json
import os

def load_payloads(file_path):
    if not os.path.exists(file_path):
        return {}
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def run_scanner(target_url, payloads):
    print(f"\n[*] Iniciando varredura no alvo: {target_url}")

    # Simulação de varredura em parâmetros (exemplo: ?id=)
    # Em um cenário real, você apontaria para um formulário ou parâmetro específico
    for categoria, lista in payloads.items():
        print(f"\n[+] Testando Categoria: {categoria.upper()}")
        for payload in lista:
            test_url = f"{target_url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=3)
                # Análise simples: procurando erros de banco de dados ou reflexão do payload
                if "SQL syntax" in response.text or "mysql_fetch" in response.text:
                    print(f"  [!] POSSÍVEL SQLi ENCONTRADO com: {payload}")
                elif payload in response.text:
                    print(f"  [!] POSSÍVEL XSS ENCONTRADO com: {payload}")
                else:
                    print(f"  [-] Testado: {payload[:20]}...")
            except Exception as e:
                print(f"  [-] Erro na requisição: {e}")

if __name__ == "__main__":
    TARGET = input("Digite a URL base (ex: http://exemplo.com/produto): ").strip()
    PAYLOADS = load_payloads("payloads.json")
    run_scanner(TARGET, PAYLOADS)
    print("\n[*] Varredura concluída.")
