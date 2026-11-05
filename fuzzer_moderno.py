import requests
import concurrent.futures
import json
import os

def load_wordlist(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Achata todas as listas em uma única lista de caminhos/endpoints
    all_words = []
    for key in data:
        if isinstance(data[key], list):
            all_words.extend(data[key])
    return list(dict.fromkeys(all_words))

def check_url(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, timeout=5, headers=headers, allow_redirects=False)
        if response.status_code == 200:
            return f"[+] [200 OK]         {url}"
        elif response.status_code == 403:
            return f"[!] [403 Forbidden]  {url}"
        elif response.status_code in (301, 302):
            return f"[*] [{response.status_code} Redirect]   {url} -> {response.headers.get('Location', '')}"
    except Exception:
        pass
    return None

def start_fuzzing(target, wordlist_file):
    print(f"\n{'='*55}")
    print(f"[*] Iniciando Fuzzing no alvo: {target}")
    print(f"[*] Carregando wordlist de: {wordlist_file}")
    print(f"{'='*55}\n")

    paths = load_wordlist(wordlist_file)
    if not paths:
        print("[-] Nenhuma palavra encontrada na wordlist ou arquivo inválido.")
        return

    print(f"[*] Total de diretórios/arquivos a testar: {len(paths)}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        urls = [f"{target.rstrip('/')}/{path.lstrip('/')}" for path in paths]
        results = executor.map(check_url, urls)

        for result in results:
            if result:
                print(result)

    print(f"\n[*] Fuzzing finalizado com sucesso.")

if __name__ == "__main__":
    target = input("Digite a URL do alvo (ex: https://exemplo.com): ").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    start_fuzzing(target, "wordlist.json")
