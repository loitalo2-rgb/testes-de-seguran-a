import requests
import concurrent.futures
import json
import os

def load_wordlist(file_path="wordlist.json"):
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    all_words = []
    for key in data:
        if isinstance(data[key], list):
            all_words.extend(data[key])
    return list(dict.fromkeys(all_words))

def check_url(url, timeout=3):
    """
    Testa se o caminho responde com código HTTP válido (200, 403, 301, 302).
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecPathFinder/3.0'
        }
        response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=False)
        code = response.status_code
        if code == 200:
            return {"url": url, "status_code": 200, "label": f"[200 OK] {url}"}
        elif code == 403:
            return {"url": url, "status_code": 403, "label": f"[403 Forbidden] {url}"}
        elif code in (301, 302, 307, 308):
            loc = response.headers.get('Location', '')
            return {"url": url, "status_code": code, "label": f"[{code} Redirect] {url} -> {loc}"}
    except Exception:
        pass
    return None

def start_fuzzing(target, wordlist_file="wordlist.json", max_workers=15, recursive=True):
    """
    Varre caminhos no alvo e, caso encontre pastas ativas,
    faz busca recursiva de subpastas automaticamente.
    """
    target = target.rstrip('/')
    print(f"\n{'='*60}")
    print(f"[*] Iniciando Busca Avançada de Pastas & Subpastas: {target}")
    print(f"[*] Recursão Automática: {'Ativada' if recursive else 'Desativada'}")
    print(f"{'='*60}\n")

    paths = load_wordlist(wordlist_file)
    if not paths:
        print("[-] Nenhuma rota carregada da wordlist.")
        return []

    discovered = []
    discovered_folders = []

    # 1ª Rodada: Nível Raiz
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        urls = [f"{target}/{p.lstrip('/')}" for p in paths]
        results = executor.map(check_url, urls)

        for res in results:
            if res:
                print(f"[+] {res['label']}")
                discovered.append(res['label'])
                # Se for código 200, 403 ou 301 e não for um arquivo com extensão (ex: .zip, .sql), marca para subpastas
                url_path = res['url'].replace(target, '').strip('/')
                if '.' not in url_path.split('/')[-1]:
                    discovered_folders.append(res['url'])

    # 2ª Rodada: Recursão Automática em Subpastas Encontradas
    if recursive and discovered_folders:
        print(f"\n[*] Pastas encontradas para busca recursiva: {len(discovered_folders)}")
        sub_words = ["users", "login", "config", "backup", "v1", "v2", "auth", "admin", "status", "health", "metrics", "export", "db", "logs"]
        
        recursive_urls = []
        for folder in discovered_folders[:5]: # Limita às 5 primeiras pastas para equilíbrio de performance
            for sub in sub_words:
                recursive_urls.append(f"{folder.rstrip('/')}/{sub}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            rec_results = executor.map(check_url, recursive_urls)
            for res in rec_results:
                if res:
                    print(f"  [↳ Subpasta] {res['label']}")
                    discovered.append(f"[Subpasta] {res['label']}")

    print(f"\n[*] Varredura de pastas concluída com {len(discovered)} rotas identificadas.")
    return discovered

if __name__ == "__main__":
    target = input("Digite a URL do alvo (ex: https://exemplo.com): ").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    start_fuzzing(target)
