import requests
import concurrent.futures

def check_url(url):
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return f"[+] {url} - 200 OK"
        elif response.status_code == 403:
            return f"[!] {url} - 403 Forbidden"
    except requests.exceptions.RequestException:
        pass
    return None

def start_fuzzing(target, wordlist_file):
    print(f"[*] Iniciando Fuzzing: {target}")
    try:
        with open(wordlist_file, 'r') as f:
            paths = [line.strip() for line in f]

        # Usando threads para performance
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            urls = [f"{target.rstrip('/')}/{path}" for path in paths]
            results = executor.map(check_url, urls)

            for result in results:
                if result:
                    print(result)
    except FileNotFoundError:
        print("[-] Arquivo de wordlist não encontrado.")

if __name__ == "__main__":
    # Exemplo básico
    TARGET = "http://example.com"
    WORDLIST = "wordlist.txt"
    start_fuzzing(TARGET, WORDLIST)
