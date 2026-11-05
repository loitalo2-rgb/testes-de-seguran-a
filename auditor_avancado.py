import socket
import concurrent.futures
import requests
import re
import json
import os
from datetime import datetime

# Portas padrão de serviços web, bancos e dev
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3000: "Node.js / React Dev",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "Django / FastAPI",
    8080: "HTTP Proxy / Tomcat",
    8443: "HTTPS Alternativo",
    27017: "MongoDB"
}

# Arquivos sensíveis de configuração, credenciais, senhas e backups
SENSITIVE_FILES = [
    {"path": "/senhas.txt", "type": "credenciais", "desc": "Arquivo de Senhas Exposto (senhas.txt)"},
    {"path": "/passwords.txt", "type": "credenciais", "desc": "Arquivo de Senhas Exposto (passwords.txt)"},
    {"path": "/senha.txt", "type": "credenciais", "desc": "Arquivo de Senha Exposto (senha.txt)"},
    {"path": "/credentials.txt", "type": "credenciais", "desc": "Credenciais em Texto Puro (credentials.txt)"},
    {"path": "/credenciais.txt", "type": "credenciais", "desc": "Credenciais em Texto Puro (credenciais.txt)"},
    {"path": "/usuarios.txt", "type": "credenciais", "desc": "Lista de Usuários/Senhas (usuarios.txt)"},
    {"path": "/users.txt", "type": "credenciais", "desc": "Lista de Usuários Exposta (users.txt)"},
    {"path": "/segredo.txt", "type": "credenciais", "desc": "Chaves ou Segredos (segredo.txt)"},
    {"path": "/secret.txt", "type": "credenciais", "desc": "Chaves ou Segredos (secret.txt)"},
    {"path": "/.env", "type": "config", "sig": "DB_", "desc": "Variáveis de Ambiente (.env)"},
    {"path": "/.env.local", "type": "config", "sig": "=", "desc": "Variáveis de Ambiente Locais (.env.local)"},
    {"path": "/.env.backup", "type": "config", "sig": "=", "desc": "Backup de Variáveis (.env.backup)"},
    {"path": "/.git/HEAD", "type": "git", "sig": "ref: refs/", "desc": "Repositório Git Exposto (.git/HEAD)"},
    {"path": "/.git/config", "type": "git", "sig": "[core]", "desc": "Configuração Git Exposta (.git/config)"},
    {"path": "/docker-compose.yml", "type": "config", "sig": "version:", "desc": "Definição de Containers (docker-compose.yml)"},
    {"path": "/web.config", "type": "config", "sig": "<configuration>", "desc": "Configuração IIS (web.config)"},
    {"path": "/phpinfo.php", "type": "debug", "sig": "PHP Version", "desc": "Exposição de Diagnóstico (phpinfo.php)"},
    {"path": "/database.sql", "type": "backup", "sig": "CREATE", "desc": "Dump de Banco de Dados (database.sql)"},
    {"path": "/dump.sql", "type": "backup", "sig": "CREATE", "desc": "Dump de Banco de Dados (dump.sql)"},
    {"path": "/backup.sql", "type": "backup", "sig": "CREATE", "desc": "Backup SQL (backup.sql)"},
    {"path": "/backup.zip", "type": "backup", "sig": "PK", "desc": "Backup Compactado (backup.zip)"}
]

def check_port(host, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Desconhecido")
                return {"port": port, "service": service, "status": "ABERTA"}
    except Exception:
        pass
    return None

def scan_ports(hostname):
    """Varre portas web e de banco de dados mais comuns de forma concorrente"""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(check_port, hostname, p): p for p in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
    return sorted(open_ports, key=lambda x: x["port"])

def check_sensitive_files(base_url):
    """Verifica se arquivos sensíveis (senhas.txt, .git, .env, backups) estão acessíveis publicamente"""
    findings = []
    clean_base = base_url.rstrip('/')
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecAudit/2.0"}

    for item in SENSITIVE_FILES:
        target = clean_base + item["path"]
        try:
            resp = requests.get(target, headers=headers, timeout=4, allow_redirects=False)
            if resp.status_code == 200:
                body = resp.text.strip()
                # Validação inteligente para evitar falsos positivos de páginas 404/HTML personalizadas
                is_valid = False

                # 1. Arquivos de texto com senhas ou credenciais
                if item.get("type") == "credenciais":
                    # Um arquivo de texto real não deve retornar um documento HTML completo (ex: <!DOCTYPE html>)
                    if "<!doctype html" not in body.lower() and "<html" not in body.lower() and len(body) > 0:
                        is_valid = True
                # 2. Arquivos com assinatura específica (ex: git, .env, dumps)
                elif "sig" in item:
                    if item["sig"] in body:
                        is_valid = True
                else:
                    if "<!doctype html" not in body.lower() and len(body) > 0:
                        is_valid = True

                if is_valid:
                    # Amostra segura das primeiras linhas (sem vazar tudo em tela)
                    preview = "\n".join(body.splitlines()[:3])
                    if len(preview) > 120:
                        preview = preview[:120] + "..."

                    findings.append({
                        "path": item["path"],
                        "url": target,
                        "description": item["desc"],
                        "severity": "CRÍTICA",
                        "status": "EXPOSTO",
                        "preview": preview
                    })
        except Exception:
            pass
    return findings

def detect_js_libraries(html_content):
    """Detecta bibliotecas frontend e versões incluídas no HTML da página"""
    libraries = []
    patterns = {
        "jQuery": r"jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "Bootstrap": r"bootstrap[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "React": r"react[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "Vue.js": r"vue[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "Angular": r"angular[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "Lodash": r"lodash[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)"
    }

    if not html_content:
        return libraries

    for lib, regex in patterns.items():
        match = re.search(regex, html_content, re.IGNORECASE)
        if match:
            version = match.group(1)
            libraries.append({"name": lib, "version": version, "status": "Detectado"})
        elif lib.lower() in html_content.lower():
            libraries.append({"name": lib, "version": "Não identificada", "status": "Detectado"})

    return libraries

def save_scan_history(scan_result, history_file="historico_scans.json"):
    """Salva a varredura realizada no histórico local"""
    history = []
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
        except Exception:
            history = []

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": scan_result.get("target"),
        "hostname": scan_result.get("hostname"),
        "score": scan_result.get("score"),
        "criticos": scan_result.get("criticos"),
        "medios": scan_result.get("medios")
    }
    history.insert(0, entry)
    history = history[:30] # Guarda as últimas 30 varreduras

    with open(history_file, 'w', encoding='utf-8') as f:
        json.dump(history, f, ensure_ascii=False, indent=2)

    return history
