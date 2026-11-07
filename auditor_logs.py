import re
import urllib.parse
from collections import Counter

MAX_FINDINGS = 40
MAX_EVIDENCE = 200

# Formato combinado Apache/Nginx (com ou sem referer/User-Agent)
WEB_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+?)(?:\s+HTTP/[0-9.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

SSH_FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
SSH_ACCEPT_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")

SCANNER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "nuclei", "dirbuster", "gobuster",
    "ffuf", "wfuzz", "wpscan", "acunetix", "netsparker", "burp", "zap",
    "zgrab", "censys", "shodan", "dirb", "feroxbuster", "nmap scripting engine",
]

ATTACK_PATTERNS = [
    {
        "type": "SQL Injection",
        "category": "Injeção",
        "severity": "ALTA",
        "desc": "Requisição com padrões de injeção SQL.",
        "impact": "Se a aplicação for vulnerável, o atacante lê/altera dados e pode obter execução de comandos no banco.",
        "fix": "Usar consultas parametrizadas, validar entradas e bloquear o IP reincidente no WAF.",
        "regex": re.compile(
            r"(?i)(union\s+select|information_schema|sleep\s*\(\s*\d|benchmark\s*\(|"
            r"'\s*or\s+'?1'?\s*=\s*'?1|'\s*or\s+1\s*=\s*1|concat\s*\(|--\s|/\*!)"
        ),
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "category": "Injeção",
        "severity": "ALTA",
        "desc": "Requisição com payload de script.",
        "impact": "O atacante tenta executar JavaScript no navegador de vítimas para roubar sessão e credenciais.",
        "fix": "Codificar saídas, aplicar CSP restritiva e validar entradas.",
        "regex": re.compile(r"(?i)(<script|onerror\s*=|onload\s*=|javascript:|document\.cookie|%3cscript)"),
    },
    {
        "type": "LFI / Path Traversal",
        "category": "Inclusão de Arquivos",
        "severity": "ALTA",
        "desc": "Tentativa de leitura de arquivos fora do diretório web.",
        "impact": "O atacante pode ler credenciais, código-fonte e chaves do servidor.",
        "fix": "Validar caminhos com allowlist e bloquear sequências de traversal.",
        "regex": re.compile(r"(?i)(\.\./|%2e%2e|/etc/passwd|php://|win\.ini|\.\.\\)"),
    },
    {
        "type": "Command Injection",
        "category": "Execução de Comandos",
        "severity": "ALTA",
        "desc": "Padrões de execução de comandos do sistema na requisição.",
        "impact": "O atacante pode executar comandos arbitrários no servidor.",
        "fix": "Nunca montar comandos com entrada do usuário; usar APIs nativas.",
        "regex": re.compile(r"(?i)(;\s*(wget|curl|bash|sh|nc|echo|id|cat)\b|\|\s*(bash|sh|nc)\b|\$\(|`[^`]+`)"),
    },
    {
        "type": "Arquivo/configuração sensível",
        "category": "Exposição de Arquivos",
        "severity": "ALTA",
        "desc": "Tentativa de acesso a arquivos sensíveis conhecidos.",
        "impact": "Se acessível, expõe credenciais, repositório Git, dumps e configurações internas.",
        "fix": "Bloquear no servidor web e remover arquivos sensíveis do diretório público.",
        "regex": re.compile(
            r"(?i)(/\.env\b|/\.git/|wp-config\.php|\.sql\b|\.bak\b|phpinfo|"
            r"id_rsa|\.htpasswd|config\.php|/backup)"
        ),
    },
    {
        "type": "Exploração Log4j/Spring (JNDI)",
        "category": "Execução Remota",
        "severity": "ALTA",
        "desc": "Requisição contendo expressão JNDI (Log4Shell/Spring4Shell).",
        "impact": "Pode levar à execução remota de código e comprometimento total do servidor.",
        "fix": "Atualizar bibliotecas afetadas e bloquear padrões ${jndi: no WAF.",
        "regex": re.compile(r"(?i)\$\{jndi:|class\.module\.classLoader"),
    },
]

LOGIN_PATHS = ("/login", "/admin", "/wp-login", "/signin", "/auth", "/usuario", "/entrar")


def _truncate(value, limit=MAX_EVIDENCE):
    value = str(value).replace("\n", " ").strip()
    return value[:limit] + ("..." if len(value) > limit else "")


def _new_finding(kind, category, severity, desc, impact, fix, ip, count, evidence):
    return {
        "type": kind,
        "category": category,
        "severity": severity,
        "source_ip": ip,
        "count": count,
        "evidence": _truncate(evidence),
        "desc": desc,
        "impact": impact,
        "fix": fix,
    }


def _detect_log_type(lines):
    ssh = sum(1 for line in lines if SSH_FAIL_RE.search(line) or SSH_INVALID_RE.search(line) or SSH_ACCEPT_RE.search(line))
    web = sum(1 for line in lines if WEB_LOG_RE.match(line))
    if ssh > web:
        return "auth"
    if web > 0:
        return "web"
    return "unknown"


def _analyze_web(lines):
    total = len(lines)
    parsed = 0
    ips = Counter()
    paths = Counter()
    statuses = Counter()
    methods = Counter()
    agents = Counter()
    attack_hits = {}
    scanner_hits = {}
    not_found = Counter()
    denied = Counter()
    login_posts = Counter()
    samples = {}

    for line in lines:
        match = WEB_LOG_RE.match(line)
        if not match:
            continue
        parsed += 1
        ip = match.group("ip")
        method = match.group("method").upper()
        raw_path = match.group("path")
        status = match.group("status")
        agent = match.group("ua") or ""
        path = urllib.parse.unquote_plus(raw_path)

        ips[ip] += 1
        paths[path.split("?")[0][:120]] += 1
        statuses[status] += 1
        methods[method] += 1
        if agent:
            agents[agent[:120]] += 1
        if status == "404":
            not_found[ip] += 1
        if status in ("401", "403"):
            denied[ip] += 1
        if method == "POST" and any(login in path.lower() for login in LOGIN_PATHS):
            login_posts[ip] += 1

        searchable = path
        for rule in ATTACK_PATTERNS:
            if not rule["regex"].search(searchable):
                continue
            key = (rule["type"], ip)
            if key not in attack_hits:
                attack_hits[key] = {"count": 0, "statuses": set(), "sample": ""}
                samples[key] = f"{method} {raw_path} -> {status} (IP {ip})"
            attack_hits[key]["count"] += 1
            attack_hits[key]["statuses"].add(status)

        agent_lower = agent.lower()
        for scanner in SCANNER_AGENTS:
            if scanner in agent_lower:
                scan_key = (scanner, ip)
                if scan_key not in scanner_hits:
                    scanner_hits[scan_key] = {"count": 0, "sample": f"User-Agent: {_truncate(agent, 120)}"}
                scanner_hits[scan_key]["count"] += 1
                break

    findings = []

    for (kind, ip), info in attack_hits.items():
        rule = next((r for r in ATTACK_PATTERNS if r["type"] == kind), None)
        if not rule:
            continue
        successful = any(s.startswith("2") for s in info["statuses"])
        severity = "ALTA" if successful else "MÉDIA"
        evidence = samples[(kind, ip)]
        if successful:
            evidence += " [resposta 2xx: possível sucesso]"
        findings.append(_new_finding(
            kind, rule["category"], severity, rule["desc"], rule["impact"], rule["fix"],
            ip, info["count"], evidence,
        ))

    for (scanner, ip), info in scanner_hits.items():
        findings.append(_new_finding(
            "Ferramenta de varredura automatizada", "Reconhecimento", "MÉDIA",
            f"User-Agent identificado como ferramenta de pentest ({scanner}).",
            "O atacante está mapeando a aplicação para encontrar falhas exploráveis.",
            "Bloquear o IP/User-Agent no WAF e revisar os acessos posteriores desse IP.",
            ip, info["count"], info["sample"],
        ))

    for ip, count in not_found.items():
        if count >= 20:
            findings.append(_new_finding(
                "Varredura de diretórios/arquivos", "Reconhecimento", "MÉDIA",
                f"{count} respostas 404 para o mesmo IP em sequência.",
                "Indica fuzzing de rotas para descobrir painéis, backups e arquivos ocultos.",
                "Bloquear o IP, aplicar rate limiting e monitorar a taxa de 404.",
                ip, count, f"{count} requisições com status 404",
            ))

    for ip, count in denied.items():
        if count >= 10:
            findings.append(_new_finding(
                "Tentativas de acesso negado", "Força Bruta", "MÉDIA",
                f"{count} respostas 401/403 para o mesmo IP.",
                "Pode indicar força bruta em autenticação ou tentativa de acesso a áreas restritas.",
                "Aplicar rate limiting, MFA e bloqueio progressivo.",
                ip, count, f"{count} requisições com status 401/403",
            ))

    for ip, count in login_posts.items():
        if count >= 10:
            findings.append(_new_finding(
                "Força bruta em login", "Força Bruta", "ALTA",
                f"{count} POSTs para rotas de autenticação do mesmo IP.",
                "O atacante tenta adivinhar credenciais de usuários.",
                "Habilitar rate limiting, CAPTCHA, MFA e bloqueio temporário.",
                ip, count, f"{count} POSTs para login (IP {ip})",
            ))

    error_count = sum(c for s, c in statuses.items() if s.startswith("4") or s.startswith("5"))
    summary = {
        "total_lines": total,
        "parsed_lines": parsed,
        "unique_ips": len(ips),
        "requests": parsed,
        "error_rate": round((error_count / parsed) * 100, 1) if parsed else 0.0,
        "top_ips": [{"ip": ip, "count": c} for ip, c in ips.most_common(10)],
        "top_paths": [{"path": p, "count": c} for p, c in paths.most_common(10)],
        "status_codes": dict(statuses.most_common(10)),
        "methods": dict(methods.most_common()),
        "top_agents": [{"agent": a, "count": c} for a, c in agents.most_common(5)],
    }
    return summary, findings


def _analyze_auth(lines):
    failed = Counter()
    users = Counter()
    accepted = Counter()
    samples = {}

    for line in lines:
        match = SSH_FAIL_RE.search(line)
        if match:
            ip = match.group("ip")
            failed[ip] += 1
            users[match.group("user")] += 1
            samples.setdefault(ip, line)
            continue
        match = SSH_INVALID_RE.search(line)
        if match:
            ip = match.group("ip")
            failed[ip] += 1
            users[match.group("user")] += 1
            samples.setdefault(ip, line)
            continue
        match = SSH_ACCEPT_RE.search(line)
        if match:
            accepted[match.group("ip")] += 1

    findings = []
    for ip, count in failed.most_common():
        severity = "ALTA"
        evidence = samples.get(ip, f"{count} falhas de autenticação")
        if accepted.get(ip):
            evidence += f" [login bem-sucedido após falhas: {accepted[ip]}]"
        # Um login aceito depois de falhas é grave mesmo com poucas tentativas
        if count >= 5 or accepted.get(ip):
            findings.append(_new_finding(
                "Força bruta SSH", "Força Bruta", severity,
                f"{count} falhas de autenticação SSH do mesmo IP.",
                "O atacante tenta adivinhar credenciais; se obteve sucesso, o servidor pode estar comprometido.",
                "Bloquear o IP, desabilitar senha (usar chaves), aplicar fail2ban e MFA.",
                ip, count, evidence,
            ))

    summary = {
        "total_lines": len(lines),
        "parsed_lines": sum(failed.values()) + sum(accepted.values()),
        "unique_ips": len(set(failed) | set(accepted)),
        "requests": sum(failed.values()) + sum(accepted.values()),
        "error_rate": 0.0,
        "failed_logins": sum(failed.values()),
        "accepted_logins": sum(accepted.values()),
        "top_ips": [{"ip": ip, "count": c} for ip, c in failed.most_common(10)],
        "top_users": [{"user": u, "count": c} for u, c in users.most_common(10)],
        "top_paths": [],
        "status_codes": {},
        "methods": {},
        "top_agents": [],
    }
    return summary, findings


def analyze_logs(content, log_type="auto"):
    """
    Analisa logs web (Apache/Nginx common/combined) ou de autenticação (SSH)
    e devolve estatísticas + tentativas de ataque detectadas.
    """
    lines = [line.strip() for line in (content or "").splitlines() if line.strip()]
    if log_type not in ("web", "auth", "auto"):
        log_type = "auto"
    detected = _detect_log_type(lines) if log_type == "auto" else log_type
    if detected == "auth":
        summary, findings = _analyze_auth(lines)
    elif detected == "web":
        summary, findings = _analyze_web(lines)
    else:
        summary = {
            "total_lines": len(lines), "parsed_lines": 0, "unique_ips": 0,
            "requests": 0, "error_rate": 0.0, "top_ips": [], "top_paths": [],
            "status_codes": {}, "methods": {}, "top_agents": [],
        }
        findings = []

    order = {"ALTA": 0, "MÉDIA": 1, "BAIXA": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 3), -f["count"]))
    return {
        "log_type": detected,
        "summary": summary,
        "findings": findings[:MAX_FINDINGS],
        "findings_total": len(findings),
    }
