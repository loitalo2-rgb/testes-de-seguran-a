import concurrent.futures
import re
import urllib.parse

import requests

# Limites de segurança para não baixar bundles gigantes nem varrer dezenas de scripts
MAX_SCRIPTS = 12
MAX_SCRIPT_BYTES = 750_000
REQUEST_TIMEOUT = 5
MAX_FINDINGS = 50
MAX_PER_TYPE = 5

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecAudit/SecretScanner"

# Cada regra: tipo, categoria, severidade, regex, grupo (opcional) e descrição.
# Regras com "mask": False exibem o valor literal (ex.: cabeçalho de chave privada).
SECRET_PATTERNS = [
    {
        "type": "AWS Access Key ID",
        "category": "Credencial Cloud",
        "severity": "ALTA",
        "regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "desc": "Chave de acesso AWS exposta. Permite acesso programático à conta se ainda estiver ativa.",
    },
    {
        "type": "AWS Secret Access Key",
        "category": "Credencial Cloud",
        "severity": "ALTA",
        "regex": r"(?i)aws[_\- ]?secret[_\- ]?access[_\- ]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "group": 1,
        "desc": "Segredo de acesso AWS (AWS Secret Access Key) embutido no código.",
    },
    {
        "type": "Google API Key",
        "category": "Credencial Cloud",
        "severity": "MÉDIA",
        "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "desc": "Chave de API do Google exposta. Pode permitir consumo indevido de serviços e cobrança.",
    },
    {
        "type": "Google OAuth Client Secret",
        "category": "Credencial Cloud",
        "severity": "ALTA",
        "regex": r"\bGOCSPX-[A-Za-z0-9_-]{28}\b",
        "desc": "Client Secret de OAuth do Google exposto.",
    },
    {
        "type": "Stripe Secret Key",
        "category": "Financeiro / Pagamentos",
        "severity": "ALTA",
        "regex": r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b",
        "desc": "Chave secreta de produção do Stripe exposta. Risco de movimentação financeira indevida.",
    },
    {
        "type": "GitHub Token",
        "category": "Credencial de Código",
        "severity": "ALTA",
        "regex": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
        "desc": "Token de acesso ao GitHub exposto. Pode permitir leitura/escrita em repositórios.",
    },
    {
        "type": "GitLab Token",
        "category": "Credencial de Código",
        "severity": "ALTA",
        "regex": r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        "desc": "Token de acesso ao GitLab exposto.",
    },
    {
        "type": "Slack Token",
        "category": "Credencial de Comunicação",
        "severity": "ALTA",
        "regex": r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
        "desc": "Token de API do Slack exposto. Pode permitir leitura de mensagens e envio em nome do bot.",
    },
    {
        "type": "Discord Webhook",
        "category": "Credencial de Comunicação",
        "severity": "MÉDIA",
        "regex": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        "desc": "URL de webhook do Discord exposta. Permite envio de mensagens em canais do servidor.",
    },
    {
        "type": "Telegram Bot Token",
        "category": "Credencial de Comunicação",
        "severity": "ALTA",
        "regex": r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b",
        "desc": "Token de bot do Telegram exposto.",
    },
    {
        "type": "SendGrid API Key",
        "category": "Credencial de E-mail",
        "severity": "ALTA",
        "regex": r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        "desc": "Chave da API do SendGrid exposta. Permite envio de e-mails em nome da organização.",
    },
    {
        "type": "Mailgun API Key",
        "category": "Credencial de E-mail",
        "severity": "ALTA",
        "regex": r"\bkey-[0-9a-zA-Z]{32}\b",
        "desc": "Chave da API do Mailgun exposta.",
    },
    {
        "type": "OpenAI API Key",
        "category": "Credencial Cloud",
        "severity": "ALTA",
        "regex": r"\bsk-(?!live_|test_)(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b",
        "desc": "Chave de API de modelo de linguagem exposta. Pode gerar custos e vazamento de dados.",
    },
    {
        "type": "npm Token",
        "category": "Credencial de Código",
        "severity": "ALTA",
        "regex": r"\bnpm_[A-Za-z0-9]{36}\b",
        "desc": "Token de publicação do npm exposto.",
    },
    {
        "type": "JWT (JSON Web Token)",
        "category": "Token de Sessão",
        "severity": "MÉDIA",
        "regex": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "desc": "JWT exposto no código. Pode permitir reutilização de sessão ou escalonamento de privilégios.",
    },
    {
        "type": "Chave Privada (PEM)",
        "category": "Criptografia",
        "severity": "ALTA",
        "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "mask": False,
        "desc": "Bloco de chave privada exposto no código-fonte. Compromete toda a criptografia associada.",
    },
    {
        "type": "Credenciais em URL de Conexão",
        "category": "Banco de Dados",
        "severity": "ALTA",
        "regex": r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^:\s/'\"]+:[^@\s/'\"]+@[^\s'\"]+",
        "desc": "String de conexão com usuário e senha embutida no código.",
    },
    {
        "type": "Basic Auth em URL",
        "category": "Credencial",
        "severity": "MÉDIA",
        "regex": r"\bhttps?://[^/\s:@'\"]+:[^/\s@'\"]+@[^\s/'\"]+",
        "desc": "Usuário e senha enviados diretamente na URL (Basic Auth), com risco de vazamento em logs.",
    },
    {
        "type": "Azure Storage Account Key",
        "category": "Credencial Cloud",
        "severity": "ALTA",
        "regex": r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{40,})",
        "group": 1,
        "desc": "Chave de conta do Azure Storage exposta em string de conexão.",
    },
    {
        "type": "Chave de API Genérica",
        "category": "Credencial Genérica",
        "severity": "MÉDIA",
        "regex": r"(?i)\b(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret)\b\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]",
        "group": 1,
        "desc": "Atribuição de chave/token com valor aparentemente real no código-fonte.",
    },
    {
        "type": "Senha Hardcoded",
        "category": "Credencial Genérica",
        "severity": "MÉDIA",
        "regex": r"(?i)\b(?:password|passwd|pwd|senha)\b\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]",
        "group": 1,
        "desc": "Senha embutida diretamente no código-fonte, sem uso de variável de ambiente.",
    },
]


def mask_secret(value):
    """Mascara o valor para exibição segura, mantendo apenas início e fim."""
    value = str(value).strip()
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:4] + "***" + value[-4:]


def _build_finding(meta, value):
    """Cria o dicionário de achado, mascarando o segredo quando necessário."""
    if meta.get("mask", True):
        sample = mask_secret(value)
    else:
        sample = value
    return {
        "type": meta["type"],
        "category": meta["category"],
        "severity": meta["severity"],
        "sample": sample,
        "desc": meta["desc"],
    }


def _scan_text(text, source, seen, findings):
    """Aplica todas as regras a um conteúdo e acumula achados únicos."""
    if not text:
        return
    per_type = {}
    for meta in SECRET_PATTERNS:
        for match in re.finditer(meta["regex"], text):
            value = match.group(meta.get("group", 0))
            key = (meta["type"], value)
            if key in seen:
                continue
            if per_type.get(meta["type"], 0) >= MAX_PER_TYPE:
                break
            seen.add(key)
            per_type[meta["type"]] = per_type.get(meta["type"], 0) + 1
            finding = _build_finding(meta, value)
            finding["source"] = source
            findings.append(finding)
            if len(findings) >= MAX_FINDINGS:
                return


def _extract_script_urls(html_content, base_url):
    """Extrai URLs de scripts do mesmo domínio do alvo."""
    if not html_content or not base_url:
        return []

    base_parsed = urllib.parse.urlparse(base_url)
    urls = []
    pattern = re.compile(r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
    for match in pattern.finditer(html_content):
        raw = match.group(1).strip()
        absolute = urllib.parse.urljoin(base_url, raw)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        # Somente same-origin: evita requisições a terceiros e falsos positivos de CDNs
        if parsed.hostname != base_parsed.hostname:
            continue
        if absolute not in urls:
            urls.append(absolute)
        if len(urls) >= MAX_SCRIPTS:
            break
    return urls


def _download_script(url):
    """Baixa o conteúdo de um script, respeitando o limite de tamanho."""
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            stream=True,
        )
        if resp.status_code != 200:
            return ""
        content = resp.raw.read(MAX_SCRIPT_BYTES + 1, decode_content=True)
        if not content or len(content) > MAX_SCRIPT_BYTES:
            return ""
        return content.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def scan_secrets(html_content, base_url=None, scan_external_scripts=True):
    """
    Procura segredos (chaves de API, tokens, senhas, chaves privadas) no HTML
    da página e, opcionalmente, nos scripts JavaScript do mesmo domínio.
    Os valores são devolvidos mascarados para exibição segura.
    """
    findings = []
    seen = set()

    _scan_text(html_content, base_url or "HTML da página", seen, findings)
    if len(findings) >= MAX_FINDINGS:
        return findings

    if scan_external_scripts and html_content and base_url:
        script_urls = _extract_script_urls(html_content, base_url)
        if script_urls:
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                contents = list(executor.map(_download_script, script_urls))
            for url, content in zip(script_urls, contents):
                _scan_text(content, url, seen, findings)
                if len(findings) >= MAX_FINDINGS:
                    break

    return findings
