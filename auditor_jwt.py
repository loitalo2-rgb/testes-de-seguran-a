import base64
import concurrent.futures
import hashlib
import hmac
import json
import re
import time

from auditor_secrets import _download_script, _extract_script_urls, mask_secret

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}")
MAX_TOKENS = 10

# Segredos HMAC comuns usados em tutoriais, exemplos e projetos reais
COMMON_SECRETS = [
    "secret", "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "letmein", "admin", "root", "changeme", "default", "jwt", "jwtsecret",
    "jwt_secret", "jwt-secret", "supersecret", "super_secret", "mysecret",
    "my-secret", "your-256-bit-secret", "your_jwt_secret", "s3cr3t", "secretkey",
    "secret_key", "secret-key", "token", "tokenkey", "api", "apikey", "test",
    "dev", "development", "production", "company", "empresa", "segredo", "senha",
    "chave", "minhachave", "minhasenha", "topsecret", "top-secret", "iloveyou",
    "welcome", "monkey", "dragon", "master", "shadow", "sunshine", "princess",
    "football", "baseball", "access", "login", "passw0rd", "p@ssw0rd", "P@ssw0rd",
    "admin123", "root123", "1234", "0000", "111111", "123123", "qwerty123",
    "zaq12wsx", "trocar", "troque", "exemplo", "example", "demo", "sandbox",
]

HASH_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

SENSITIVE_CLAIM_KEYS = (
    "password", "senha", "passwd", "pwd", "secret", "token", "cpf", "cnpj",
    "email", "telefone", "phone", "celular", "credit", "cartao", "card", "cvv",
)


def _b64url_decode(part):
    padding = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + padding)


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_token(token):
    """Decodifica header e payload de um JWT. Retorna (header, payload) ou (None, None)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None, None
        return header, payload
    except Exception:
        return None, None


def _sign(signing_input, secret, algorithm):
    digest = HASH_ALGS[algorithm]
    return hmac.new(secret.encode(), signing_input.encode(), digest).digest()


def _forge_poc(token, secret=None, algorithm="none"):
    """
    Gera um token de prova de conceito (PoC) a partir do token original,
    alterando apenas uma claim inofensiva. Não eleva privilégios.
    """
    header, payload = _decode_token(token)
    if header is None:
        return None

    forged_header = dict(header)
    forged_header["alg"] = algorithm
    forged_payload = dict(payload)
    forged_payload["poc"] = "jwt-forge-test"

    head_b64 = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    body_b64 = _b64url_encode(json.dumps(forged_payload, separators=(",", ":")).encode())
    signing_input = f"{head_b64}.{body_b64}"

    if algorithm == "none":
        return signing_input + "."

    signature = _sign(signing_input, secret, algorithm)
    return signing_input + "." + _b64url_encode(signature)


def _finding(tipo, categoria, severidade, token, desc, impacto, correcao, source, poc=None):
    item = {
        "type": tipo,
        "category": categoria,
        "severity": severidade,
        "sample": mask_secret(token),
        "desc": desc,
        "impact": impacto,
        "fix": correcao,
        "source": source,
    }
    if poc:
        item["poc"] = poc
    return item


def analyze_jwt(token, source="HTML da página"):
    """Analisa um JWT e devolve as falhas exploráveis encontradas (offline)."""
    header, payload = _decode_token(token)
    if header is None:
        return []

    findings = []
    alg = str(header.get("alg", "")).strip()
    alg_upper = alg.upper()

    # 1. Algoritmo "none" aceito/emitido
    if alg.lower() == "none":
        findings.append(_finding(
            "JWT com algoritmo 'none'", "Autenticação", "ALTA", token,
            "O token declara 'alg: none', ou seja, não possui assinatura válida.",
            "O atacante pode alterar qualquer claim (usuário, role, expiração) e o servidor, se aceitar 'none', confia no token sem validar assinatura — assumindo a identidade de outro usuário.",
            "Rejeitar explicitamente 'alg: none' e fixar os algoritmos aceitos no validador.",
            source, _forge_poc(token, algorithm="none"),
        ))

    # 2. Segredo HMAC fraco (força bruta offline)
    if alg_upper in HASH_ALGS:
        parts = token.split(".")
        signing_input = parts[0] + "." + parts[1]
        try:
            signature = _b64url_decode(parts[2])
        except Exception:
            signature = b""
        for secret in COMMON_SECRETS:
            expected = _sign(signing_input, secret, alg_upper)
            if hmac.compare_digest(expected, signature):
                findings.append(_finding(
                    "Segredo JWT fraco (HMAC)", "Autenticação", "ALTA", token,
                    f"A assinatura {alg_upper} foi quebrada por dicionário. Segredo encontrado: '{secret}'.",
                    "Com o segredo, o atacante forja tokens válidos para qualquer usuário e privilégio, sem precisar de senha.",
                    "Rotacionar o segredo por uma chave aleatória longa (256+ bits) e invalidar todos os tokens emitidos.",
                    source, _forge_poc(token, secret=secret, algorithm=alg_upper),
                ))
                break

    # 3. Chaves públicas controladas pelo atacante (jku/x5u)
    for claim in ("jku", "x5u"):
        if isinstance(header.get(claim), str) and header[claim].strip():
            findings.append(_finding(
                f"JWT com '{claim}' externo", "Autenticação", "MÉDIA", token,
                f"O header aponta para uma chave externa em '{claim}': {header[claim]}",
                "Se o servidor buscar a chave nessa URL, o atacante pode hospedar a própria chave pública e assinar tokens válidos para a aplicação.",
                "Usar chaves embutidas/allowlist de domínios confiáveis e nunca buscar JWKS de URLs controladas pelo token.",
                source,
            ))

    # 4. 'kid' com caracteres de injeção
    kid = header.get("kid")
    if isinstance(kid, str) and re.search(r"(\.\.|/|\\|'|\"|;|\||\x00)", kid):
        findings.append(_finding(
            "'kid' com caracteres suspeitos", "Autenticação", "MÉDIA", token,
            f"O header 'kid' contém caracteres de caminho/injeção: {kid}",
            "O atacante pode apontar o 'kid' para um arquivo do servidor ou injetar SQL, controlando qual chave é usada na validação.",
            "Validar o 'kid' contra uma allowlist de identificadores e nunca usá-lo em caminhos ou consultas diretamente.",
            source,
        ))

    # 5. Expiração
    agora = int(time.time())
    exp = payload.get("exp")
    if exp is None:
        findings.append(_finding(
            "JWT sem expiração (exp)", "Sessão", "BAIXA", token,
            "O token não define a claim 'exp'.",
            "Um token vazado permanece válido indefinidamente, ampliando a janela de uso por um atacante.",
            "Definir expiração curta (ex.: 15–60 min) e implementar refresh token.",
            source,
        ))
    else:
        try:
            exp_int = int(exp)
            if exp_int < agora:
                findings.append(_finding(
                    "JWT expirado aceito/exposto", "Sessão", "BAIXA", token,
                    f"O token expirou em {time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(exp_int))}.",
                    "Se a aplicação ainda aceita tokens expirados, o atacante reutiliza credenciais antigas indefinidamente.",
                    "Validar 'exp' no servidor e rejeitar tokens expirados.",
                    source,
                ))
            elif exp_int - agora > 365 * 24 * 3600:
                findings.append(_finding(
                    "JWT com validade superior a 1 ano", "Sessão", "MÉDIA", token,
                    f"O token é válido até {time.strftime('%d/%m/%Y', time.localtime(exp_int))}.",
                    "Tokens de longa duração aumentam o impacto de vazamentos: uma vez roubado, o atacante mantém acesso por muito tempo.",
                    "Reduzir a validade e usar refresh tokens com revogação.",
                    source,
                ))
        except (TypeError, ValueError, OSError):
            pass

    # 6. Dados pessoais/sensíveis legíveis no payload (JWT não é criptografado)
    expostos = []
    for key, value in payload.items():
        key_lower = str(key).lower()
        if any(s in key_lower for s in SENSITIVE_CLAIM_KEYS) and value:
            expostos.append(f"{key}={str(value)[:40]}")
    if expostos:
        findings.append(_finding(
            "Dados sensíveis no payload do JWT", "Privacidade / LGPD", "MÉDIA", token,
            "Claims legíveis sem criptografia: " + ", ".join(expostos[:5]),
            "Qualquer pessoa com acesso ao token lê esses dados (JWT é apenas Base64, não criptografia), favorecendo vazamento de PII e LGPD.",
            "Não incluir dados pessoais/sensíveis no payload; guardar apenas identificadores opacos.",
            source,
        ))

    return findings


def scan_jwts(html_content, base_url=None, scan_external_scripts=True):
    """
    Encontra JWTs no HTML e nos scripts do mesmo domínio e analisa
    a força da assinatura e das claims (100% offline, sem enviar tokens).
    """
    token_sources = {}
    sources = [(html_content or "", base_url or "HTML da página")]

    if scan_external_scripts and html_content and base_url:
        script_urls = _extract_script_urls(html_content, base_url)[:MAX_TOKENS]
        if script_urls:
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                contents = list(executor.map(_download_script, script_urls))
            sources.extend(zip(contents, script_urls))

    for text, source in sources:
        if not text:
            continue
        for match in JWT_RE.finditer(text):
            token = match.group(0)
            if token not in token_sources:
                token_sources[token] = source
            if len(token_sources) >= MAX_TOKENS:
                break
        if len(token_sources) >= MAX_TOKENS:
            break

    findings = []
    for token, source in token_sources.items():
        findings.extend(analyze_jwt(token, source=source))
    return findings
