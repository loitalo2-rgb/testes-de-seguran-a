from types import SimpleNamespace

import auditor_secrets
from auditor_secrets import (
    _extract_script_urls,
    mask_secret,
    scan_secrets,
)


def test_mask_secret_nao_expoe_valor_completo():
    valor = "AKIAIOSFODNN7EXAMPLE"
    mascarado = mask_secret(valor)
    assert valor not in mascarado
    assert mascarado.startswith("AKIA")
    assert mascarado.endswith("MPLE")


def test_detecta_aws_access_key():
    findings = scan_secrets("<script>const k = 'AKIAIOSFODNN7EXAMPLE';</script>", scan_external_scripts=False)
    aws = [f for f in findings if f["type"] == "AWS Access Key ID"]
    assert len(aws) == 1
    assert aws[0]["severity"] == "ALTA"
    assert "AKIAIOSFODNN7EXAMPLE" not in aws[0]["sample"]


def test_detecta_github_google_e_stripe():
    token_github = "ghp_" + "a" * 36
    chave_google = "AIza" + "b" * 35
    chave_stripe = "sk_live_" + "c" * 24
    html = f"<p>{token_github} {chave_google} {chave_stripe}</p>"
    tipos = {f["type"] for f in scan_secrets(html, scan_external_scripts=False)}
    assert "GitHub Token" in tipos
    assert "Google API Key" in tipos
    assert "Stripe Secret Key" in tipos


def test_detecta_chave_privada_sem_mascarar_cabecalho():
    html = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
    findings = scan_secrets(html, scan_external_scripts=False)
    pem = [f for f in findings if f["type"] == "Chave Privada (PEM)"]
    assert len(pem) == 1
    assert "BEGIN RSA PRIVATE KEY" in pem[0]["sample"]


def test_detecta_jwt_e_string_de_conexao():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
    conexao = "mongodb://admin:SenhaForte123@db.exemplo.com:27017/app"
    tipos = {f["type"] for f in scan_secrets(f"{jwt}\n{conexao}", scan_external_scripts=False)}
    assert "JWT (JSON Web Token)" in tipos
    assert "Credenciais em URL de Conexão" in tipos


def test_detecta_senha_hardcoded():
    html = 'const config = { password: "SuperSecret123" };'
    findings = scan_secrets(html, scan_external_scripts=False)
    senhas = [f for f in findings if f["type"] == "Senha Hardcoded"]
    assert len(senhas) == 1
    assert "SuperSecret123" not in senhas[0]["sample"]


def test_deduplica_mesmo_segredo():
    html = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE"
    findings = scan_secrets(html, scan_external_scripts=False)
    aws = [f for f in findings if f["type"] == "AWS Access Key ID"]
    assert len(aws) == 1


def test_texto_normal_nao_gera_falso_positivo():
    html = "<html><body>Bem-vindo ao nosso site. Entre em contato pelo formulário.</body></html>"
    assert scan_secrets(html, scan_external_scripts=False) == []
    assert scan_secrets("", scan_external_scripts=False) == []
    assert scan_secrets(None, scan_external_scripts=False) == []


def test_extrai_apenas_scripts_do_mesmo_dominio():
    html = """
      <script src="/app.js"></script>
      <script src="https://example.com/static/bundle.js"></script>
      <script src="https://cdn.terceiros.com/lib.js"></script>
    """
    urls = _extract_script_urls(html, "https://example.com/pagina")
    assert urls == [
        "https://example.com/app.js",
        "https://example.com/static/bundle.js",
    ]


def test_scan_secrets_baixa_script_externo(monkeypatch):
    html = '<script src="/app.js"></script>'
    conteudo_js = 'const token = "ghp_' + "a" * 36 + '";'

    def fake_get(url, **kwargs):
        return SimpleNamespace(
            status_code=200,
            raw=SimpleNamespace(read=lambda *a, **k: conteudo_js.encode()),
        )

    monkeypatch.setattr(auditor_secrets.requests, "get", fake_get)
    findings = scan_secrets(html, "https://example.com")
    github = [f for f in findings if f["type"] == "GitHub Token"]
    assert len(github) == 1
    assert github[0]["source"] == "https://example.com/app.js"
