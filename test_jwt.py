import base64
import hashlib
import hmac
import json
import time

from auditor_jwt import analyze_jwt, scan_jwts


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(header, payload, secret=None):
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}"
    if secret is None:
        return signing_input + "."
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + _b64(signature)


def base_payload(**extra):
    payload = {"sub": "1234567890", "name": "Usuario", "exp": int(time.time()) + 3600}
    payload.update(extra)
    return payload


def test_detecta_segredo_hmac_fraco_com_poc():
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, base_payload(), secret="secret")
    findings = analyze_jwt(token)
    fracos = [f for f in findings if f["type"] == "Segredo JWT fraco (HMAC)"]
    assert len(fracos) == 1
    assert fracos[0]["severity"] == "ALTA"
    assert fracos[0]["poc"]
    assert "secret" in fracos[0]["desc"]


def test_segredo_forte_nao_e_quebrado():
    token = make_jwt({"alg": "HS256"}, base_payload(), secret="x" * 64)
    findings = analyze_jwt(token)
    assert not [f for f in findings if "Segredo JWT fraco" in f["type"]]


def test_detecta_algoritmo_none_e_gera_poc():
    token = make_jwt({"alg": "none", "typ": "JWT"}, base_payload())
    findings = analyze_jwt(token)
    none = [f for f in findings if "algoritmo 'none'" in f["type"]]
    assert len(none) == 1
    assert none[0]["severity"] == "ALTA"
    assert none[0]["poc"].endswith(".")


def test_detecta_jku_externo():
    token = make_jwt({"alg": "RS256", "jku": "https://evil.example/jwks.json"}, base_payload())
    tipos = {f["type"] for f in analyze_jwt(token)}
    assert "JWT com 'jku' externo" in tipos


def test_detecta_kid_com_path_traversal():
    token = make_jwt({"alg": "RS256", "kid": "../../etc/passwd"}, base_payload())
    tipos = {f["type"] for f in analyze_jwt(token)}
    assert "'kid' com caracteres suspeitos" in tipos


def test_detecta_dados_sensiveis_no_payload():
    token = make_jwt({"alg": "HS256"}, base_payload(email="cliente@exemplo.com", cpf="52998224725"), secret="x" * 64)
    priv = [f for f in analyze_jwt(token) if f["type"] == "Dados sensíveis no payload do JWT"]
    assert len(priv) == 1
    assert priv[0]["severity"] == "MÉDIA"


def test_detecta_jwt_expirado_e_sem_expiracao():
    expirado = make_jwt({"alg": "HS256"}, {"sub": "1", "exp": int(time.time()) - 60}, secret="x" * 64)
    sem_exp = make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="x" * 64)
    tipos_exp = {f["type"] for f in analyze_jwt(expirado)}
    tipos_sem = {f["type"] for f in analyze_jwt(sem_exp)}
    assert "JWT expirado aceito/exposto" in tipos_exp
    assert "JWT sem expiração (exp)" in tipos_sem


def test_detecta_validade_longa():
    token = make_jwt({"alg": "HS256"}, {"sub": "1", "exp": int(time.time()) + 900 * 24 * 3600}, secret="x" * 64)
    tipos = {f["type"] for f in analyze_jwt(token)}
    assert "JWT com validade superior a 1 ano" in tipos


def test_token_malformado_e_ignorado():
    assert analyze_jwt("abc.def.ghi") == []
    assert analyze_jwt("") == []


def test_scan_jwts_encontra_token_no_html():
    token = make_jwt({"alg": "HS256"}, base_payload(), secret="secret")
    findings = scan_jwts(f"<script>const t = '{token}';</script>", scan_external_scripts=False)
    assert any(f["type"] == "Segredo JWT fraco (HMAC)" for f in findings)


def test_scan_jwts_deduplica_token_repetido():
    token = make_jwt({"alg": "none"}, base_payload())
    findings = scan_jwts(f"{token} {token}", scan_external_scripts=False)
    none = [f for f in findings if "algoritmo 'none'" in f["type"]]
    assert len(none) == 1
