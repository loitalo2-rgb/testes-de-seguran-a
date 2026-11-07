import base64
from types import SimpleNamespace

import auditor_injecao_avancada as mod
from auditor_injecao_avancada import (
    _build_get_url,
    _send,
    _test_task,
    extract_parameters,
    run_advanced_injection,
)

PARAM = {"url": "http://alvo.local/item", "method": "GET", "name": "id", "location": "URL"}


def test_extrai_parametros_da_url():
    params = extract_parameters("http://alvo.local/item?id=1&nome=abc")
    assert [p["name"] for p in params] == ["id", "nome"]
    assert all(p["method"] == "GET" for p in params)


def test_extrai_parametros_de_formulario():
    html = """
      <form action="/login" method="POST">
        <input name="usuario">
        <input type="password" name="senha">
      </form>
      <form action="/busca">
        <input name="termo">
      </form>
    """
    params = extract_parameters("http://alvo.local/", html)
    nomes = [(p["method"], p["name"]) for p in params]
    assert ("POST", "usuario") in nomes
    assert ("POST", "senha") in nomes
    assert ("GET", "termo") in nomes
    assert all(p["url"].startswith("http://alvo.local/") for p in params)


def test_fallback_quando_nao_ha_parametros():
    params = extract_parameters("http://alvo.local/")
    assert params == [{"url": "http://alvo.local/", "method": "GET", "name": "q", "location": "Fallback"}]


def test_build_get_url_substitui_parametro():
    url = _build_get_url("http://alvo.local/item?id=1&lang=pt", "id", "{{7*7}}")
    assert "id=%7B%7B7%2A7%7D%7D" in url
    assert "lang=pt" in url


def test_ssti_confirmado(monkeypatch):
    monkeypatch.setattr(mod, "_send", lambda p, pl: ("http://alvo.local/?id=x", "Resultado: 1000000"))
    f = _test_task(PARAM, "SSTI", "Jinja2/Twig", "{{1000*1000}}", 1000000)
    assert f is not None
    assert f["type"] == "SSTI"
    assert f["severity"] == "ALTA"


def test_ssti_refletido_nao_gera_falso_positivo(monkeypatch):
    payload = "{{1000*1000}}"
    monkeypatch.setattr(mod, "_send", lambda p, pl: ("http://alvo.local/?id=" + pl, "Eco: " + payload))
    assert _test_task(PARAM, "SSTI", "Jinja2/Twig", payload, 1000000) is None


def test_lfi_confirmado(monkeypatch):
    monkeypatch.setattr(mod, "_send", lambda p, pl: ("http://alvo.local/?id=" + pl, "root:x:0:0:root:/root:/bin/bash"))
    f = _test_task(PARAM, "LFI", "Linux /etc/passwd", "../../../../etc/passwd", ["root:x:0:0"])
    assert f is not None
    assert f["type"] == "LFI"


def test_lfi_refletido_nao_gera_falso_positivo(monkeypatch):
    payload = "../../../../etc/passwd"
    monkeypatch.setattr(mod, "_send", lambda p, pl: ("http://alvo.local/?id=" + pl, "Eco: " + payload))
    assert _test_task(PARAM, "LFI", "Linux /etc/passwd", payload, ["root:x:0:0"]) is None


def test_php_filter_confirmado(monkeypatch):
    conteudo = "<?php " + "A" * 120 + " ?>"
    blob = base64.b64encode(conteudo.encode()).decode()
    monkeypatch.setattr(mod, "_send", lambda p, pl: ("http://alvo.local/?id=x", blob))
    f = _test_task(PARAM, "LFI", "PHP filter (base64)", "php://filter/convert.base64-encode/resource=index.php", None)
    assert f is not None
    assert f["type"] == "LFI"


def test_command_injection_confirmado(monkeypatch):
    monkeypatch.setattr(mod, "_send", lambda p, pl: ("http://alvo.local/?id=x", "saida: qaMARKER123"))
    f = _test_task(PARAM, "CMD", "ponto e vírgula", ";echo qaMARKER123", "qaMARKER123")
    assert f is not None
    assert f["type"] == "CMD"


def test_command_injection_refletido_nao_gera_falso_positivo(monkeypatch):
    payload = ";echo qaMARKER123"
    monkeypatch.setattr(mod, "_send", lambda p, pl: ("http://alvo.local/?id=" + pl, "Eco: " + payload))
    assert _test_task(PARAM, "CMD", "ponto e vírgula", payload, "qaMARKER123") is None


def test_executa_bateria_completa(monkeypatch):
    monkeypatch.setattr(mod.random, "randint", lambda a, b: 1000)
    monkeypatch.setattr(mod, "_rand_marker", lambda: "qaFIXO123")

    def fake_send(param, payload):
        if "{{" in payload or "${" in payload or "#{" in payload or "<%=" in payload:
            return "http://alvo.local/?id=x", "valor 1000000"
        return "http://alvo.local/?id=x", "ok"

    monkeypatch.setattr(mod, "_send", fake_send)
    resultado = run_advanced_injection("http://alvo.local/item?id=1")
    assert resultado["tested"] == 13
    assert resultado["parameters"] == ["GET id"]
    assert any(f["type"] == "SSTI" for f in resultado["findings"])
    # Cada payload SSTI confirmado deve aparecer apenas uma vez
    ssti = [f for f in resultado["findings"] if f["type"] == "SSTI"]
    assert len(ssti) == 4


def test_send_post_e_get(monkeypatch):
    chamadas = {}

    def fake_post(url, data=None, **kwargs):
        chamadas["post"] = (url, data)
        return SimpleNamespace(text="resposta")

    def fake_get(url, **kwargs):
        chamadas["get"] = url
        return SimpleNamespace(text="resposta")

    monkeypatch.setattr(mod.requests, "post", fake_post)
    monkeypatch.setattr(mod.requests, "get", fake_get)

    post_param = {"url": "http://alvo.local/login", "method": "POST", "name": "user", "location": "Formulário"}
    assert _send(post_param, "teste") == ("http://alvo.local/login", "resposta")
    assert chamadas["post"] == ("http://alvo.local/login", {"user": "teste"})

    assert _send(PARAM, "abc")[0].endswith("id=abc")
    assert "id=abc" in chamadas["get"]
