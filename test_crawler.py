import auditor_crawler as mod
from auditor_crawler import (
    crawl_site,
    crawl_summary,
    extract_links,
    is_crawlable,
    is_same_origin,
    normalize_url,
)


class FakeResponse:
    def __init__(self, url, text="", status=200, content_type="text/html; charset=utf-8"):
        self.url = url
        self.text = text
        self.status_code = status
        self.headers = {"Content-Type": content_type}


def test_normaliza_url_remove_fragmento():
    assert normalize_url("HTTP://Alvo.local/a?x=1#topo") == "http://alvo.local/a?x=1"


def test_same_origin_respeita_porta_e_host():
    assert is_same_origin("http://alvo.local/a", "http://alvo.local/")
    assert is_same_origin("https://alvo.local:443/a", "https://alvo.local/")
    assert not is_same_origin("http://alvo.local:8080/a", "http://alvo.local/")
    assert not is_same_origin("http://outro.local/a", "http://alvo.local/")


def test_is_crawlable_ignora_assets_e_acoes_destrutivas():
    base = "http://alvo.local/"
    assert is_crawlable(base + "sobre")
    assert not is_crawlable(base + "logo.png")
    assert not is_crawlable(base + "app.js")
    assert not is_crawlable(base + "manual.pdf")
    assert not is_crawlable(base + "logout")
    assert not is_crawlable("mailto:contato@alvo.local")


def test_extrai_links_e_actions_do_mesmo_dominio():
    html = """
      <a href="/sobre">Sobre</a>
      <a href="contato?x=1#frag">Contato</a>
      <a href="https://externo.local/x">Externo</a>
      <a href="mailto:a@b.c">Email</a>
      <a href="/logo.png">Logo</a>
      <form action="/enviar" method="post"></form>
    """
    links = extract_links("http://alvo.local/", html)
    assert "http://alvo.local/sobre" in links
    assert "http://alvo.local/contato?x=1" in links
    assert "http://alvo.local/enviar" in links
    assert all("externo.local" not in link for link in links)
    assert all(not link.endswith(".png") for link in links)


def test_crawl_percorre_mesmo_dominio_respeitando_profundidade(monkeypatch):
    paginas = {
        "http://alvo.local/a": '<html><title>A</title><a href="/d">d</a></html>',
        "http://alvo.local/b": '<html><title>B</title><a href="/">home</a></html>',
        "http://alvo.local/c": "<html><title>C</title><form action='/enviar'></form></html>",
    }
    chamadas = []

    def fake_get(url, **kwargs):
        chamadas.append(url)
        return FakeResponse(url, paginas.get(url, ""))

    monkeypatch.setattr(mod.requests, "get", fake_get)

    html_inicial = """
      <html><title>Home</title>
        <a href="/a">A</a>
        <a href="/b">B</a>
        <a href="/a#topo">A repetido</a>
        <a href="https://externo.local/x">Externo</a>
        <form action="/c"></form>
      </html>
    """
    resultado = crawl_site(
        "http://alvo.local/", max_pages=10, max_depth=1,
        respect_robots=False, seed_html=html_inicial,
    )

    urls = [p["url"] for p in resultado["pages"]]
    assert urls[0] == "http://alvo.local/"
    assert urls.count("http://alvo.local/a") == 1
    assert set(urls) == {
        "http://alvo.local/", "http://alvo.local/a", "http://alvo.local/b", "http://alvo.local/c",
    }
    # /d está no nível 2 e não deve ser visitado com max_depth=1
    assert "http://alvo.local/d" not in urls
    assert resultado["total"] == 4
    assert resultado["pages"][0]["title"] == "Home"
    assert resultado["pages"][0]["forms"] == 1
    assert not any("externo.local" in url for url in chamadas)


def test_crawl_limita_paginas_e_marca_truncado(monkeypatch):
    html = "".join(f'<a href="/p{i}">P</a>' for i in range(6))

    def fake_get(url, **kwargs):
        return FakeResponse(url, '<html><a href="/proxima">x</a></html>')

    monkeypatch.setattr(mod.requests, "get", fake_get)
    resultado = crawl_site(
        "http://alvo.local/", max_pages=3, max_depth=2,
        respect_robots=False, seed_html=html,
    )
    assert resultado["total"] == 3
    assert resultado["truncated"] is True


def test_crawl_registra_erro_http_sem_quebrar(monkeypatch):
    def fake_get(url, **kwargs):
        if url.endswith("/erro"):
            return FakeResponse(url, "<html>not found</html>", status=404)
        return FakeResponse(url, "")

    monkeypatch.setattr(mod.requests, "get", fake_get)
    resultado = crawl_site(
        "http://alvo.local/", max_pages=5, max_depth=1,
        respect_robots=False, seed_html='<a href="/erro">erro</a>',
    )
    assert any(p["url"].endswith("/erro") and p["status"] == 404 for p in resultado["pages"])


def test_crawl_ignora_resposta_que_nao_e_html(monkeypatch):
    def fake_get(url, **kwargs):
        return FakeResponse(url, "{}", content_type="application/json")

    monkeypatch.setattr(mod.requests, "get", fake_get)
    resultado = crawl_site(
        "http://alvo.local/", max_pages=5, max_depth=1,
        respect_robots=False, seed_html='<a href="/api/dados">dados</a>',
    )
    assert resultado["total"] == 1
    assert "html" in resultado["pages"][0]


def test_crawl_respeita_robots(monkeypatch):
    class RoboBloqueia:
        def can_fetch(self, ua, url):
            return False

    monkeypatch.setattr(mod, "_load_robots", lambda base, timeout: RoboBloqueia())
    resultado = crawl_site(
        "http://alvo.local/", max_pages=5, max_depth=1,
        seed_html='<a href="/privado">x</a>',
    )
    assert resultado["total"] == 1
    assert resultado["errors"][0]["error"] == "bloqueado por robots.txt"


def test_resumo_nao_expoe_html():
    resumo = crawl_summary({
        "start_url": "http://alvo.local/",
        "total": 1,
        "truncated": False,
        "errors": [],
        "pages": [{
            "url": "http://alvo.local/", "status": 200, "depth": 0,
            "title": "Home", "html": "<html>segredo</html>", "forms": 0, "links": 2,
        }],
    })
    assert "html" not in resumo["pages"][0]
    assert resumo["pages"][0]["links"] == 2
