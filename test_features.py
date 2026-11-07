import json
from unittest.mock import MagicMock, patch
import pytest

from app_server import build_auth_config
from notificador_webhook import format_discord_payload, format_slack_payload, send_scan_webhook
from relatorio_executivo import generate_executive_html


def test_build_auth_config_bearer():
    headers, cookies = build_auth_config("bearer", "Bearer my-jwt-token-123")
    assert headers.get("Authorization") == "Bearer my-jwt-token-123"
    assert cookies == {}

    # Sem prefixo 'Bearer '
    headers2, _ = build_auth_config("bearer", "my-jwt-token-456")
    assert headers2.get("Authorization") == "Bearer my-jwt-token-456"


def test_build_auth_config_cookie():
    cookie_str = "PHPSESSID=s3ss10n; auth_token=token999; theme=dark"
    headers, cookies = build_auth_config("cookie", cookie_str)
    assert headers.get("Cookie") == cookie_str
    assert cookies["PHPSESSID"] == "s3ss10n"
    assert cookies["auth_token"] == "token999"
    assert cookies["theme"] == "dark"


def test_build_auth_config_custom_and_empty():
    headers, _ = build_auth_config("custom", "X-Custom-Secret: supersecretkey")
    assert headers.get("X-Custom-Secret") == "supersecretkey"

    h_empty, c_empty = build_auth_config("none", "")
    assert h_empty == {}
    assert c_empty == {}


def test_webhook_formatters():
    dummy_scan = {
        "target": "https://example.com/admin",
        "hostname": "example.com",
        "score": 30,
        "criticos": 3,
        "medios": 5,
        "resumo_risco": {
            "veredito": "RISCO CRÍTICO",
            "itens": [
                {"severidade": "ALTO", "titulo": "Chave AWS Exposta"},
                {"severidade": "ALTO", "titulo": "SSTI Confirmado"},
            ],
        },
    }

    discord_p = format_discord_payload(dummy_scan)
    assert "embeds" in discord_p
    embed = discord_p["embeds"][0]
    assert embed["color"] == 0xEF4444  # score < 40 = vermelho
    assert "example.com" in embed["title"]
    assert any("Chave AWS Exposta" in f["value"] for f in embed["fields"] if f["name"] == "Top Achados Prioritários")

    slack_p = format_slack_payload(dummy_scan)
    assert "blocks" in slack_p
    assert any("🔴" in b["text"]["text"] for b in slack_p["blocks"] if b.get("text"))


def test_send_scan_webhook_mocked():
    dummy_scan = {
        "target": "https://test.com",
        "hostname": "test.com",
        "score": 90,
        "criticos": 0,
        "medios": 1,
    }

    # URL vazia
    res_empty = send_scan_webhook("", dummy_scan)
    assert res_empty["success"] is False

    # Mock de envio com sucesso
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_post.return_value = mock_resp

        res = send_scan_webhook("https://discord.com/api/webhooks/123/xyz", dummy_scan)
        assert res["success"] is True
        assert res["status_code"] == 204


def test_generate_executive_html():
    scan_data = {
        "target": "https://portal.empresa.com.br",
        "hostname": "portal.empresa.com.br",
        "score": 35,
        "criticos": 2,
        "medios": 4,
        "data_scan": "07/11/2026 às 00:00",
        "resumo_risco": {
            "veredito": "RISCO CRÍTICO",
            "itens": [
                {
                    "severidade": "ALTO",
                    "titulo": "Arquivo .env com Credenciais de Banco Exposto",
                    "como_atacam": "Atacante baixa o .env e obtém senha de banco de dados de produção.",
                    "como_corrigir": "Bloquear acesso a arquivos ocultos (.env) no nginx/apache.",
                }
            ],
        },
        "ssl": {"cipher": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "days_left": 90},
        "pii": [{"type": "CPF", "value": "123.***.***-00"}],
        "secrets": [{"type": "AWS", "secret": "AKIA***"}],
        "ports": [80, 443],
    }

    html_out = generate_executive_html(scan_data)
    assert "<!DOCTYPE html>" in html_out
    assert "portal.empresa.com.br" in html_out
    assert "Arquivo .env com Credenciais" in html_out
    assert "RISCO CRÍTICO" in html_out
    assert "TLS_AES_256_GCM_SHA384" in html_out
    assert "35" in html_out
    assert "@media print" in html_out
