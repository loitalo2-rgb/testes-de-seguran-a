"""notificador_webhook.py - Notificações de auditoria para Discord, Slack e Webhooks genéricos.

Formata e envia mensagens enriquecidas (embeds/blocks) com nota de segurança,
contagem de falhas críticas/médias e veredito do scan.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional
import requests

logger = logging.getLogger("notificador_webhook")


def format_discord_payload(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    score = scan_data.get("score", 0)
    hostname = scan_data.get("hostname", "alvo")
    target = scan_data.get("target", hostname)
    criticos = scan_data.get("criticos", 0)
    medios = scan_data.get("medios", 0)
    veredito = scan_data.get("resumo_risco", {}).get("veredito", "AVALIADO")

    # Cor baseada no score (Verde >= 70, Laranja >= 40, Vermelho < 40)
    color = 0x10B981 if score >= 70 else (0xF59E0B if score >= 40 else 0xEF4444)

    embed = {
        "title": f"🛡️ Relatório de Segurança: {hostname}",
        "url": target,
        "description": f"Auditoria concluída com veredito: **{veredito}**\nScore de Postura: **{score}/100**",
        "color": color,
        "fields": [
            {"name": "🚨 Falhas Críticas / Altas", "value": str(criticos), "inline": True},
            {"name": "⚠️ Alertas Médios", "value": str(medios), "inline": True},
            {"name": "🎯 Alvo", "value": target, "inline": False},
        ],
        "footer": {"text": "Security Suite Pro • Auditoria DAST Automatizada"},
    }

    # Adicionar resumo dos principais achados graves
    itens = scan_data.get("resumo_risco", {}).get("itens", [])
    if itens:
        top_achados = "\n".join([f"• [{it.get('severidade', 'INFO')}] {it.get('titulo', '')}" for it in itens[:4]])
        embed["fields"].append({"name": "Top Achados Prioritários", "value": top_achados[:1000], "inline": False})

    return {"username": "Security Suite Auditor", "embeds": [embed]}


def format_slack_payload(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    score = scan_data.get("score", 0)
    hostname = scan_data.get("hostname", "alvo")
    target = scan_data.get("target", hostname)
    criticos = scan_data.get("criticos", 0)
    medios = scan_data.get("medios", 0)
    veredito = scan_data.get("resumo_risco", {}).get("veredito", "AVALIADO")

    status_icon = "🟢" if score >= 70 else ("🟠" if score >= 40 else "🔴")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🛡️ Auditoria de Segurança: {hostname}"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{status_icon} *Alvo:* <{target}|{target}>\n*Score:* `{score}/100` | *Veredito:* *{veredito}*\n*Críticos:* `{criticos}` | *Médios:* `{medios}`",
            },
        },
        {"type": "divider"},
    ]

    return {"blocks": blocks}


def send_scan_webhook(webhook_url: str, scan_data: Dict[str, Any], timeout: int = 8) -> Dict[str, Any]:
    """Envia os resultados de segurança para a URL de webhook configurada."""
    url = (webhook_url or "").strip()
    if not url:
        return {"success": False, "message": "URL de webhook não informada."}

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Detecta tipo de serviço
    if "discord.com/api/webhooks" in url:
        payload = format_discord_payload(scan_data)
    elif "hooks.slack.com" in url:
        payload = format_slack_payload(scan_data)
    else:
        # Webhook genérico padrão JSON
        payload = {
            "event": "security_scan_completed",
            "hostname": scan_data.get("hostname"),
            "target": scan_data.get("target"),
            "score": scan_data.get("score"),
            "criticos": scan_data.get("criticos"),
            "medios": scan_data.get("medios"),
            "resumo": scan_data.get("resumo_risco"),
        }

    try:
        resp = requests.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json", "User-Agent": "SecuritySuite-Webhook/1.0"},
            timeout=timeout,
        )
        if 200 <= resp.status_code < 300:
            return {"success": True, "status_code": resp.status_code, "message": "Notificação enviada com sucesso!"}
        else:
            return {
                "success": False,
                "status_code": resp.status_code,
                "message": f"Servidor remoto respondeu com status {resp.status_code}: {resp.text[:120]}",
            }
    except Exception as exc:
        return {"success": False, "message": f"Falha ao enviar webhook: {exc}"}
