"""relatorio_executivo.py - Gerador de Relatório Executivo e Técnico de Auditoria de Segurança.

Gera documento HTML executivo estilizado com capa corporativa, resumo gerencial,
matriz de severidade, conformidade LGPD/OWASP e plano de remediação.
Otimizado para exportação direta em PDF via navegador (Ctrl+P / Salvar como PDF).
"""

from __future__ import annotations

import html
import json
import time
from typing import Any, Dict, List


def escape_txt(val: Any) -> str:
    return html.escape(str(val or ""))


def generate_executive_html(scan_data: Dict[str, Any]) -> str:
    target = scan_data.get("target", "Alvo")
    hostname = scan_data.get("hostname", "alvo.com")
    score = scan_data.get("score", 0)
    criticos = scan_data.get("criticos", 0)
    medios = scan_data.get("medios", 0)
    data_scan = scan_data.get("data_scan", time.strftime("%d/%m/%Y às %H:%M"))
    resumo_risco = scan_data.get("resumo_risco", {})
    veredito = resumo_risco.get("veredito", "AVALIADO")
    itens_risco = resumo_risco.get("itens", [])

    # Cores de postura
    if score >= 70:
        cor_score = "#10B981"
        badge_bg = "#ECFDF5"
        badge_border = "#A7F3D0"
        badge_text = "#065F46"
        resumo_gerencial = (
            "A aplicação apresenta uma postura defensiva adequada nos testes automatizados, com boas práticas "
            "de criptografia e proteção de infraestrutura. Recomenda-se a revisão periódica e atenção aos alertas médios e informativos."
        )
    elif score >= 40:
        cor_score = "#F59E0B"
        badge_bg = "#FFFBEB"
        badge_border = "#FDE68A"
        badge_text = "#92400E"
        resumo_gerencial = (
            "Foram detectadas vulnerabilidades e fragilidades de configuração moderadas que facilitam ataques de enumeração, "
            "vazamento de informações ou comprometimento de integridade. Ações de remediação a médio prazo são fortemente recomendadas."
        )
    else:
        cor_score = "#EF4444"
        badge_bg = "#FEF2F2"
        badge_border = "#FECACA"
        badge_text = "#991B1B"
        resumo_gerencial = (
            "Atenção urgente necessária: foram identificadas falhas de impacto crítico ou alto (exposição de credenciais, "
            "dados pessoais regulados pela LGPD, arquivos confidenciais ou pontos de injeção). Atacantes podem explorar estas fraquezas "
            "para exfiltração de dados ou comprometimento da aplicação."
        )

    # Detalhes técnicos
    headers_info = scan_data.get("headers", {})
    ssl_info = scan_data.get("ssl", {})
    ports_info = scan_data.get("ports", [])
    secrets_info = scan_data.get("secrets", {})
    pii_info = scan_data.get("pii", {})

    linhas_tabela_risco = ""
    if itens_risco:
        for idx, it in enumerate(itens_risco, 1):
            sev = it.get("severidade", "MÉDIO")
            sev_color = "#DC2626" if sev == "ALTO" else ("#D97706" if sev == "MÉDIO" else "#2563EB")
            linhas_tabela_risco += f"""
            <tr style="border-bottom: 1px solid #E5E7EB;">
                <td style="padding: 12px; font-weight: bold; color: {sev_color};">{escape_txt(sev)}</td>
                <td style="padding: 12px; font-weight: 600; color: #111827;">{escape_txt(it.get('titulo', ''))}</td>
                <td style="padding: 12px; color: #4B5563; font-size: 13px;">{escape_txt(it.get('como_atacam', ''))}</td>
                <td style="padding: 12px; color: #065F46; font-size: 13px; background-color: #F0FDF4;">{escape_txt(it.get('como_corrigir', ''))}</td>
            </tr>
            """
    else:
        linhas_tabela_risco = """
        <tr>
            <td colspan="4" style="padding: 16px; text-align: center; color: #10B981; font-weight: 500;">
                ✓ Nenhuma vulnerabilidade de alta ou média severidade confirmada nos testes automáticos.
            </td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório Executivo de Segurança - {escape_txt(hostname)}</title>
    <style>
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            margin: 0;
            padding: 0;
            color: #1F2937;
            background-color: #F9FAFB;
            line-height: 1.5;
        }}
        .container {{
            max-width: 900px;
            margin: 30px auto;
            background: #FFFFFF;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        @media print {{
            body {{ background: #FFFFFF; }}
            .container {{ box-shadow: none; padding: 0; margin: 0; max-width: 100%; }}
            .page-break {{ page-break-before: always; }}
            .no-print {{ display: none; }}
        }}
        .header-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #E5E7EB;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .title {{ font-size: 24px; font-weight: 800; color: #111827; margin: 0; }}
        .subtitle {{ font-size: 14px; color: #6B7280; margin-top: 4px; }}
        .badge {{
            display: inline-block;
            padding: 6px 14px;
            font-weight: 700;
            font-size: 13px;
            border-radius: 9999px;
            background: {badge_bg};
            color: {badge_text};
            border: 1px solid {badge_border};
        }}
        .grid-cards {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin: 25px 0;
        }}
        .card {{
            background: #F9FAFB;
            border: 1px solid #E5E7EB;
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .card-val {{ font-size: 32px; font-weight: 800; margin: 4px 0; }}
        .card-lbl {{ font-size: 12px; font-weight: 600; text-transform: uppercase; color: #6B7280; }}
        .section-title {{
            font-size: 18px;
            font-weight: 700;
            color: #111827;
            border-left: 4px solid #4F46E5;
            padding-left: 10px;
            margin: 35px 0 15px 0;
        }}
        .exec-box {{
            background: #EEF2FF;
            border: 1px solid #C7D2FE;
            border-radius: 8px;
            padding: 20px;
            color: #312E81;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }}
        th {{
            background: #F3F4F6;
            text-align: left;
            padding: 12px;
            font-weight: 700;
            color: #374151;
            border-bottom: 2px solid #E5E7EB;
        }}
        .footer {{
            margin-top: 50px;
            border-top: 1px solid #E5E7EB;
            padding-top: 15px;
            font-size: 12px;
            color: #9CA3AF;
            display: flex;
            justify-content: space-between;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Barra de Ações (oculta na impressão) -->
        <div class="no-print" style="margin-bottom: 20px; display: flex; justify-content: flex-end; gap: 10px;">
            <button onclick="window.print()" style="background: #4F46E5; color: white; border: none; padding: 10px 18px; border-radius: 6px; font-weight: 600; cursor: pointer;">
                🖨️ Salvar como PDF / Imprimir
            </button>
        </div>

        <!-- Cabeçalho -->
        <div class="header-bar">
            <div>
                <h1 class="title">Relatório Executivo de Auditoria de Segurança</h1>
                <p class="subtitle">Auditoria DAST e Avaliação de Postura Cibernética</p>
                <p style="font-size: 12px; color: #6B7280; margin-top: 4px;">Alvo: <strong>{escape_txt(target)}</strong> | Data: {escape_txt(data_scan)}</p>
            </div>
            <div>
                <span class="badge">{escape_txt(veredito)}</span>
            </div>
        </div>

        <!-- Cards de Resumo -->
        <div class="grid-cards">
            <div class="card">
                <div class="card-lbl">Score de Postura</div>
                <div class="card-val" style="color: {cor_score};">{score}<span style="font-size: 16px; color: #9CA3AF;">/100</span></div>
            </div>
            <div class="card">
                <div class="card-lbl">Falhas Críticas / Altas</div>
                <div class="card-val" style="color: #DC2626;">{criticos}</div>
            </div>
            <div class="card">
                <div class="card-lbl">Vulnerabilidades Médias</div>
                <div class="card-val" style="color: #D97706;">{medios}</div>
            </div>
        </div>

        <!-- Resumo para Diretoria -->
        <div class="section-title">1. Resumo Gerencial (Diretoria & Gestão)</div>
        <div class="exec-box">
            <p style="margin: 0 0 10px 0; font-weight: 700;">Parecer Técnico Sintético:</p>
            <p style="margin: 0;">{resumo_gerencial}</p>
        </div>

        <!-- Matriz de Vulnerabilidades e Plano de Ação -->
        <div class="section-title">2. Matriz de Riscos e Recomendações Priorizadas</div>
        <table>
            <thead>
                <tr>
                    <th style="width: 12%;">Severidade</th>
                    <th style="width: 28%;">Vulnerabilidade</th>
                    <th style="width: 30%;">Impacto e Como Exploram</th>
                    <th style="width: 30%;">Medida Recomendada de Correção</th>
                </tr>
            </thead>
            <tbody>
                {linhas_tabela_risco}
            </tbody>
        </table>

        <!-- Conformidade e Infraestrutura -->
        <div class="page-break"></div>
        <div class="section-title">3. Indicadores de Infraestrutura e Conformidade</div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; font-size: 13px;">
            <div style="background: #F9FAFB; padding: 16px; border-radius: 8px; border: 1px solid #E5E7EB;">
                <h4 style="margin: 0 0 10px 0; color: #111827;">🔒 Criptografia & SSL/TLS</h4>
                <p><strong>Cifra:</strong> {escape_txt(ssl_info.get('cipher', 'N/D'))}</p>
                <p><strong>Protocolo:</strong> {escape_txt(ssl_info.get('protocol', 'TLS'))}</p>
                <p><strong>Dias até Expiração:</strong> {escape_txt(ssl_info.get('days_left', 'N/D'))} dias</p>
            </div>
            <div style="background: #F9FAFB; padding: 16px; border-radius: 8px; border: 1px solid #E5E7EB;">
                <h4 style="margin: 0 0 10px 0; color: #111827;">🛡️ Proteção LGPD & Segredos</h4>
                <p><strong>PII / Dados Pessoais:</strong> {escape_txt(pii_info.get('total', 0))} achados</p>
                <p><strong>Segredos / Chaves de API:</strong> {escape_txt(secrets_info.get('total', 0))} chaves detectadas</p>
                <p><strong>Serviços / Portas Abertas:</strong> {escape_txt(len(ports_info))} identificadas</p>
            </div>
        </div>

        <!-- Rodapé do Relatório -->
        <div class="footer">
            <span>Gerado automaticamente por Security Suite Pro • Relatório Confidencial</span>
            <span>Normas OWASP ASVS / NIST SP 800-115</span>
        </div>
    </div>
</body>
</html>"""
    return html_content
