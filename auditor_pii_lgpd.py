import re

def validate_cpf(cpf_str):
    """Valida o dígito verificador de um CPF."""
    cpf = re.sub(r'\D', '', cpf_str)
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    for i in range(9, 11):
        value = sum((int(cpf[num]) * ((i + 1) - num) for num in range(0, i)))
        digit = ((value * 10) % 11) % 10
        if digit != int(cpf[i]):
            return False
    return True

def scan_pii_and_pix(html_content):
    """
    Inspeciona o conteúdo HTML do site em busca de vazamentos de dados pessoais (PII)
    e dados financeiros/PIX em conformidade com a LGPD.
    """
    findings = []
    if not html_content:
        return findings

    # 1. Chaves PIX (E-mails, Telefones BR, Chaves Aleatórias/EVP, CPFs)
    # 1.1 Chaves Aleatórias PIX (UUID v4 padrão Banco Central: 8-4-4-4-12 hex)
    pix_random_pattern = r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    pix_random_matches = set(re.findall(pix_random_pattern, html_content))
    for m in list(pix_random_matches)[:5]:
        findings.append({
            "type": "Chave PIX Aleatória (EVP)",
            "category": "Financeiro / PIX",
            "sample": m,
            "severity": "MÉDIA",
            "desc": "Chave PIX aleatória exposta no código-fonte da página."
        })

    # 1.2 Menção explícita de Chave PIX (ex: "pix: ...", "chave pix:")
    pix_explicit = re.findall(r'(?:chave\s*pix|pix\s*:)\s*([a-zA-Z0-9_\-\.@+]{5,40})', html_content, re.IGNORECASE)
    for p in set(pix_explicit):
        findings.append({
            "type": "Chave PIX Declarada",
            "category": "Financeiro / PIX",
            "sample": p,
            "severity": "MÉDIA",
            "desc": "Chave PIX encontrada próxima a menções de pagamento no texto."
        })

    # 2. CPF (Cadastro de Pessoas Físicas)
    cpf_candidates = re.findall(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b', html_content)
    valid_cpfs = set()
    for c in cpf_candidates:
        if validate_cpf(c):
            # Mascarar parcialmente para exibição segura (LGPD compliance)
            masked = c[:4] + "***.***-" + c[-2:]
            valid_cpfs.add(masked)

    for cpf in list(valid_cpfs)[:5]:
        findings.append({
            "type": "CPF Válido Exposto",
            "category": "Dados Pessoais (LGPD)",
            "sample": cpf,
            "severity": "ALTA",
            "desc": "Número de CPF válido identificado publicamente no HTML."
        })

    # 3. Telefones Celulares Brasileiros com DDD
    phones = set(re.findall(r'(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?9\d{4}[-\s]?\d{4}\b', html_content))
    for ph in list(phones)[:5]:
        findings.append({
            "type": "Telefone Celular BR",
            "category": "Dados Pessoais (LGPD)",
            "sample": ph,
            "severity": "BAIXA",
            "desc": "Contato telefônico celular exposto na página."
        })

    # 4. CEPs e Padrões de Endereço Físico BR
    ceps = set(re.findall(r'\b\d{5}-\d{3}\b', html_content))
    for cep in list(ceps)[:5]:
        findings.append({
            "type": "CEP Residencial/Comercial",
            "category": "Endereço Físico",
            "sample": cep,
            "severity": "BAIXA",
            "desc": "Código de Endereçamento Postal (CEP) identificado."
        })

    # Menções de logradouro (Rua, Av, Alameda) com número
    address_matches = set(re.findall(r'\b(?:Rua|Avenida|Av\.|Travessa|Alameda)\s+[A-Za-z0-9À-ÿ\s]{4,40},\s*(?:nº|n°|n\.)?\s*\d+\b', html_content, re.IGNORECASE))
    for addr in list(address_matches)[:5]:
        findings.append({
            "type": "Endereço Físico Completo",
            "category": "Endereço Físico",
            "sample": addr,
            "severity": "MÉDIA",
            "desc": "Logradouro com número residencial ou comercial identificado."
        })

    # 5. E-mails pessoais / corporativos expostos
    emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b', html_content))
    # Filtrar extensões comuns de imagens ou fontes que pareçam e-mails
    valid_emails = [e for e in emails if not e.endswith(('.png', '.jpg', '.jpeg', '.svg', '.webp'))]
    for em in list(valid_emails)[:5]:
        findings.append({
            "type": "E-mail de Contato/Usuário",
            "category": "Dados Pessoais (LGPD)",
            "sample": em,
            "severity": "BAIXA",
            "desc": "Endereço de e-mail exposto (alvo comum de web scraping para spam)."
        })

    return findings
