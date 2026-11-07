import pytest

from auditor_pii_lgpd import scan_pii_and_pix, validate_cpf


def test_validate_cpf_valido():
    assert validate_cpf("529.982.247-25") is True
    assert validate_cpf("52998224725") is True


def test_validate_cpf_invalido():
    assert validate_cpf("111.111.111-11") is False
    assert validate_cpf("123.456.789-00") is False
    assert validate_cpf("529.982.247-24") is False
    assert validate_cpf("abc") is False


def test_cpf_exposto_e_mascarado():
    findings = scan_pii_and_pix("<p>Contato do cliente: 529.982.247-25</p>")
    cpf_findings = [f for f in findings if f["type"] == "CPF Válido Exposto"]
    assert len(cpf_findings) == 1
    # O CPF não pode ser devolvido por inteiro (conformidade LGPD)
    assert "529.982.247-25" not in cpf_findings[0]["sample"]
    assert cpf_findings[0]["sample"].endswith("-25")
    assert cpf_findings[0]["severity"] == "ALTA"


def test_cpf_invalido_nao_e_reportado():
    findings = scan_pii_and_pix("<p>Número qualquer: 111.111.111-11</p>")
    assert not [f for f in findings if f["type"] == "CPF Válido Exposto"]


def test_deteccao_de_chave_pix_aleatoria():
    uuid = "123e4567-e89b-42d3-a456-426614174000"
    findings = scan_pii_and_pix(f"<script>const pixKey = '{uuid}';</script>")
    pix_findings = [f for f in findings if f["type"] == "Chave PIX Aleatória (EVP)"]
    assert len(pix_findings) == 1
    assert pix_findings[0]["sample"] == uuid
    assert pix_findings[0]["category"] == "Financeiro / PIX"


def test_deteccao_de_chave_pix_declarada():
    findings = scan_pii_and_pix("<p>Pague via chave pix: loja@exemplo.com.br</p>")
    assert any(f["type"] == "Chave PIX Declarada" for f in findings)


def test_deteccao_de_telefone_email_e_cep():
    html = "<p>Tel: (11) 98765-4321 | Email: contato@exemplo.com | CEP: 01310-100</p>"
    findings = scan_pii_and_pix(html)
    types = {f["type"] for f in findings}
    assert "Telefone Celular BR" in types
    assert "E-mail de Contato/Usuário" in types
    assert "CEP Residencial/Comercial" in types


def test_html_vazio_retorna_lista_vazia():
    assert scan_pii_and_pix("") == []
    assert scan_pii_and_pix(None) == []
