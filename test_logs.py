from auditor_logs import analyze_logs


def web_line(ip, path, status=200, method="GET", ua="Mozilla/5.0", ts="06/Nov/2026:10:00:00 -0300"):
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 512 "-" "{ua}"'


def test_detecta_formato_web_e_resumo():
    conteudo = "\n".join([
        web_line("203.0.113.5", "/index.html"),
        web_line("203.0.113.5", "/produto?id=1"),
        web_line("198.51.100.9", "/contato", status=404),
    ])
    res = analyze_logs(conteudo)
    assert res["log_type"] == "web"
    assert res["summary"]["total_lines"] == 3
    assert res["summary"]["parsed_lines"] == 3
    assert res["summary"]["unique_ips"] == 2
    assert res["summary"]["top_ips"][0] == {"ip": "203.0.113.5", "count": 2}
    assert res["summary"]["status_codes"]["200"] == 2


def test_sqli_com_sucesso_e_risco_alto():
    linha = web_line("203.0.113.5", "/produto?id=1%20UNION%20SELECT%20NULL", status=200)
    res = analyze_logs(linha)
    sql = [f for f in res["findings"] if f["type"] == "SQL Injection"]
    assert len(sql) == 1
    assert sql[0]["severity"] == "ALTA"
    assert "possível sucesso" in sql[0]["evidence"]


def test_sqli_bloqueado_e_risco_medio():
    linha = web_line("203.0.113.5", "/produto?id=1%20UNION%20SELECT%20NULL", status=403)
    res = analyze_logs(linha)
    sql = [f for f in res["findings"] if f["type"] == "SQL Injection"]
    assert len(sql) == 1
    assert sql[0]["severity"] == "MÉDIA"


def test_detecta_xss_lfi_e_arquivo_sensivel():
    conteudo = "\n".join([
        web_line("203.0.113.7", "/busca?q=%3Cscript%3Ealert(1)%3C/script%3E"),
        web_line("203.0.113.8", "/download?file=../../../../etc/passwd"),
        web_line("203.0.113.9", "/.env"),
    ])
    tipos = {f["type"] for f in analyze_logs(conteudo)["findings"]}
    assert "Cross-Site Scripting (XSS)" in tipos
    assert "LFI / Path Traversal" in tipos
    assert "Arquivo/configuração sensível" in tipos


def test_detecta_scanner_pelo_user_agent():
    linha = web_line("203.0.113.10", "/", ua="sqlmap/1.8 (https://sqlmap.org)")
    res = analyze_logs(linha)
    scanners = [f for f in res["findings"] if f["type"] == "Ferramenta de varredura automatizada"]
    assert len(scanners) == 1
    assert "sqlmap" in scanners[0]["desc"]


def test_detecta_varredura_de_diretorios():
    linhas = [web_line("203.0.113.11", f"/admin{i}", status=404) for i in range(25)]
    res = analyze_logs("\n".join(linhas))
    scans = [f for f in res["findings"] if f["type"] == "Varredura de diretórios/arquivos"]
    assert len(scans) == 1
    assert scans[0]["count"] == 25


def test_detecta_forca_bruta_em_login():
    linhas = [web_line("203.0.113.12", "/login", status=401, method="POST") for _ in range(12)]
    res = analyze_logs("\n".join(linhas))
    brutas = [f for f in res["findings"] if f["type"] == "Força bruta em login"]
    assert len(brutas) == 1
    assert brutas[0]["severity"] == "ALTA"
    assert brutas[0]["count"] == 12


def test_analisa_log_ssh_com_forca_bruta():
    linhas = [f"Nov  6 10:0{i}:00 host sshd[123]: Failed password for root from 198.51.100.7 port 5000 ssh2" for i in range(6)]
    res = analyze_logs("\n".join(linhas))
    assert res["log_type"] == "auth"
    ssh = [f for f in res["findings"] if f["type"] == "Força bruta SSH"]
    assert len(ssh) == 1
    assert ssh[0]["severity"] == "ALTA"
    assert ssh[0]["source_ip"] == "198.51.100.7"
    assert res["summary"]["failed_logins"] == 6


def test_ssh_com_sucesso_apos_falhas():
    linhas = [
        "Nov  6 10:00:00 host sshd[1]: Failed password for admin from 198.51.100.8 port 1 ssh2",
        "Nov  6 10:00:01 host sshd[1]: Failed password for admin from 198.51.100.8 port 1 ssh2",
        "Nov  6 10:00:02 host sshd[1]: Accepted password for admin from 198.51.100.8 port 1 ssh2",
    ]
    res = analyze_logs("\n".join(linhas))
    ssh = [f for f in res["findings"] if f["type"] == "Força bruta SSH"]
    assert "login bem-sucedido" in ssh[0]["evidence"]


def test_conteudo_desconhecido_nao_quebra():
    res = analyze_logs("linha qualquer sem formato\noutra linha")
    assert res["log_type"] == "unknown"
    assert res["summary"]["parsed_lines"] == 0
    assert res["findings"] == []


def test_log_normal_nao_gera_achados():
    linhas = [web_line("203.0.113.20", "/index.html"), web_line("203.0.113.20", "/sobre")]
    assert analyze_logs("\n".join(linhas))["findings"] == []
