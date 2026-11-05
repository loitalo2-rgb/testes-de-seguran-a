import subprocess
import socket
import re
import requests
import xml.etree.ElementTree as ET

def check_dns_email_security(domain):
    """
    Audita registros DNS, SPF, DMARC e MX do domínio alvo usando consultas nslookup padrão.
    """
    results = {
        "domain": domain,
        "ips": [],
        "mx_records": [],
        "spf": {"status": "FAIL", "record": "Não encontrado", "recommendation": "Adicionar registro TXT com v=spf1 ... -all"},
        "dmarc": {"status": "FAIL", "record": "Não encontrado", "recommendation": "Configurar registro TXT em _dmarc.{domain} com política p=reject ou p=quarantine"}
    }

    # 1. Resolução de IPs (A / AAAA)
    try:
        addr_info = socket.getaddrinfo(domain, None)
        ips = list(dict.fromkeys([item[4][0] for item in addr_info]))
        results["ips"] = ips
    except Exception as e:
        results["ips_error"] = str(e)

    # 2. Consulta TXT (SPF)
    try:
        ns_txt = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, text=True, timeout=5)
        out_txt = ns_txt.stdout or ""
        for line in out_txt.splitlines():
            clean = line.strip().replace('"', '')
            if "v=spf1" in clean:
                results["spf"]["status"] = "PASS"
                results["spf"]["record"] = clean
                results["spf"]["recommendation"] = "Configuração de SPF ativa."
                break
    except Exception:
        pass

    # 3. Consulta DMARC (_dmarc.dominio)
    try:
        ns_dmarc = subprocess.run(["nslookup", "-type=TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=5)
        out_dmarc = ns_dmarc.stdout or ""
        for line in out_dmarc.splitlines():
            clean = line.strip().replace('"', '')
            if "v=DMARC1" in clean:
                results["dmarc"]["status"] = "PASS"
                results["dmarc"]["record"] = clean
                results["dmarc"]["recommendation"] = "Política DMARC configurada no DNS."
                break
    except Exception:
        pass

    # 4. Consulta MX
    try:
        ns_mx = subprocess.run(["nslookup", "-type=MX", domain], capture_output=True, text=True, timeout=5)
        out_mx = ns_mx.stdout or ""
        mx_list = []
        for line in out_mx.splitlines():
            if "mail exchanger" in line.lower() or "mx preference" in line.lower():
                mx_list.append(line.strip())
        results["mx_records"] = mx_list[:5]
    except Exception:
        pass

    return results

def inspect_recon_files(base_url):
    """
    Examina /robots.txt e /sitemap.xml identificando rotas ocultas ou restritas.
    """
    clean_base = base_url.rstrip('/')
    data = {
        "robots": {"found": False, "disallowed_paths": [], "sitemaps_declared": [], "raw": ""},
        "sitemap": {"found": False, "urls_count": 0, "sample_urls": []}
    }

    # Checar robots.txt
    try:
        resp = requests.get(f"{clean_base}/robots.txt", timeout=5, allow_redirects=True)
        if resp.status_code == 200 and "User-agent" in resp.text:
            data["robots"]["found"] = True
            data["robots"]["raw"] = resp.text[:2000]
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path not in data["robots"]["disallowed_paths"]:
                        data["robots"]["disallowed_paths"].append(path)
                elif line.lower().startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm not in data["robots"]["sitemaps_declared"]:
                        data["robots"]["sitemaps_declared"].append(sm)
    except Exception:
        pass

    # Checar sitemap.xml
    try:
        sm_url = f"{clean_base}/sitemap.xml"
        resp_sm = requests.get(sm_url, timeout=5, allow_redirects=True)
        if resp_sm.status_code == 200 and ("<urlset" in resp_sm.text or "<sitemapindex" in resp_sm.text):
            data["sitemap"]["found"] = True
            root = ET.fromstring(resp_sm.content)
            urls = []
            for elem in root.iter():
                if elem.tag.endswith("loc") and elem.text:
                    urls.append(elem.text.strip())
            data["sitemap"]["urls_count"] = len(urls)
            data["sitemap"]["sample_urls"] = urls[:10]
    except Exception:
        pass

    return data

def inspect_cookies_privacy(response_cookies, target_url):
    """
    Inspeciona cookies retornados avaliando flags de segurança e conformidade de privacidade.
    """
    cookies_analysis = []
    is_https = target_url.startswith("https://")

    for cookie in response_cookies:
        issues = []
        is_secure = getattr(cookie, 'secure', False)
        is_httponly = cookie.has_nonstandard_attr('HttpOnly') or getattr(cookie, 'httponly', False)
        same_site = cookie.get_nonstandard_attr('SameSite', 'Não Definido')

        if not is_secure and is_https:
            issues.append("Ausência da flag Secure em conexão HTTPS")
        if not is_httponly:
            issues.append("Ausência de HttpOnly (Vulnerável à extração via XSS)")
        if same_site in ['Não Definido', 'None']:
            issues.append("SameSite ausente ou permissive (Risco de CSRF)")

        cookies_analysis.append({
            "name": cookie.name,
            "domain": cookie.domain or "Host local",
            "path": cookie.path or "/",
            "secure": is_secure,
            "http_only": is_httponly,
            "same_site": same_site,
            "status": "PASS" if not issues else "FAIL",
            "issues": issues if issues else ["Conforme com boas práticas"]
        })

    return cookies_analysis
