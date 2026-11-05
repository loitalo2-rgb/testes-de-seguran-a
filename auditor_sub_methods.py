import requests
import json
import urllib.parse

def enumerate_subdomains_crtsh(domain, limit=25):
    """
    Enumera subdomínios de forma 100% passiva consultando logs públicos de
    Transparência de Certificados (Certificate Transparency - crt.sh).
    """
    subdomains = set()
    clean_domain = domain.lower().strip()
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecAudit/1.0"}

    try:
        response = requests.get(url, headers=headers, timeout=12)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if "*" not in sub and sub.endswith(clean_domain) and sub != clean_domain:
                        subdomains.add(sub)
            return {
                "status": "SUCCESS",
                "domain": clean_domain,
                "total_found": len(subdomains),
                "subdomains": sorted(list(subdomains))[:limit]
            }
    except Exception as e:
        return {
            "status": "UNAVAILABLE",
            "domain": clean_domain,
            "error": "Consulta ao serviço crt.sh indisponível ou tempo limite esgotado.",
            "subdomains": []
        }

    return {
        "status": "SUCCESS",
        "domain": clean_domain,
        "total_found": 0,
        "subdomains": []
    }

def check_http_methods(target_url):
    """
    Verifica se o servidor web aceita métodos HTTP arriscados ou desnecessários:
    - TRACE (Permite ataques de Cross-Site Tracing / XST)
    - PUT, DELETE (Permitem gravação ou exclusão indevida se desprotegidos)
    - TRACK, CONNECT
    """
    results = {
        "allowed_methods": [],
        "risky_methods": [],
        "trace_enabled": False,
        "status": "PASS",
        "recommendation": "Apenas métodos HTTP seguros e estritamente necessários estão habilitados."
    }

    try:
        # Envia requisição OPTIONS para inspecionar o cabeçalho 'Allow' ou 'Public'
        resp_options = requests.options(target_url, timeout=5, allow_redirects=True)
        allow_header = resp_options.headers.get("Allow", "") or resp_options.headers.get("Public", "")
        
        methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
        results["allowed_methods"] = methods

        # Testar explicitamente o método TRACE
        try:
            resp_trace = requests.request("TRACE", target_url, timeout=4)
            if resp_trace.status_code in [200, 204] and "message/http" in resp_trace.headers.get("Content-Type", ""):
                results["trace_enabled"] = True
                if "TRACE" not in results["risky_methods"]:
                    results["risky_methods"].append("TRACE")
        except Exception:
            pass

        # Checar se métodos arriscados estão na lista de Allow
        for r in ["TRACE", "TRACK", "PUT", "DELETE"]:
            if r in methods and r not in results["risky_methods"]:
                results["risky_methods"].append(r)

        if results["risky_methods"]:
            results["status"] = "FAIL"
            results["recommendation"] = f"Desabilitar os métodos potencialmente perigosos ({', '.join(results['risky_methods'])}) na configuração do servidor web."

    except Exception as e:
        results["error"] = str(e)

    return results
