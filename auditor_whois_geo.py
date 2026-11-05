import requests
import socket
from datetime import datetime

def get_domain_whois_rdap(domain):
    """
    Consulta informações de registro e idade do domínio via RDAP (protocolo sucessor do WHOIS).
    Funciona para domínios globais (.com, .net, .org, .io) e nacionais (.br, etc.).
    """
    clean_domain = domain.lower().strip()
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    info = {
        "domain": clean_domain,
        "created_date": "Não disponível",
        "expires_date": "Não disponível",
        "updated_date": "Não disponível",
        "registrar": "Não identificado",
        "age_days": None,
        "age_text": "Idade desconhecida",
        "risk_level": "BAIXO",
        "nameservers": [],
        "status": "SUCCESS"
    }

    try:
        url = f"https://rdap.org/domain/{clean_domain}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecAudit/1.0"}
        resp = requests.get(url, headers=headers, timeout=8)

        if resp.status_code == 200:
            data = resp.json()

            # Extração de datas (registration, expiration, last changed)
            events = data.get("events", [])
            for event in events:
                action = event.get("eventAction", "")
                date_str = event.get("eventDate", "")
                if "registration" in action:
                    info["created_date"] = date_str[:10]
                    try:
                        dt = datetime.strptime(date_str[:10], "%Y-%m-%d")
                        days = (datetime.now() - dt).days
                        info["age_days"] = days
                        if days < 30:
                            info["age_text"] = f"{days} dias (Domínio Muito Recente - Risco de Phishing/Scam)"
                            info["risk_level"] = "ALTO"
                        elif days < 365:
                            info["age_text"] = f"{days} dias (~{days//30} meses)"
                        else:
                            years = days // 365
                            info["age_text"] = f"{years} anos ({days} dias de atividade)"
                    except Exception:
                        pass
                elif "expiration" in action:
                    info["expires_date"] = date_str[:10]
                elif "last changed" in action:
                    info["updated_date"] = date_str[:10]

            # Nameservers
            ns_list = []
            for ns in data.get("nameservers", []):
                handle = ns.get("ldhName", "")
                if handle:
                    ns_list.append(handle.lower())
            info["nameservers"] = ns_list[:4]

            # Registrador (entities)
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles or "registrant" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn":
                                info["registrar"] = field[3]
                                break
                    if info["registrar"] == "Não identificado":
                        info["registrar"] = entity.get("handle", "Não identificado")
                    break

        else:
            info["status"] = "UNAVAILABLE"
            info["error"] = f"Consulta RDAP retornou status {resp.status_code}"
    except Exception as e:
        info["status"] = "ERROR"
        info["error"] = str(e)

    return info

def get_ip_geolocation(hostname):
    """
    Obtém localização física, país, cidade, ASN e Provedor de Nuvem do servidor.
    """
    geo_data = {
        "ip": "Não resolvido",
        "country": "Desconhecido",
        "city": "Desconhecido",
        "region": "Desconhecido",
        "isp": "Desconhecido",
        "org": "Desconhecido",
        "as_number": "Desconhecido",
        "is_cloudflare": False,
        "is_aws": False
    }

    try:
        resolved_ip = socket.gethostbyname(hostname)
        geo_data["ip"] = resolved_ip

        resp = requests.get(f"http://ip-api.com/json/{resolved_ip}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                geo_data["country"] = f"{data.get('country', '')} ({data.get('countryCode', '')})"
                geo_data["city"] = data.get("city", "")
                geo_data["region"] = data.get("regionName", "")
                geo_data["isp"] = data.get("isp", "")
                geo_data["org"] = data.get("org", "")
                geo_data["as_number"] = data.get("as", "")

                combined = f"{geo_data['isp']} {geo_data['org']}".lower()
                if "cloudflare" in combined:
                    geo_data["is_cloudflare"] = True
                if "amazon" in combined or "aws" in combined:
                    geo_data["is_aws"] = True
    except Exception:
        pass

    return geo_data
