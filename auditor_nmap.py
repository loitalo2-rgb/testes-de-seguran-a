import shutil
import subprocess
import socket
import json
import xml.etree.ElementTree as ET

def is_nmap_available():
    """Verifica se o binário do nmap está instalado no PATH do sistema operacional."""
    return shutil.which("nmap") is not None

def run_nmap_scan(target_host, fast_mode=True):
    """
    Executa uma varredura via Nmap caso disponível no sistema,
    ou fallback transparente para o scanner nativo em Python caso o nmap não esteja instalado.
    """
    if is_nmap_available():
        # Argumentos seguros: -sV (versões), -T4 (velocidade), -F (top 100 portas rápidas)
        cmd = ["nmap", "-sV", "-T4", "-F", target_host]
        try:
            print(f"[*] Executando Nmap no alvo: {target_host}...")
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = process.stdout or ""
            
            ports_found = []
            for line in output.splitlines():
                if "/tcp" in line or "/udp" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0]
                        state = parts[1]
                        service = parts[2]
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        ports_found.append({
                            "port": port_proto,
                            "state": state,
                            "service": service,
                            "version": version
                        })

            return {
                "engine": "Nmap Official CLI",
                "installed": True,
                "command": " ".join(cmd),
                "ports": ports_found,
                "raw_output": output
            }
        except Exception as e:
            return {
                "engine": "Nmap Official CLI",
                "installed": True,
                "error": str(e)
            }
    else:
        # Fallback elegante em Python caso o usuário ainda não tenha instalado o nmap.exe
        common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3000, 3306, 5432, 6379, 8000, 8080, 8443, 27017]
        discovered = []
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((target_host, port)) == 0:
                        discovered.append({
                            "port": f"{port}/tcp",
                            "state": "open",
                            "service": socket.getservbyport(port, "tcp") if port in [21, 22, 25, 53, 80, 110, 143, 443] else "service-generic",
                            "version": "Detectado via socket nativo (Nmap não instalado)"
                        })
            except Exception:
                pass

        return {
            "engine": "Nmap Emulador Nativo (Python Socket Fallback)",
            "installed": False,
            "tip": "Para utilizar o motor nativo completo com detecção de OS e fingerprinting do Nmap, instale-o em https://nmap.org/download.html",
            "ports": discovered,
            "raw_output": f"Nmap CLI não encontrado no PATH do sistema. Varredura executada via fallback nativo com {len(discovered)} portas identificadas."
        }
