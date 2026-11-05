import os
import shutil
import subprocess
import socket

# Caminhos padrão do instalador oficial no Windows
DEFAULT_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe"
]

def get_nmap_binary():
    """
    Localiza o binário executável do Nmap no sistema:
    1. Verifica se está no PATH (nmap).
    2. Procura nas pastas de instalação padrão do Windows.
    """
    binary = shutil.which("nmap")
    if binary:
        return binary

    for path in DEFAULT_NMAP_PATHS:
        if os.path.isfile(path):
            return path

    return None

def is_nmap_available():
    return get_nmap_binary() is not None

def run_nmap_scan(target_host, fast_mode=True):
    """
    Executa a varredura via Nmap oficial ou fallback nativo se não for encontrado.
    """
    nmap_bin = get_nmap_binary()

    if nmap_bin:
        # -sV: Versões de serviços, -T4: Modo rápido, -F: Top 100 portas mais comuns
        # -Pn: Trata todos os hosts como online (evita falha por bloqueio de ping ICMP no Windows)
        cmd = [nmap_bin, "-sV", "-T4", "-F", "-Pn", target_host]
        try:
            print(f"[*] Executando Nmap Oficial ({nmap_bin}) em: {target_host}...")
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
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
                "engine": "Nmap Official CLI (Ativo)",
                "installed": True,
                "binary_path": nmap_bin,
                "command": " ".join(cmd),
                "ports": ports_found,
                "raw_output": output
            }
        except Exception as e:
            return {
                "engine": "Nmap Official CLI",
                "installed": True,
                "binary_path": nmap_bin,
                "error": str(e)
            }
    else:
        # Fallback de sockets nativos caso o nmap realmente não seja encontrado
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
            "tip": "Para utilizar o Nmap nativo, instale-o em https://nmap.org/download.html",
            "ports": discovered,
            "raw_output": f"Varredura executada via fallback nativo com {len(discovered)} portas identificadas."
        }
