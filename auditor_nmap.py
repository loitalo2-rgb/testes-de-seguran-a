import os
import shutil
import subprocess
import socket

DEFAULT_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe"
]

def get_nmap_binary():
    binary = shutil.which("nmap")
    if binary:
        return binary
    for path in DEFAULT_NMAP_PATHS:
        if os.path.isfile(path):
            return path
    return None

def is_nmap_available():
    return get_nmap_binary() is not None

def run_nmap_scan(target_host, mode="fast"):
    """
    Executa a varredura Nmap com base no modo selecionado pelo usuário:
    - fast: Top 100 portas + versões (-F -sV) [~10s]
    - advanced: Top 1.000 portas padrão + detecção de serviços + scripts seguros (-sV -sC) [~30-60s]
    - deep: Varredura de portas estendida (Top 5.000) + detecção agressiva (-A -T4) [~2-4min]
    """
    nmap_bin = get_nmap_binary()

    if nmap_bin:
        # Configurar flags de acordo com o modo
        if mode == "advanced":
            cmd = [nmap_bin, "-sV", "-sC", "-T4", "-Pn", target_host]
            timeout_sec = 180
            mode_label = "Modo Avançado (Top 1.000 Portas + Scripts NSE)"
        elif mode == "deep":
            # Usando --top-ports 5000 com -A para máxima profundidade de SO e serviços
            cmd = [nmap_bin, "-A", "-T4", "--top-ports", "5000", "-Pn", target_host]
            timeout_sec = 360
            mode_label = "Modo Profundo (Top 5.000 Portas + Detecção de SO + Traceroute)"
        else:
            # fast por padrão
            cmd = [nmap_bin, "-sV", "-T4", "-F", "-Pn", target_host]
            timeout_sec = 90
            mode_label = "Modo Rápido (Top 100 Portas Mais Comuns)"

        try:
            print(f"[*] Executando Nmap [{mode_label}] no alvo: {target_host}...")
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
            output = process.stdout or ""
            
            ports_found = []
            os_detected = "Não determinado"

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
                elif "OS details:" in line or "Service Info: OS:" in line:
                    os_detected = line.strip()

            return {
                "engine": "Nmap Official CLI (Ativo)",
                "installed": True,
                "mode": mode,
                "mode_label": mode_label,
                "binary_path": nmap_bin,
                "command": " ".join(cmd),
                "os_detected": os_detected,
                "ports": ports_found,
                "raw_output": output
            }
        except subprocess.TimeoutExpired:
            return {
                "engine": "Nmap Official CLI",
                "installed": True,
                "error": f"Tempo limite ({timeout_sec}s) excedido para a varredura selecionada."
            }
        except Exception as e:
            return {
                "engine": "Nmap Official CLI",
                "installed": True,
                "error": str(e)
            }
    else:
        # Fallback de sockets nativos caso o nmap não esteja disponível
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
                            "version": "Detectado via socket nativo"
                        })
            except Exception:
                pass

        return {
            "engine": "Nmap Emulador Nativo (Python Socket Fallback)",
            "installed": False,
            "mode": mode,
            "mode_label": "Fallback Socket Básico",
            "ports": discovered,
            "raw_output": f"Nmap CLI não encontrado. Varredura via socket com {len(discovered)} portas encontradas."
        }
