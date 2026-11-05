import sys
import subprocess

def mostrar_menu():
    print("\n" + "="*55)
    print("      KIT DE SEGURANÇA E AUDITORIA DEFENSIVA")
    print("="*55)
    print("1. Iniciar Painel Visual Web Completo (app_server.py)")
    print("2. Auditor Defensivo de Headers OWASP (auditor_headers.py)")
    print("3. Fuzzer de Diretórios (fuzzer_moderno.py)")
    print("4. Scanner de Vulnerabilidades (scanner_visual.py)")
    print("5. Auditor de SSL/TLS (auditor_ssl.py)")
    print("6. Executar Bateria de Testes Automatizados (pytest)")
    print("7. Sair")
    print("="*55)

def main():
    while True:
        mostrar_menu()
        escolha = input("Escolha uma opção (1-7): ").strip()

        if escolha == '1':
            print("\n[*] Iniciando servidor local do Painel Web...")
            subprocess.run([sys.executable, "app_server.py"])
        elif escolha == '2':
            subprocess.run([sys.executable, "auditor_headers.py"])
        elif escolha == '3':
            subprocess.run([sys.executable, "fuzzer_moderno.py"])
        elif escolha == '4':
            subprocess.run([sys.executable, "scanner_visual.py"])
        elif escolha == '5':
            subprocess.run([sys.executable, "auditor_ssl.py"])
        elif escolha == '6':
            subprocess.run([sys.executable, "-m", "pytest", "-v"])
        elif escolha == '7':
            print("[*] Encerrando...")
            break
        else:
            print("[-] Opção inválida!")

if __name__ == "__main__":
    main()
