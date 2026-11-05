import sys
import subprocess

def mostrar_menu():
    print("\n" + "="*50)
    print("   KIT DE SEGURANÇA E AUDITORIA DEFENSIVA")
    print("="*50)
    print("1. Auditor Defensivo de Headers OWASP (auditor_headers.py)")
    print("2. Fuzzer de Diretórios (fuzzer_moderno.py)")
    print("3. Scanner de Vulnerabilidades (scanner_visual.py)")
    print("4. Auditor de SSL/TLS (auditor_ssl.py)")
    print("5. Executar Bateria de Testes Automatizados (pytest)")
    print("6. Sair")
    print("="*50)

def main():
    while True:
        mostrar_menu()
        escolha = input("Escolha uma opção (1-6): ").strip()

        if escolha == '1':
            subprocess.run([sys.executable, "auditor_headers.py"])
        elif escolha == '2':
            subprocess.run([sys.executable, "fuzzer_moderno.py"])
        elif escolha == '3':
            subprocess.run([sys.executable, "scanner_visual.py"])
        elif escolha == '4':
            subprocess.run([sys.executable, "auditor_ssl.py"])
        elif escolha == '5':
            subprocess.run([sys.executable, "-m", "pytest", "-v"])
        elif escolha == '6':
            print("[*] Encerrando...")
            break
        else:
            print("[-] Opção inválida!")

if __name__ == "__main__":
    main()
