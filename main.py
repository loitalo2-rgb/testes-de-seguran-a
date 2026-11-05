import sys
import subprocess

def mostrar_menu():
    print("\n" + "="*45)
    print("   KIT DE AUTOMAÇÃO DE SEGURANÇA (PENTEST)")
    print("="*45)
    print("1. Fuzzer de Diretórios (fuzzer_moderno.py)")
    print("2. Scanner de Vulnerabilidades (scanner_visual.py)")
    print("3. Auditor de SSL/TLS (auditor_ssl.py)")
    print("4. Executar Testes Automatizados (pytest)")
    print("5. Sair")
    print("="*45)

def main():
    while True:
        mostrar_menu()
        escolha = input("Escolha uma opção (1-5): ").strip()

        if escolha == '1':
            subprocess.run([sys.executable, "fuzzer_moderno.py"])
        elif escolha == '2':
            subprocess.run([sys.executable, "scanner_visual.py"])
        elif escolha == '3':
            subprocess.run([sys.executable, "auditor_ssl.py"])
        elif escolha == '4':
            subprocess.run([sys.executable, "-m", "pytest", "-v"])
        elif escolha == '5':
            print("[*] Encerrando...")
            break
        else:
            print("[-] Opção inválida!")

if __name__ == "__main__":
    main()
