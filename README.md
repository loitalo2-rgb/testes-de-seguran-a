# QA Web Inspector & Advanced Security Suite 🛡️

Suite completa e intuitiva para testes de segurança ofensiva e defensiva em aplicações web, inspeção de headers OWASP Top 10 e automação de testes de segurança.

---

## 🚀 Funcionalidades Principais

### 1. 🛡️ Interface Interativa (Dashboard SPA) - `index.html`
- **OWASP Top 10 Headers**: Análise de `X-Frame-Options`, `Content-Security-Policy` (CSP) e proteções anti-Clickjacking.
- **Fingerprinting e Ocultação de Tecnologias**: Auditoria dos headers `Server` e `X-Powered-By` para mitigar reconhecimento de CVEs conhecidas.
- **Auditoria de CORS**: Detecção de origens abertas (`Access-Control-Allow-Origin: *`) com risco de vazamento de dados confidenciais.
- **Criptografia Estrita (HSTS)**: Validação do cabeçalho `Strict-Transport-Security` para prevenção de SSL Stripping.
- **Filtros por Categoria**: Visualização em tempo real de falhas críticas, médias e diagnósticos de estabilidade para automação/RPA.

### 2. ⚡ Scripts de Pentest Automatizado (Python)
- **`main.py`**: Menu interativo CLI para orquestrar todas as ferramentas de varredura.
- **`scanner_visual.py`**: Scanner de injeção de parâmetros contra vulnerabilidades **XSS** (Cross-Site Scripting) e **SQLi** (SQL Injection) com exportação de relatório HTML.
- **`fuzzer_moderno.py`**: Fuzzer concorrente (multithreaded) para descoberta de pastas, rotas e arquivos sensíveis usando `wordlist.json`.
- **`auditor_ssl.py`**: Inspetor de certificados SSL/TLS, validação de cifras, bits de criptografia, autoridade certificadora e data de expiração.
- **Testes de Qualidade (`pytest`)**: Rotinas de teste automatizado de endpoints e tolerância a falhas (`test_rotina.py`).

---

## 📦 Instalação

Clone o repositório e instale as dependências:

```bash
git clone https://github.com/loitalo2-rgb/testes-de-seguran-a.git
cd testes-de-seguran-a
pip install -r requirements.txt
```

---

## 🛠️ Como Utilizar

### Executando a Interface Web
Basta abrir o arquivo `index.html` em qualquer navegador moderno.

### Executando o Menu Principal via Terminal
```bash
python main.py
```

### Executando Módulos Individualmente
- **Fuzzer de Diretórios:**
  ```bash
  python fuzzer_moderno.py
  ```
- **Scanner de Vulnerabilidades:**
  ```bash
  python scanner_visual.py
  ```
- **Auditor SSL/TLS:**
  ```bash
  python auditor_ssl.py
  ```
- **Bateria de Testes Automatizados:**
  ```bash
  pytest -v
  ```

---

## 📁 Estrutura do Projeto

```
├── index.html                 # Interface Web Interativa (QA Web Inspector v3.0)
├── main.py                    # Menu principal CLI
├── scanner_visual.py          # Scanner de XSS e SQLi com relatório visual
├── fuzzer_moderno.py          # Fuzzer multithreaded de diretórios
├── auditor_ssl.py             # Auditor e extrator de certificados SSL/TLS
├── payloads.json              # Dicionário de vetores de ataque para testes
├── wordlist.json              # Lista de rotas e caminhos comuns
├── test_rotina.py             # Testes automatizados de API e resiliência
├── requirements.txt           # Dependências do projeto
└── README.md                  # Documentação completa
```

---

## ⚖️ Aviso Legal (Disclaimer)
Este kit foi desenvolvido estritamente para propósitos educacionais, auditorias de segurança autorizadas e rotinas de garantia de qualidade (QA). O uso não autorizado contra alvos de terceiros sem prévio consentimento é de inteira responsabilidade do executor.
