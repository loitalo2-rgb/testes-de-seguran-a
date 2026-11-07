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

### 3. 🔒 Privacidade e Conformidade LGPD
- **`auditor_pii_lgpd.py`**: Varredura do HTML público em busca de dados pessoais expostos.
- **CPF**: validação real do dígito verificador com exibição mascarada (ex.: `529.***.***-25`).
- **Chaves PIX**: detecção de chaves aleatórias (EVP/UUID) e de chaves declaradas no texto.
- **Contatos e endereços**: telefones celulares brasileiros, e-mails, CEPs e logradouros completos.
- **Impacto no score**: achados de severidade ALTA (ex.: CPF válido exposto) são contabilizados como críticos e reduzem a pontuação final.

### 4. 🔑 Segredos Expostos (Secret Scanner)
- **`auditor_secrets.py`**: Procura chaves e credenciais vazadas no HTML e nos scripts JavaScript do próprio domínio.
- **Cloud e APIs**: AWS, Google, Azure, Stripe, OpenAI, SendGrid, Mailgun, Slack, Telegram, Discord, GitHub, GitLab e npm.
- **Tokens e criptografia**: JWT, strings de conexão de banco com senha, Basic Auth em URL, chaves privadas PEM e senhas hardcoded.
- **Segurança da exibição**: os valores são sempre mascarados (`AKIA***MPLE`), e apenas scripts same-origin são baixados (limite de 12 arquivos / 750 KB cada).
- **Impacto no score**: segredos de severidade ALTA somam aos críticos e descontam 15 pontos cada.

### 5. 🚨 Resumo de Risco e Impacto Real
- **Destaque no topo dos resultados**: veredito consolidado (`RISCO CRÍTICO`, `ATENÇÃO NECESSÁRIA` ou `POSTURA BOA`) e contadores por severidade.
- **Explicação do ataque**: para cada achado grave mostra a evidência, **como um atacante poderia explorar** e **como corrigir**.
- **Agregação inteligente**: reúne segredos, arquivos expostos, injeções, PII, headers ausentes, portas de banco, SPF/DMARC, cookies e SSL em um único painel priorizado.
- **Atalho direto**: o botão “Ver detalhes” leva à aba técnica correspondente.

### 6. 🔐 Análise e Ataque a JWT
- **`auditor_jwt.py`**: analisa tokens JWT encontrados no HTML e nos scripts do domínio.
- **Quebra de segredo HMAC**: teste offline por dicionário (HS256/HS384/HS512), sem enviar requisições.
- **`alg: none`**: detecta tokens sem assinatura e gera prova de conceito.
- **`jku`/`x5u`/`kid`**: aponta sequestro de chave pública e injeção via `kid`.
- **Claims**: expiração ausente/expirada/longa e dados pessoais legíveis no payload (LGPD).
- **PoC segura**: gera um token forjado apenas com a claim `poc`, **sem enviar automaticamente** a nenhum endpoint.

### 7. 💉 Injeção Avançada (SSTI, LFI e Command Injection)
- **`auditor_injecao_avancada.py`**: descobre parâmetros na URL e em formulários (GET/POST) e testa injeções não destrutivas.
- **SSTI**: `{{A*B}}`, `${A*B}`, `#{A*B}`, `<%= A*B %>` com números aleatórios — confirma pela avaliação do resultado.
- **LFI / Path Traversal**: `/etc/passwd`, bypass com `....//`, `win.ini` e `php://filter` (detecta código PHP em base64).
- **Command Injection**: eco de marcador exclusivo via `;`, `|`, `$()` e `&` — sem comandos destrutivos.
- **Proteção contra falso positivo**: exige que a resposta contenha o resultado/marcador e **não** seja apenas o payload refletido.
- **Integração**: achados entram no score (−20 cada), no resumo de risco e na nova aba “Injeção Avançada”.

### 8. 📄 Análise de Logs (Apache/Nginx/SSH)
- **`auditor_logs.py`**: analisa logs de acesso web (formato *combined* ou *common*) e logs de autenticação (SSH/syslog).
- **Acesso independente**: seção “Análise de Logs” sempre visível no painel — **não exige rodar uma varredura**.
- **Entrada**: cole o conteúdo ou envie um arquivo (limite de 5 MB); o tipo pode ser detectado automaticamente ou escolhido manualmente.
- **Ataques web detectados**: SQL Injection, XSS, LFI/Path Traversal, Command Injection, acesso a arquivos sensíveis e exploração Log4j/Spring (JNDI).
- **Reconhecimento e força bruta**: scanners pelo *User-Agent* (sqlmap, nikto, gobuster etc.), rajadas de 404, excesso de 401/403 e muitos POSTs em rotas de login.
- **SSH**: falhas de autenticação por IP/usuário e destaque quando há **login aceito após falhas** (possível comprometimento).
- **Resumo da análise**: linhas lidas, requisições válidas, IPs únicos, taxa de erro, top IPs/rotas/status/usuários e veredito de risco.
- **Integração**: `POST /api/logs` recebe `{content, log_type}` e devolve `{log_type, summary, findings, findings_total}`; cada achado traz evidência, “Como o atacante usa” e “Como corrigir”.

### 9. 🕷️ Crawler e Varredura Multi-página
- **`auditor_crawler.py`**: rastreia links e formulários **do mesmo domínio** (esquema + host + porta), com profundidade máxima 2 e até 15 páginas.
- **Respeito ao alvo**: lê `robots.txt`, ignora arquivos estáticos (imagens, CSS, JS, PDFs…) e rotas destrutivas (`logout`, `delete`, `excluir`…).
- **Reaproveitamento**: o HTML de cada página é usado em memória pelos scanners, sem baixar de novo.
- **Cobertura ampliada**: em páginas com parâmetros ou formulários roda Injeção Avançada (SSTI/LFI/CMD) e o scanner de XSS/SQLi; PII/LGPD também é verificada em cada página, com deduplicação.
- **Nova aba “Crawler”**: mapa do site com título, URL, status, profundidade, quantidade de links/formulários e achados encontrados nas páginas extras.
- **Controle**: caixa “Rastrear o site (crawler)” no formulário; pode ser desativada para scans mais rápidos.

### 10. 🛰️ Proxy Interceptador & Scanner Passivo (Estilo OWASP ZAP)
- **`auditor_proxy.py`**: servidor proxy HTTP/HTTPS multithreaded local inspirado no OWASP ZAP para interceptação e análise de segurança de tráfego web em tempo real.
- **Auditoria Passiva (Zero Impacto)**: analisa o tráfego capturado sem enviar requisições adicionais:
  - Cabeçalhos defensivos ausentes (CSP, HSTS, X-Content-Type-Options, anti-Clickjacking).
  - Cookies inseguros (falta de `HttpOnly`, `Secure` e `SameSite`).
  - Vazamento de banners de servidores e frameworks (`Server`, `X-Powered-By`, `X-AspNet-Version`).
  - Cache permissivo em rotas autenticadas e sensíveis.
  - Origens excessivamente permissivas em CORS com credenciais.
  - Exposição de mensagens de depuração técnica e *stack traces* no corpo da resposta.
- **Painel Interativo no `index.html`**:
  - Iniciar/Parar proxy na porta desejada (padrão `127.0.0.1:8090`).
  - Tabela de histórico de requisições em tempo real com status, alertas e latência.
  - Alertas classificados nos padrões OWASP (*Alto, Médio, Baixo, Informativo*) com referências CWE.
  - Botão de envio rápido de qualquer URL interceptada para a auditoria ativa do scanner.
- **Controle via API REST**:
  - `POST /api/proxy/start` e `POST /api/proxy/stop`
  - `GET /api/proxy/status` e `GET /api/proxy/history`
  - `GET /api/proxy/alerts` e `POST /api/proxy/clear`

### 11. 🔐 Varredura Autenticada (Área Logada)
- Suporte a cookies de sessão (`PHPSESSID`, tokens de autenticação), cabeçalhos `Authorization: Bearer <JWT>` e headers customizados (`X-API-Key`).
- A sessão e credenciais configuradas são propagadas automaticamente para o Crawler multi-página, motor de injeções (SSTI, LFI, Command Injection) e inspeção de arquivos sensíveis.

### 12. 📄 Relatório Executivo Formal (PDF / HTML)
- **`relatorio_executivo.py`**: gera relatório corporativo pronto para apresentação a diretorias e clientes.
- Inclui capa executiva, parecer técnico gerencial em linguagem acessível, matriz priorizada de vulnerabilidades com impacto no negócio e plano de ação recomendado.
- Otimizado com estilos CSS `@media print` para exportação direta em PDF pelo navegador (Ctrl+P ou botão dedicado no painel).

### 13. 🔔 Notificações e Webhooks (Discord, Slack, Teams)
- **`notificador_webhook.py`**: integra com URLs de webhook para disparo automático ao finalizar auditorias.
- Envia cards com embeds visuais contendo nota de segurança, veredito de risco, falhas críticas/médias e link do alvo.
- Suporta Discord, Slack e payloads genéricos de automação via API (`POST /api/webhook/test`).

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
├── app_server.py              # Servidor local e orquestrador de todas as auditorias
├── main.py                    # Menu principal CLI
├── scanner_visual.py          # Scanner de XSS e SQLi com relatório visual
├── fuzzer_moderno.py          # Fuzzer multithreaded de diretórios
├── auditor_headers.py         # Auditor defensivo de headers OWASP
├── auditor_ssl.py             # Auditor e extrator de certificados SSL/TLS
├── auditor_recon_dns.py       # DNS/SPF/DMARC, robots/sitemap e cookies
├── auditor_avancado.py        # Portas, arquivos sensíveis e libs JS
├── auditor_nmap.py            # Motor Nmap com fallback nativo
├── auditor_sub_methods.py     # Subdomínios (crt.sh) e métodos HTTP inseguros
├── auditor_whois_geo.py       # WHOIS/RDAP e geolocalização do servidor
├── auditor_pii_lgpd.py        # Dados pessoais expostos, PIX e conformidade LGPD
├── auditor_secrets.py         # Chaves, tokens e senhas expostos no HTML e JS
├── auditor_jwt.py             # Análise e quebra offline de tokens JWT
├── auditor_injecao_avancada.py # SSTI, LFI/Path Traversal e Command Injection
├── auditor_logs.py            # Análise de logs web e SSH (ataques e força bruta)
├── auditor_crawler.py         # Crawler same-origin e mapa do site
├── payloads.json              # Dicionário de vetores de ataque para testes
├── wordlist.json              # Lista de rotas e caminhos comuns
├── test_rotina.py             # Testes automatizados de API e resiliência
├── test_pii_lgpd.py           # Testes unitários do detector de PII/LGPD
├── test_secrets.py            # Testes unitários do Secret Scanner
├── test_jwt.py                # Testes unitários do analisador de JWT
├── test_injecao_avancada.py   # Testes unitários de SSTI/LFI/Command Injection
├── test_logs.py               # Testes unitários da análise de logs web/SSH
├── test_crawler.py            # Testes unitários do crawler same-origin
├── requirements.txt           # Dependências do projeto
└── README.md                  # Documentação completa
```

---

## ⚖️ Aviso Legal (Disclaimer)
Este kit foi desenvolvido estritamente para propósitos educacionais, auditorias de segurança autorizadas e rotinas de garantia de qualidade (QA). O uso não autorizado contra alvos de terceiros sem prévio consentimento é de inteira responsabilidade do executor.
