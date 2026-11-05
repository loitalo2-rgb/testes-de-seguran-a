# testes-de-seguran-a
app teste de segurança em aplicações
As principais adições que transformaram a ferramenta em um scanner de segurança corporativo foram:

1. 🛡️ Proteção contra Clickjacking (X-Frame-Options)
O que testa: Verifica se o site permite ser embutido dentro de iframes em páginas maliciosas de terceiros.

Por que é importante: Sem essa proteção, atacantes podem criar armadilhas visuais transparentes sobre o seu site para induzir o usuário a clicar em botões confidenciais sem saber (UI Redressing).

2. 🔍 Fingerprinting e Ocultação de Versão de Servidor
O que testa: Inspeciona se os cabeçalhos HTTP (Server ou X-Powered-By) estão revelando a tecnologia exata e o número da versão do servidor (ex: Nginx, Apache ou IIS).

Por que é importante: Expor versões exatas facilita que hackers procurem vulnerabilidades públicas conhecidas (CVEs) específicas daquele software para realizar ataques direcionados.

3. 🌐 Auditoria de CORS Restritivo (Access-Control-Allow-Origin)
O que testa: Identifica se a API ou o site está configurado com permissões excessivamente abertas (*).

Por que é importante: Um CORS mal configurado permite que qualquer site na web leia dados sensíveis e confidenciais retornados pelas requisições autenticadas do usuário.

4. 🔒 Criptografia Estrita de Transporte (HSTS)
O que testa: Verifica a presença do cabeçalho Strict-Transport-Security.

Por que é importante: Garante que o navegador do usuário sempre force conexões seguras via HTTPS, evitando interceptações de dados no primeiro acesso (SSL Stripping).

5. 🎛️ Filtros Avançados de Categoria no Dashboard
Interface: Agora você pode filtrar os resultados instantaneamente na tela clicando nas categorias: OWASP / Headers, Privacidade & Cookies ou Estabilidade RPA.
