import re
import urllib.parse
import urllib.robotparser
from collections import deque

import requests

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecAudit/Crawler"
DEFAULT_MAX_PAGES = 8
DEFAULT_MAX_DEPTH = 2
REQUEST_TIMEOUT = 6

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".bmp", ".ico",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".webm",
    ".pdf", ".zip", ".rar", ".gz", ".tar", ".7z",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dmg", ".apk", ".iso",
}

# Rotas que alteram estado ou encerram sessão não devem ser visitadas por um crawler
SKIP_KEYWORDS = (
    "logout", "signout", "logoff", "sair", "delete", "excluir", "remover",
    "unsubscribe", "cancelar", "checkout/complete",
)

HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
FORM_ACTION_RE = re.compile(r"""<form\b[^>]*\baction\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _split(url):
    return urllib.parse.urlsplit(url)


def _effective_port(parsed):
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def normalize_url(url):
    """Remove fragmento e normaliza host/esquema para evitar duplicatas."""
    parsed = _split(url)
    path = parsed.path or "/"
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, "")
    )


def is_same_origin(url, base_url):
    a = _split(url)
    b = _split(base_url)
    return (
        a.scheme.lower() == b.scheme.lower()
        and (a.hostname or "").lower() == (b.hostname or "").lower()
        and _effective_port(a) == _effective_port(b)
    )


def is_crawlable(url):
    parsed = _split(url)
    if parsed.scheme not in ("http", "https"):
        return False
    path = (parsed.path or "/").lower()
    extension = "." + path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    if extension in SKIP_EXTENSIONS:
        return False
    if any(word in path for word in SKIP_KEYWORDS):
        return False
    return True


def extract_links(base_url, html):
    """Extrai hrefs e actions de formulários, devolvendo URLs absolutas e únicas."""
    html = html or ""
    links = set()
    for match in HREF_RE.finditer(html):
        links.add(match.group(1).strip())
    for match in FORM_ACTION_RE.finditer(html):
        links.add(match.group(1).strip())

    result = []
    for raw in links:
        if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = urllib.parse.urljoin(base_url, raw)
        absolute = normalize_url(absolute)
        if is_crawlable(absolute) and is_same_origin(absolute, base_url):
            result.append(absolute)
    return sorted(set(result))


def extract_title(html):
    match = TITLE_RE.search(html or "")
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:120]


def _load_robots(base_url, timeout):
    parsed = _split(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    parser = urllib.robotparser.RobotFileParser()
    parser.set_url(robots_url)
    try:
        response = requests.get(robots_url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        if response.status_code == 200:
            parser.parse(response.text.splitlines())
        else:
            parser.parse([])
    except Exception:
        parser.parse([])
    return parser


def crawl_site(target_url, max_pages=DEFAULT_MAX_PAGES, max_depth=DEFAULT_MAX_DEPTH,
               timeout=REQUEST_TIMEOUT, respect_robots=True, seed_html=None,
               extra_headers=None, cookies=None):
    """
    Rastreia o site mantendo-se na mesma origem (esquema + host + porta).

    Retorna as páginas com o HTML em memória para que os scanners possam
    reaproveitar o conteúdo sem baixar de novo.
    Suporta autenticação com extra_headers e cookies.
    """
    try:
        max_pages = max(1, min(int(max_pages), 50))
        max_depth = max(0, min(int(max_depth), 5))
    except (TypeError, ValueError):
        max_pages, max_depth = DEFAULT_MAX_PAGES, DEFAULT_MAX_DEPTH

    start = normalize_url(target_url)
    pages = []
    errors = []
    robots = _load_robots(start, timeout) if respect_robots else None

    queue = deque([(start, 0, seed_html)])
    seen = {start}

    req_headers = {"User-Agent": USER_AGENT}
    if extra_headers and isinstance(extra_headers, dict):
        req_headers.update(extra_headers)

    while queue and len(pages) < max_pages:
        url, depth, html = queue.popleft()

        if html is None:
            if robots is not None and not robots.can_fetch(USER_AGENT, url):
                errors.append({"url": url, "error": "bloqueado por robots.txt"})
                continue
            try:
                response = requests.get(
                    url,
                    timeout=timeout,
                    headers=req_headers,
                    cookies=cookies,
                    allow_redirects=True,
                )
            except Exception as exc:
                errors.append({"url": url, "error": str(exc)[:160]})
                continue

            status = response.status_code
            content_type = (response.headers.get("Content-Type") or "").lower()
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                continue
            if status >= 400:
                pages.append({
                    "url": url, "final_url": normalize_url(response.url), "status": status,
                    "depth": depth, "title": "", "html": "", "forms": 0, "links": 0,
                })
                continue
            html = response.text
        else:
            status = 200

        html = html or ""
        pages.append({
            "url": url,
            "final_url": url,
            "status": status,
            "depth": depth,
            "title": extract_title(html),
            "html": html,
            "forms": len(re.findall(r"<form\b", html, re.IGNORECASE)),
            "links": len(extract_links(url, html)),
        })

        if depth >= max_depth:
            continue

        for link in extract_links(url, html):
            if link in seen:
                continue
            seen.add(link)
            queue.append((link, depth + 1, None))

    return {
        "start_url": start,
        "pages": pages,
        "total": len(pages),
        "truncated": bool(queue),
        "errors": errors,
    }


def crawl_summary(result):
    """Versão sem HTML, segura para enviar ao navegador."""
    pages = []
    for page in result.get("pages", []):
        pages.append({
            "url": page["url"],
            "status": page["status"],
            "depth": page["depth"],
            "title": page["title"],
            "forms": page["forms"],
            "links": page["links"],
        })
    return {
        "start_url": result.get("start_url", ""),
        "total": result.get("total", len(pages)),
        "truncated": result.get("truncated", False),
        "errors": result.get("errors", []),
        "pages": pages,
    }
