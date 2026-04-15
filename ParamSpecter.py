#!/usr/bin/env python3
"""
ParamSpecter - Advanced Recon Crawler for Bug Bounty & Security Research
For authorized and educational use only
"""

import requests
import re
import sys
import json
import csv
import time
import argparse
import threading
import queue
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser
from datetime import datetime
from collections import defaultdict

SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|apikey|token|secret)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{8,}'),
    re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'),
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS keys
]
# ─────────────────────────────────────────────────────────────
#  ANSI COLORS
# ─────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def color(text, *codes):
    return "".join(codes) + str(text) + C.RESET

# ─────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────
BANNER = f"""
{C.RED}{C.BOLD}
  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗███████╗██████╗ ███████╗███████╗████████╗███████╗██████╗ 
  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝███████║██████╔╝███████║██╔████╔██║█████╗  ██████╔╝█████╗  █████╗     ██║   █████╗  ██████╔╝
  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══╝  ██╔══╝     ██║   ██╔══╝  ██╔══██╗
  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║███████╗███████╗   ██║   ███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}{C.GRAY}  ParamSpecter - Advanced Recon Crawler for Bug Bounty & Security Research
{C.RED}{'─'*90}{C.RESET}
"""

# ─────────────────────────────────────────────────────────────
#  PATTERNS
# ─────────────────────────────────────────────────────────────
PATTERNS = {
    "email":     re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I),
    "phone":     re.compile(r"(?:\+?\d[\d\s\-().]{7,}\d)"),
    "ipv4":      re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "subdomain": re.compile(r"https?://([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+)", re.I),
    "comment":   re.compile(r"<!--(.*?)-->", re.DOTALL),
    "js_url":    re.compile(r"""(?:['"`])(https?://[^\s'"`<>]+)(?:['"`])"""),
    "aws_key":   re.compile(r"AKIA[0-9A-Z]{16}"),
    "api_key":   re.compile(r"""(?:api[_\-]?key|apikey|token|secret)['\"]?\s*[:=]\s*['\"a-zA-Z0-9\-_]{8,}""", re.I),
}

SOCIAL_DOMAINS = {"facebook.com","twitter.com","x.com","linkedin.com","instagram.com",
                  "github.com","youtube.com","tiktok.com","t.me","discord.gg"}

TECH_SIGNATURES = {
    "WordPress":      [re.compile(r"wp-content|wp-includes|WordPress", re.I)],
    "Joomla":         [re.compile(r"Joomla|/components/com_", re.I)],
    "Drupal":         [re.compile(r"Drupal|/sites/default/files", re.I)],
    "React":          [re.compile(r"react(?:\.min)?\.js|__REACT|_reactRootContainer", re.I)],
    "Angular":        [re.compile(r"ng-version|angular(?:\.min)?\.js", re.I)],
    "Vue":            [re.compile(r"vue(?:\.min)?\.js|__vue__", re.I)],
    "jQuery":         [re.compile(r"jquery(?:\.min)?\.js|jQuery", re.I)],
    "Bootstrap":      [re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I)],
    "Cloudflare":     [re.compile(r"cloudflare|cf-ray", re.I)],
    "AWS":            [re.compile(r"amazonaws\.com|x-amz-", re.I)],
    "PHP":            [re.compile(r"\.php|X-Powered-By: PHP", re.I)],
    "ASP.NET":        [re.compile(r"__VIEWSTATE|ASP\.NET|X-Powered-By: ASP", re.I)],
    "Django":         [re.compile(r"csrfmiddlewaretoken|Django", re.I)],
    "Laravel":        [re.compile(r"laravel_session|Laravel", re.I)],
    "Nginx":          [re.compile(r"nginx", re.I)],
    "Apache":         [re.compile(r"Apache", re.I)],
}

WAF_SIGNATURES = {
    "Cloudflare WAF": re.compile(r"cloudflare|cf-ray|__cfduid|attention required", re.I),
    "Sucuri WAF":     re.compile(r"sucuri|cloudproxy", re.I),
    "ModSecurity":    re.compile(r"mod_security|modsecurity|NOYB", re.I),
    "Incapsula":      re.compile(r"incapsula|visid_incap", re.I),
    "Akamai":         re.compile(r"akamai|akamaighhost", re.I),
    "Barracuda":      re.compile(r"barracuda", re.I),
}

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)

# ─────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────
def normalize_url(url, parent=""):
    try:
        full = urljoin(parent, url)
        p = urlparse(full)
        clean = urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/",
                            "", "", ""))
        return clean if p.scheme in ("http", "https") else None
    except Exception:
        return None

def status_color(code):
    if code is None:
        return color("ERR", C.RED)
    if code < 300:
        return color(code, C.GREEN)
    if code < 400:
        return color(code, C.YELLOW)
    if code < 500:
        return color(code, C.RED)
    return color(code, C.RED, C.BOLD)

def log(prefix, msg, col=C.WHITE):
    ts = color(datetime.now().strftime("%H:%M:%S"), C.GRAY)
    print(f"  {ts}  {color(prefix, col)}  {msg}")

# ─────────────────────────────────────────────────────────────
#  ROBOTS.TXT HANDLER
# ─────────────────────────────────────────────────────────────
class RobotsTxtChecker:
    def __init__(self, base_url, ua):
        self.rp = RobotFileParser()
        robots_url = urljoin(base_url, "/robots.txt")
        self.rp.set_url(robots_url)
        self.ua = ua
        self.disallowed_paths = []
        self.sitemaps = []
        try:
            self.rp.read()
            resp = requests.get(robots_url, timeout=8, headers={"User-Agent": ua})
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            self.disallowed_paths.append(path)
                    elif line.lower().startswith("sitemap:"):
                        self.sitemaps.append(line.split(":", 1)[1].strip())
        except Exception:
            pass

    def allowed(self, url):
        try:
            return self.rp.can_fetch(self.ua, url)
        except Exception:
            return True

# ─────────────────────────────────────────────────────────────
#  PER-PAGE ANALYSIS
# ─────────────────────────────────────────────────────────────
def analyze_page(url, resp, soup, raw_html):
    data = {
        "url":            url,
        "status":         resp.status_code,
        "content_type":   resp.headers.get("Content-Type", ""),
        "server":         resp.headers.get("Server", ""),
        "redirect_chain": [r.url for r in resp.history] if resp.history else [],
        "title":          "",
        "meta_desc":      "",
        "links":          [],
        "external_links": [],
        "social_links":   [],
        "emails":         [],
        "phones":         [],
        "ips":            [],
        "subdomains":     [],
        "js_urls":        [],
        "html_comments":  [],
        "forms":          [],
        "input_fields":   [],
        "sensitive_hints":[],
        "technologies":   [],
        "waf":            [],
        "secrets":        [],
        "cookies":        dict(resp.cookies),
        "security_headers": {},
    }
    # ────────────────
    # JS FILE EXTRACTION
    # ────────────────
    js_files = re.findall(r'<script.*?src=["\'](.*?)["\']', raw_html, re.I)
    data["js_urls"] = list(set(js_files))
    
    
    # ────────────────
    # JS ENDPOINT EXTRACTION
    # ────────────────
    endpoints = re.findall(r'/api/[a-zA-Z0-9_/.-]+', raw_html)
    data["js_endpoints"] = list(set(endpoints))

    # ────────────────
    #  DEEP JS ANALYSIS (DOWNLOAD + SCAN)
    # ────────────────
    deep_endpoints = set()
    found_secrets  = set()
    for js in data["js_urls"]:
        try:
            # Convert relative → absolute
            js_full = urljoin(url, js)
    
            js_resp = requests.get(js_full, timeout=5)
            js_content = js_resp.text
    
            # Extract endpoints from JS files
            endpoints = re.findall(r'/(api|v1|v2|admin|auth)[a-zA-Z0-9_/.-]*', js_content)
            for e in endpoints:
                deep_endpoints.add(e)
            # Extract secrets
            for pattern in SECRET_PATTERNS:
                matches = pattern.findall(js_content)
                for m in matches:
                    if isinstance(m, tuple):
                        m = "".join(m)
                    found_secrets.add(m)
        except:
            continue
    data["js_endpoints"].extend(list(deep_endpoints))
    data["js_endpoints"] = list(set(data["js_endpoints"]))

    data["secrets"] = list(found_secrets)
    
    # Title / meta
    if soup:
        t = soup.find("title")
        if t:
            data["title"] = t.get_text(strip=True)
        m = soup.find("meta", attrs={"name": re.compile("description", re.I)})
        if m:
            data["meta_desc"] = m.get("content", "")

    # Security headers
    SEC_HEADERS = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
        "X-XSS-Protection", "X-Powered-By"
    ]
    for h in SEC_HEADERS:
        val = resp.headers.get(h)
        if val:
            data["security_headers"][h] = val

    # Links
    if soup:
        base_domain = urlparse(url).netloc
        for tag in soup.find_all("a", href=True):
            norm = normalize_url(tag["href"], url)
            if norm:
                if urlparse(norm).netloc == base_domain:
                    data["links"].append(norm)
                else:
                    data["external_links"].append(norm)
                    if any(sd in norm for sd in SOCIAL_DOMAINS):
                        data["social_links"].append(norm)

    # Regex extractions on raw HTML
    data["emails"]    = list(set(PATTERNS["email"].findall(raw_html)))
    data["phones"]    = list(set(PATTERNS["phone"].findall(raw_html)))
    data["ips"]       = list(set(PATTERNS["ipv4"].findall(raw_html)))
    data["subdomains"]= list(set(PATTERNS["subdomain"].findall(raw_html)))
    data["js_urls"]   = list(set(PATTERNS["js_url"].findall(raw_html)))

    # HTML comments
    comments = PATTERNS["comment"].findall(raw_html)
    data["html_comments"] = [c.strip() for c in comments if c.strip()]

    # Sensitive hints
    if PATTERNS["aws_key"].search(raw_html):
        data["sensitive_hints"].append("Possible AWS Access Key found")
    if PATTERNS["api_key"].search(raw_html):
        data["sensitive_hints"].append("Possible API key / secret found")

    # Forms + input fields
    if soup:
        for form in soup.find_all("form"):
            action  = form.get("action", "")
            method  = form.get("method", "GET").upper()
            enctype = form.get("enctype", "")
            inputs  = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "tag":   inp.name,
                    "name":  inp.get("name", ""),
                    "type":  inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            data["forms"].append({
                "action": action, "method": method,
                "enctype": enctype, "inputs": inputs
            })
            data["input_fields"].extend(inputs)

    # Technology detection
    combined = raw_html + str(resp.headers)
    for tech, sigs in TECH_SIGNATURES.items():
        if any(sig.search(combined) for sig in sigs):
            data["technologies"].append(tech)

    # WAF detection
    waf_combined = str(resp.headers) + raw_html[:3000]
    for waf, sig in WAF_SIGNATURES.items():
        if sig.search(waf_combined):
            data["waf"].append(waf)

    return data

# ─────────────────────────────────────────────────────────────
#  MAIN CRAWLER
# ─────────────────────────────────────────────────────────────
class ParamSpecter:
    def __init__(self, args):
        self.start_url   = args.url.rstrip("/")
        self.max_pages   = args.max_pages
        self.delay       = args.delay
        self.depth       = args.depth
        self.threads     = args.threads
        self.timeout     = args.timeout
        self.same_domain = not args.follow_external
        self.respect_robots = not args.ignore_robots
        self.ua          = args.user_agent or DEFAULT_UA
        self.output      = args.output

        self.base_domain = urlparse(self.start_url).netloc
        self.session     = requests.Session()
        self.session.headers.update({"User-Agent": self.ua})

        # Thread-safe state
        self.visited      = set()
        self.visited_lock = threading.Lock()
        self.url_queue    = queue.Queue()
        self.url_queue.put((self.start_url, 0))  # (url, depth)
        self.results      = []
        self.results_lock = threading.Lock()
        self.page_count   = 0
        self.count_lock   = threading.Lock()

        # Aggregates
        self.all_emails    = set()
        self.all_phones    = set()
        self.all_links     = set()
        self.all_subdomains= set()
        self.all_techs     = set()
        self.all_wafs      = set()
        self.missing_sec_headers = defaultdict(int)

        # Robots.txt
        self.robots = None
        if self.respect_robots:
            log("ROBOTS", f"Fetching robots.txt ...", C.CYAN)
            self.robots = RobotsTxtChecker(self.start_url, self.ua)
            if self.robots.disallowed_paths:
                log("ROBOTS", f"Disallowed paths: {len(self.robots.disallowed_paths)}", C.YELLOW)
            if self.robots.sitemaps:
                log("ROBOTS", f"Sitemaps found: {', '.join(self.robots.sitemaps)}", C.CYAN)

        self.start_time = datetime.now()

    # ── fetch ─────────────────────────────────
    def fetch(self, url):
        try:
            resp = self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True, stream=False)
            return resp
        except requests.RequestException as e:
            return None

    # ── worker ────────────────────────────────
    def worker(self):
        while True:
            try:
                url, depth = self.url_queue.get(timeout=3)
            except queue.Empty:
                break

            with self.count_lock:
                if self.page_count >= self.max_pages:
                    self.url_queue.task_done()
                    break
                self.page_count += 1
                count = self.page_count

            with self.visited_lock:
                if url in self.visited:
                    self.url_queue.task_done()
                    continue
                self.visited.add(url)

            # Robots check
            if self.robots and not self.robots.allowed(url):
                log("SKIP ", f"{url}", C.GRAY)
                self.url_queue.task_done()
                continue

            resp = self.fetch(url)

            if resp is None:
                log(f"[{count:>4}]", f"{color('FAIL', C.RED)}  {url}", C.RED)
                with self.results_lock:
                    self.results.append({
                        "url": url, "status": None, "error": "Request failed"
                    })
                self.url_queue.task_done()
                continue

            content_type = resp.headers.get("Content-Type", "")
            raw_html = ""
            soup = None

            if "text/html" in content_type:
                try:
                    raw_html = resp.text
                    soup = BeautifulSoup(raw_html, "html.parser")
                except Exception:
                    pass

            page_data = analyze_page(url, resp, soup, raw_html)
            
            # print secrets
            if page_data.get("secrets"):
                log("     ", f"Secrets found: {len(page_data['secrets'])}", C.RED)
            print(
                f"  {color(datetime.now().strftime('%H:%M:%S'), C.GRAY)}  "
                f"{color(f'[{count:>4}]', C.CYAN)}  "
                f"{status_color(resp.status_code)}  "
                f"{color(url[:80], C.WHITE)}"
            )

            if page_data["emails"]:
                log("     +", f"Emails: {color(', '.join(page_data['emails']), C.GREEN)}", C.GRAY)
            if page_data["sensitive_hints"]:
                for hint in page_data["sensitive_hints"]:
                    log("     !", color(hint, C.RED, C.BOLD), C.RED)
            if page_data["waf"]:
                log("     W", f"WAF: {color(', '.join(page_data['waf']), C.YELLOW)}", C.GRAY)
            if page_data["forms"]:
                log("     F", f"Forms: {len(page_data['forms'])} found | Inputs: {len(page_data['input_fields'])}", C.GRAY)

            # Aggregates
            with self.results_lock:
                self.results.append(page_data)
                self.all_emails.update(page_data["emails"])
                self.all_phones.update(page_data["phones"])
                self.all_links.update(page_data["links"])
                self.all_subdomains.update(page_data["subdomains"])
                self.all_techs.update(page_data["technologies"])
                self.all_wafs.update(page_data["waf"])

            # Queue new URLs
            if depth < self.depth and "text/html" in content_type:
                for link in page_data["links"]:
                    # PARAM DETECTION
                    if "?" in link and "=" in link:
                        log("     P", f"Param found: {color(link, C.YELLOW)}", C.YELLOW)
                        
                    with self.visited_lock:
                        if link not in self.visited:
                            if not self.same_domain or urlparse(link).netloc == self.base_domain:
                                self.url_queue.put((link, depth + 1))

            time.sleep(self.delay)
            self.url_queue.task_done()

    # ── run ───────────────────────────────────
    def run(self):
        workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            workers.append(t)

        # Wait until queue is drained or max pages hit
        self.url_queue.join()

        for t in workers:
            t.join(timeout=1)

        self.print_summary()
        self.save_results()

    # ── summary ───────────────────────────────
    def print_summary(self):
        duration = (datetime.now() - self.start_time).seconds
        print(f"\n{color('='*90, C.RED)}")
        print(color(f"  CRAWL COMPLETE", C.BOLD + C.WHITE))
        print(color('='*90, C.RED))

        stats = [
            ("Target",         self.start_url),
            ("Pages crawled",  len(self.results)),
            ("Links found",    len(self.all_links)),
            ("Emails found",   len(self.all_emails)),
            ("Phones found",   len(self.all_phones)),
            ("Subdomains",     len(self.all_subdomains)),
            ("Technologies",   ", ".join(self.all_techs) if self.all_techs else "None detected"),
            ("WAF detected",   ", ".join(self.all_wafs) if self.all_wafs else "None"),
            ("Duration",       f"{duration}s"),
        ]
        for label, val in stats:
            print(f"  {color(label+':',C.CYAN):<30} {val}")

        # HTTP status breakdown
        status_counts = defaultdict(int)
        for r in self.results:
            status_counts[r.get("status") or "Error"] += 1

        print(f"\n  {color('HTTP Status Breakdown:', C.CYAN)}")
        for code in sorted(status_counts, key=lambda x: str(x)):
            bar = "#" * status_counts[code]
            print(f"    {status_color(code)}  {bar}  ({status_counts[code]})")

        if self.all_emails:
            print(f"\n  {color('Emails:', C.CYAN)}")
            for e in sorted(self.all_emails):
                print(f"    {color(e, C.GREEN)}")

        if self.all_phones:
            print(f"\n  {color('Phone Numbers:', C.CYAN)}")
            for p in sorted(self.all_phones):
                print(f"    {p.strip()}")

        # Missing security headers summary
        missing = defaultdict(int)
        important = ["Strict-Transport-Security", "Content-Security-Policy",
                     "X-Frame-Options", "X-Content-Type-Options"]
        for r in self.results:
            if "security_headers" in r:
                for h in important:
                    if h not in r.get("security_headers", {}):
                        missing[h] += 1
        if missing:
            print(f"\n  {color('Missing Security Headers (pages affected):', C.YELLOW)}")
            for h, count in missing.items():
                print(f"    {color(h, C.RED)}: {count} page(s)")

        print(f"{color('='*90, C.RED)}\n")

    # ── save ──────────────────────────────────
    def save_results(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_safe = self.base_domain.replace(".", "_")

        if self.output in ("json", "both"):
            fname = f"hellcrawler_{domain_safe}_{ts}.json"
            out = {
                "meta": {
                    "target":        self.start_url,
                    "crawled_at":    self.start_time.isoformat(),
                    "total_pages":   len(self.results),
                    "emails":        list(self.all_emails),
                    "phones":        list(self.all_phones),
                    "subdomains":    list(self.all_subdomains),
                    "technologies":  list(self.all_techs),
                    "waf":           list(self.all_wafs),
                },
                "pages": self.results
            }
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, ensure_ascii=False)
            log("SAVED", f"JSON -> {fname}", C.GREEN)

        if self.output in ("csv", "both"):
            fname = f"hellcrawler_{domain_safe}_{ts}.csv"
            fields = ["url","status","title","server","technologies","waf",
                      "emails","phones","ips","subdomains","forms",
                      "html_comments","sensitive_hints","redirect_chain",
                      "social_links","security_headers"]
            with open(fname, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for r in self.results:
                    row = dict(r)
                    for key in ["emails","phones","ips","subdomains","technologies",
                                "waf","html_comments","sensitive_hints",
                                "redirect_chain","social_links"]:
                        if isinstance(row.get(key), list):
                            row[key] = " | ".join(str(i) for i in row[key])
                    row["forms"] = len(r.get("forms", []))
                    row["security_headers"] = str(r.get("security_headers", {}))
                    writer.writerow(row)
            log("SAVED", f"CSV  -> {fname}", C.GREEN)

# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────
def main():
    print(BANNER + " v1.0\n")

    parser = argparse.ArgumentParser(
        description="ParamSpecter - Advanced recon crawler for bug bounty and security research"
    )
    parser.add_argument("url",                  help="Target URL (e.g. https://example.com)")
    parser.add_argument("-m","--max-pages",     type=int,   default=50,    help="Max pages to crawl (default: 50)")
    parser.add_argument("-d","--delay",         type=float, default=0.8,   help="Delay between requests in seconds (default: 0.8)")
    parser.add_argument("-D","--depth",         type=int,   default=3,     help="Max crawl depth (default: 3)")
    parser.add_argument("-t","--threads",       type=int,   default=5,     help="Number of threads (default: 5)")
    parser.add_argument("--timeout",            type=int,   default=10,    help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o","--output",        choices=["json","csv","both"], default="both", help="Output format")
    parser.add_argument("--follow-external",    action="store_true",       help="Follow links to external domains")
    parser.add_argument("--ignore-robots",      action="store_true",       help="Ignore robots.txt restrictions")
    parser.add_argument("-u","--user-agent",    default=None,              help="Custom user-agent string")

    args = parser.parse_args()

    print(f"  {color('WARNING:', C.RED+C.BOLD)} Only crawl targets you own or have written authorization to test.\n")
    print(f"  {color('Target   :', C.CYAN)} {args.url}")
    print(f"  {color('Max pages:', C.CYAN)} {args.max_pages}")
    print(f"  {color('Depth    :', C.CYAN)} {args.depth}")
    print(f"  {color('Threads  :', C.CYAN)} {args.threads}")
    print(f"  {color('Delay    :', C.CYAN)} {args.delay}s")
    print(f"  {color('Robots   :', C.CYAN)} {'respected' if not args.ignore_robots else 'ignored'}")
    print(f"\n{color('='*90, C.RED)}\n")

    crawler = ParamSpecter(args)
    crawler.run()


if __name__ == "__main__":
        main()#!/usr/bin/env python3

  
