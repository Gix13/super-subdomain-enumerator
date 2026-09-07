#!/usr/bin/env python3
from subprocess import TimeoutExpired
import argparse
import os
import subprocess
import datetime
import json
import requests
import time
import random
import shutil
from urllib.parse import urlparse

# active/passive switch for vuln stages
ACTIVE_MODE = False

# ---- logging first, so helpers can use it
def debug(msg):
    print(f"[DEBUG] {msg}")

def run_cmd(cmd, *, stdout=None, stderr=None, timeout=None, cwd=None, check=True):
    debug(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, stdout=stdout, stderr=stderr, timeout=timeout, cwd=cwd, check=check)

def safe_name(s):
    return s.replace('/', '_').replace(':', '_')

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


def _wayback_fetch_urls_for_domain(domain, max_retries=5):
    """
    Pull archived URLs for domain and subdomains via Wayback CDX.
    Tries JSON first, then falls back to plain-text parsing.
    Returns a set of absolute URLs.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (SuperSubEnumTool/paramspider-shim)"})

    patterns = [f"{domain}/*", f"*.{domain}/*"]
    urls = set()

    def _fetch_json(pat):
        params = {
            "url": pat,
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
        }
        for attempt in range(1, max_retries + 1):
            try:
                r = session.get("https://web.archive.org/cdx/search/cdx", params=params, timeout=30)
                if r.status_code in (429, 503):
                    wait = min(30, 2 ** attempt + random.random())
                    debug(f"CDX rate/slow ({r.status_code}) for {pat}. Sleeping {wait:.1f}s (try {attempt}/{max_retries})")
                    time.sleep(wait); continue
                r.raise_for_status()
                data = r.json()
                for row in data:
                    if isinstance(row, list) and row:
                        u = row[0].strip()
                        if u.startswith("http://") or u.startswith("https://"):
                            urls.add(u)
                return True
            except Exception as e:
                if attempt == max_retries:
                    debug(f"CDX JSON fetch failed for {pat}: {e}")
        return False

    def _fetch_text(pat):
        # Fallback parser for default CDX format
        params = {"url": pat}
        for attempt in range(1, max_retries + 1):
            try:
                r = session.get("https://web.archive.org/cdx/search/cdx", params=params, timeout=30)
                if r.status_code in (429, 503):
                    wait = min(30, 2 ** attempt + random.random())
                    debug(f"CDX rate/slow ({r.status_code}) for {pat}. Sleeping {wait:.1f}s (try {attempt}/{max_retries})")
                    time.sleep(wait); continue
                r.raise_for_status()
                for line in r.text.splitlines():
                    parts = line.strip().split(maxsplit=6)
                    if len(parts) >= 3:
                        u = parts[2].strip()
                        if u.startswith("http://") or u.startswith("https://"):
                            urls.add(u)
                return
            except Exception as e:
                if attempt == max_retries:
                    debug(f"CDX text fetch failed for {pat}: {e}")

    for pat in patterns:
        if not _fetch_json(pat):
            _fetch_text(pat)

    return urls


class APIKeyRotator:
    def __init__(self, keys_file, pointer_file=None):
        self.keys_file = keys_file
        self.pointer_file = pointer_file or f"{keys_file}.pointer"
        self._load_keys()
        self._load_pointer()

    def _load_keys(self):
        with open(self.keys_file) as f:
            self.keys = [line.strip() for line in f if line.strip()]

    def _load_pointer(self):
        try:
            with open(self.pointer_file) as pf:
                idx = int(pf.read().strip())
                self.index = idx if 0 <= idx < len(self.keys) else 0
        except Exception:
            self.index = 0

    def _save_pointer(self):
        with open(self.pointer_file, 'w') as pf:
            pf.write(str(self.index))

    def get_key(self):
        if not self.keys:
            raise ValueError(f"No API keys found in {self.keys_file}")
        return self.keys[self.index]

    def rotate_key(self):
        self.index = (self.index + 1) % len(self.keys)
        self._save_pointer()
        return self.get_key()

# Initialize key rotators (they will auto-persist pointers)
try:
    shodan_rotator = APIKeyRotator(os.path.join(SCRIPT_DIR, 'shodan_keys.txt'))
except FileNotFoundError:
    debug("shodan_keys.txt not found; Shodan enumeration will be skipped")
    shodan_rotator = None

try:
    censys_rotator = APIKeyRotator(os.path.join(SCRIPT_DIR, 'censys_keys.txt'))
except FileNotFoundError:
    debug("censys_keys.txt not found; Censys enumeration will be skipped")
    censys_rotator = None

LOCK_FILE = "/tmp/SuperSubdomainEnumerator_vpn.lock"

def make_output_dir(domain):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"{domain}_{timestamp}"
    os.makedirs(folder_name, exist_ok=True)
    return folder_name

def parse_and_save(file_path, cleaned_name, domain, output_dir):
    # (Enumerator helper) -> subdomains
    subdomains = set()
    with open(file_path, 'r', errors='ignore') as f:
        for line in f:
            try:
                host = urlparse(line.strip()).hostname
                if host and host.endswith(domain):
                    subdomains.add(host.lower())
            except Exception:
                continue
    cleaned_path = os.path.join(output_dir, cleaned_name)
    with open(cleaned_path, 'w') as outf:
        for sub in sorted(subdomains):
            outf.write(sub + "\n")
    debug(f"{cleaned_name} found {len(subdomains)} subdomains")
    return subdomains

def parse_urls_and_save(file_path, cleaned_name, output_dir):
    # (Crawler helper) -> full URLs (extract anywhere in the line)
    import re
    url_re = re.compile(r'https?://[^\s\'"<>)]+', re.IGNORECASE)

    urls = set()
    with open(file_path, 'r', errors='ignore') as f:
        for line in f:
            for u in url_re.findall(line):
                urls.add(u.strip())

    cleaned_path = os.path.join(output_dir, cleaned_name)
    with open(cleaned_path, 'w') as outf:
        for u in sorted(urls):
            outf.write(u + "\n")
    debug(f"{cleaned_name} collected {len(urls)} URLs")
    return urls


def append_urls_to_combined(urls, combined_urls_path):
    if not urls:
        return
    # Ensure file exists
    if not os.path.exists(combined_urls_path):
        with open(combined_urls_path, 'w') as _:
            pass
    # Load current
    with open(combined_urls_path, 'r', errors='ignore') as f:
        existing = {line.strip() for line in f if line.strip()}
    existing |= set(urls)
    with open(combined_urls_path, 'w') as f:
        for u in sorted(existing):
            f.write(u + "\n")


def save_combined_results(subdomains, domain, output_dir):
    """
    Deduplicate & persist discovered subdomains.
    Returns (final_set, path_to_file).
    """
    subs = set()
    for s in subdomains:
        if not s:
            continue
        s = s.strip().lower()
        # if a URL slipped in, normalize to hostname
        try:
            host = urlparse(s).hostname or s
        except Exception:
            host = s
        if host.endswith(domain):
            subs.add(host)

    out_path = os.path.join(output_dir, "combined_subdomains.txt")
    with open(out_path, "w") as f:
        for h in sorted(subs):
            f.write(h + "\n")
    return subs, out_path

# -------------------- ENUMERATORS --------------------

def run_crtsh(domain, output_dir, max_retries=5):
    debug(f"Running crt.sh enumeration for {domain}")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    debug(f"$ GET {url}")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; crtsh-enum/1.0)'})
    r = None
    for attempt in range(1, max_retries + 1):
        try:
            r = session.get(url, timeout=20)
            if r.status_code == 429:
                wait = 2 ** attempt + random.random()
                debug(f"Rate limited (429). Sleeping {wait:.1f}s before retry #{attempt}")
                time.sleep(wait)
                continue
            r.raise_for_status()
            break
        except requests.RequestException as e:
            if attempt == max_retries:
                debug(f"crt.sh request failed after {attempt} tries: {e}")
                return set()
            wait = 2 ** attempt + random.random()
            debug(f"crt.sh error: {e}. Retrying in {wait:.1f}s (#{attempt})")
            time.sleep(wait)
    if r is None:
        debug("crt.sh: no response received")
        return set()
    raw = r.text
    raw_path = os.path.join(output_dir, "crtsh_raw.json")
    with open(raw_path, 'w') as f:
        f.write(raw)
    subs = set()
    try:
        data = json.loads(raw)
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                n = name.strip().lstrip('*.')
                if n and n.endswith(domain): subs.add(n.lower())
    except Exception as e:
        debug(f"crt.sh parsing failed: {e}")
    cleaned = os.path.join(output_dir, "crtsh_cleaned.txt")
    with open(cleaned, 'w') as f:
        for s in sorted(subs): f.write(s + "\n")
    debug(f"crt.sh found {len(subs)} subdomains")
    return subs

def generic_tool(tool_name, cmd, out_name, domain, output_dir):
    debug(f"Running {tool_name} for {domain}")
    out_file = os.path.join(output_dir, out_name)
    err_file = os.path.join(output_dir, f"{tool_name.lower().replace(' ', '_')}_stderr.log")
    try:
        with open(out_file, 'w') as f, open(err_file, 'w') as ef:
            run_cmd(cmd, stdout=f, stderr=ef, timeout=300, check=True)
    except TimeoutExpired:
        debug(f"{tool_name} timed out after 300s; skipping")
        return set()
    except KeyboardInterrupt:
        debug(f"{tool_name} interrupted by user; skipping")
        return set()
    except Exception as e:
        debug(f"{tool_name} failed: {e}")
        return set()
    cleaned_name = os.path.splitext(out_name)[0].replace('_output', '') + '_cleaned.txt'
    return parse_and_save(out_file, cleaned_name, domain, output_dir)

def run_gau(domain, output_dir):
    return generic_tool('gau', ['gau', domain], 'gau_output.txt', domain, output_dir)

def run_wayback(domain, output_dir):
    return generic_tool('waybackurls', ['waybackurls', domain], 'wayback_output.txt', domain, output_dir)

def run_amass(domain, output_dir):
    # (kept for backward compatibility – passive)
    return generic_tool('amass', ['amass', 'enum', '-passive', '-d', domain], 'amass_output.txt', domain, output_dir)

def run_amass_passive(domain, output_dir):
    return generic_tool('amass_passive', ['amass', 'enum', '-passive', '-d', domain], 'amass_passive_output.txt', domain, output_dir)

def run_amass_active(domain, output_dir):
    # active enumerator
    return generic_tool('amass_active', ['amass', 'enum', '-active', '-d', domain], 'amass_active_output.txt', domain, output_dir)

def run_urlscan(domain, output_dir):
    # Requires API or CLI; using search endpoint
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    debug(f"$ GET {url}")
    out = os.path.join(output_dir, 'urlscan_output.json')
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        with open(out, 'w') as f: f.write(r.text)
    except Exception as e:
        debug(f"urlscan.io failed: {e}")
        return set()
    subs = set()
    try:
        data = json.loads(open(out).read())
        for res in data.get('results', []):
            page = res.get('page', {})
            host = urlparse(page.get('url','')).hostname
            if host and host.endswith(domain): subs.add(host.lower())
    except Exception as e:
        debug(f"urlscan.io parsing failed: {e}")
    return subs

def run_shodan(domain, output_dir):
    if not shodan_rotator or not shodan_rotator.keys:
        debug("No Shodan API keys found; skipping Shodan enumeration")
        return set()
    debug(f"Running Shodan for {domain}")
    subs, attempts = set(), 0
    while attempts < len(shodan_rotator.keys):
        key = shodan_rotator.get_key()
        url = f"https://api.shodan.io/dns/domain/{domain}"
        debug(f"$ GET {url}  (auth: shodan)")
        try:
            r = requests.get(url, params={"key": key}, timeout=30)
            r.raise_for_status()
            data = r.json()
            for sub in data.get('subdomains', []):
                subs.add(f"{sub}.{domain}".lower())
            break
        except requests.HTTPError as e:
            code = r.status_code
            if code == 403:
                debug("Shodan returned 403 Forbidden—your plan may not include this endpoint. Skipping Shodan.")
                break
            if code in (401, 429):
                debug(f"Shodan credential failed ({code}), rotating")
                shodan_rotator.rotate_key(); attempts += 1; continue
            debug(f"Shodan request failed with HTTP {code}")
            break
        except Exception as e:
            debug(f"Shodan request failed ({type(e).__name__})")
            break
    cleaned = os.path.join(output_dir, 'shodan_cleaned.txt')
    with open(cleaned, 'w') as f:
        for s in sorted(subs):
            f.write(s + "\n")
    debug(f"shodan_cleaned.txt found {len(subs)} subdomains")
    return subs

def run_censys(domain, output_dir):
    if not censys_rotator or not censys_rotator.keys:
        debug("No Censys API keys found; skipping Censys enumeration")
        return set()
    debug(f"Running Censys for {domain}")
    subs, attempts = set(), 0
    while attempts < len(censys_rotator.keys):
        key = censys_rotator.get_key()
        try:
            api_id, api_secret = key.split(':', 1)
        except ValueError:
            debug("Censys key malformed; expecting id:secret")
            break
        url = "https://search.censys.io/api/v1/search/certificates"
        params = {'q': f'parsed.names:{domain}', 'per_page': 100}
        debug(f"$ GET {url}  (auth: censys)")
        try:
            r = requests.get(url, auth=(api_id, api_secret), params=params, timeout=30)
            r.raise_for_status()
            for entry in r.json().get('results', []):
                for name in entry.get('parsed.names', []):
                    if name.endswith(domain):
                        subs.add(name.lower())
            break
        except requests.HTTPError as e:
            if r.status_code in (401, 429):
                debug(f"Censys credential failed ({r.status_code}), rotating")
                censys_rotator.rotate_key(); attempts += 1; continue
            debug(f"Censys request failed: {e}")
            break
        except Exception as e:
            debug(f"Censys error: {e}")
            break
    cleaned = os.path.join(output_dir, 'censys_cleaned.txt')
    with open(cleaned, 'w') as f:
        for s in sorted(subs):
            f.write(s + "\n")
    debug(f"censys_cleaned.txt found {len(subs)} subdomains")
    return subs

def run_dnsdumpster(domain, output_dir):
    debug(f"Running DNSDumpster for {domain}")
    subs = set()
    # First try: PaulSec client
    try:
        from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
        try:
            res = DNSDumpsterAPI().search(domain)
            for r in res.get('dns_records', {}).get('host', []):
                d = r.get('domain')
                if d and d.endswith(domain):
                    subs.add(d.lower())
            debug(f"DNSDumpster (PaulSec) yielded {len(subs)} subs")
        except Exception as e:
            debug(f"DNSDumpster (PaulSec) failed: {e}")
    except ImportError:
        debug("dnsdumpster client not installed; skipping PaulSec client")
    # Fallback: Node Playwright helper
    if not subs:
        import json as _json, os as _os
        script_path = "/opt/dnsdmpstr/dnsdumpster_playwright.js"
        if _os.path.exists(script_path):
            try:
                debug(f"$ node {script_path} {domain}")
                res = subprocess.run(
                    ["node", script_path, domain],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=120
                )
                if res.returncode == 0:
                    data = _json.loads(res.stdout or "{}")
                    for r in data.get("dns_records", {}).get("host", []):
                        d = r.get("domain", "")
                        if d.endswith(domain):
                            subs.add(d.lower())
                    debug(f"DNSDumpster (Playwright) yielded {len(subs)} subs")
                else:
                    debug(f"DNSDumpster (Playwright) error: {res.stderr.strip()}")
            except Exception as e:
                debug(f"DNSDumpster (Playwright) exception: {e}")
        else:
            debug(f"Playwright helper not found at {script_path}")
    cleaned = os.path.join(output_dir, 'dnsdumpster_cleaned.txt')
    with open(cleaned, 'w') as f:
        for s in sorted(subs): f.write(s + "\n")
    debug(f"dnsdumpster_cleaned.txt found {len(subs)} subdomains")
    return subs



def run_linkfinder(domain, output_dir):
    return generic_tool('LinkFinder', ['python3', '/opt/LinkFinder/linkfinder.py', '-i', f'https://{domain}', '-o', 'cli'] , 'linkfinder_output.txt', domain, output_dir)

def run_arjun(domain, output_dir):
    return generic_tool('arjun', ['arjun', '-u', f'https://{domain}'], 'arjun_output.txt', domain, output_dir)

def run_ffuf(domain, output_dir, wordlist):
    debug("Running ffuf")
    out_json = os.path.join(output_dir, 'ffuf_output.json')
    try:
        debug(f"$ ffuf -u http://FUZZ.{domain}/ -w {wordlist} -t 40 -H 'Host: FUZZ.{domain}' -mc 200,301,302,403,401 -fs 0 -o {out_json} -of json")
        subprocess.run(
            ['ffuf', '-u', f'http://FUZZ.{domain}/', '-w', wordlist,
             '-t', '40', '-H', f'Host: FUZZ.{domain}',
             '-mc', '200,301,302,403,401', '-fs', '0',
             '-o', out_json, '-of', 'json'],
            check=True, timeout=600
        )
    except TimeoutExpired:
        debug("ffuf timed out after 600s; skipping")
        return set()
    except Exception as e:
        debug(f"ffuf failed: {e}")
        return set()
    subs = set()
    try:
        with open(out_json) as f:
            data = json.load(f)
        for r in data.get('results', []):
            host = r.get('host') or urlparse(r.get('url', '')).hostname
            if host and host.endswith(domain):
                subs.add(host.lower())
    except Exception as e:
        debug(f"ffuf JSON parse error: {e}")
    cleaned = os.path.join(output_dir, 'ffuf_cleaned.txt')
    with open(cleaned, 'w') as f:
        for s in sorted(subs): f.write(s + "\n")
    debug(f"ffuf found {len(subs)} subdomains")
    return subs

def run_gospider(domain, output_dir):
    debug(f"Running gospider for {domain}")
    gospider_dir = os.path.join(output_dir, 'gospider_output')
    os.makedirs(gospider_dir, exist_ok=True)
    err_file = os.path.join(output_dir, 'gospider_stderr.log')
    try:
        with open(err_file, 'w') as ef:
            run_cmd(['gospider', '-s', f'https://{domain}', '-o', gospider_dir],
                    stdout=subprocess.DEVNULL, stderr=ef, timeout=300, check=True)
    except TimeoutExpired:
        debug("gospider timed out after 300s; skipping")
        return set()
    except Exception as e:
        debug(f"gospider failed: {e}")
        return set()
    import glob as _glob
    merged = os.path.join(output_dir, 'gospider_merged.txt')
    with open(merged, 'w') as out:
        for txt in _glob.glob(os.path.join(gospider_dir, '*')):
            try:
                with open(txt, 'r', errors='ignore') as f:
                    for line in f:
                        out.write(line)
            except Exception:
                continue
    return parse_and_save(merged, 'gospider_cleaned.txt', domain, output_dir)


def run_burp_spider(domain, output_dir):
    """
    Run Burp Suite Pro's spider headlessly, export the site map, and parse subdomains.
    Requires:
      - BURP_JAR_PATH env var pointing to burpsuite_pro.jar
      - Java 11+ installed
    """
    burp_jar = os.environ.get("BURP_JAR_PATH")
    if not burp_jar or not os.path.isfile(burp_jar):
        debug("Skipping Burp spider (BURP_JAR_PATH not set or file missing)")
        return set()
    debug(f"Running Burp spider for {domain}")
    project_file = os.path.join(output_dir, f"burp_{domain}.project")
    api_port = 1337
    export_json = os.path.join(output_dir, "burp_spider_export.json")
    cmd = [
        "java", "-Xmx2G", "-jar", burp_jar,
        "--project-file", project_file,
        "--spider-only",
        "--url", f"https://{domain}",
        "--api-listener", f"127.0.0.1:{api_port}"
    ]
    try:
        debug(f"$ {' '.join(cmd)}  (cwd={output_dir})")
        subprocess.run(cmd, cwd=output_dir, check=True, timeout=600)
    except TimeoutExpired:
        debug("Burp spider timed out after 600s")
        return set()
    except subprocess.CalledProcessError as e:
        debug(f"Burp spider failed: {e}")
        return set()
    try:
        debug(f"$ GET http://127.0.0.1:{api_port}/burp/spider/results")
        resp = requests.get(f"http://127.0.0.1:{api_port}/burp/spider/results", timeout=20)
        resp.raise_for_status()
        with open(export_json, "w") as f:
            f.write(resp.text)
    except Exception as e:
        debug(f"Failed to export Burp site map: {e}")
        return set()
    subs = set()
    try:
        data = json.loads(open(export_json).read())
        for entry in data.get("urls", []):
            host = urlparse(entry.get("url", "")).hostname
            if host and host.endswith(domain):
                subs.add(host.lower())
    except Exception:
        debug("Failed to parse Burp export JSON")
        return set()
    cleaned = os.path.join(output_dir, "burp_spider_cleaned.txt")
    with open(cleaned, "w") as f:
        for s in sorted(subs):
            f.write(s + "\n")
    debug(f"burp_spider_cleaned.txt found {len(subs)} subdomains")
    return subs

def run_zap_spider(domain, output_dir):
    return generic_tool('owasp zap spider', ['zap-cli', 'spider', f'https://{domain}'], 'zap_spider_output.txt', domain, output_dir)

def run_hakrawler(domain, output_dir):
    debug(f"Running hakrawler for {domain}")
    out_file = os.path.join(output_dir, 'hakrawler_output.txt')
    debug(f"$ echo https://{domain} | hakrawler -subs -insecure -u")
    try:
        with open(out_file, 'w') as f:
            echo = subprocess.Popen(
                ['echo', f'https://{domain}'],
                stdout=subprocess.PIPE
            )
            subprocess.run(
                ['hakrawler', '-subs', '-insecure', '-u'],
                stdin=echo.stdout,
                stdout=f,
                stderr=subprocess.PIPE,
                check=True,
                timeout=300
            )
            echo.stdout.close()
    except subprocess.CalledProcessError as e:
        debug(f"hakrawler error: {e.stderr.decode().strip()}")
        return set()
    except TimeoutExpired:
        debug("hakrawler timed out after 300s; skipping")
        return set()
    return parse_and_save(out_file, 'hakrawler_cleaned.txt', domain, output_dir)

def run_photon(domain, output_dir):
    photon_dir = os.path.join(output_dir, 'photon_output')
    os.makedirs(photon_dir, exist_ok=True)
    cmd = [
        'python3', '/opt/Photon/photon.py',
        '-u', f'https://{domain}',
        '-o', photon_dir
    ]
    try:
        debug(f"$ {' '.join(cmd)}")
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        debug(f"photon error: {e.stderr.decode().strip()}")
        return set()
    import glob
    candidates = glob.glob(os.path.join(photon_dir, '*.txt'))
    if not candidates:
        debug(f"photon subdomains file not found (tried {photon_dir}/*.txt)")
        return set()
    all_subs = set()
    for txt in candidates:
        with open(txt, 'r', errors='ignore') as fh:
            for line in fh:
                host = urlparse(line.strip()).hostname
                if host and host.endswith(domain):
                    all_subs.add(host.lower())
    cleaned_path = os.path.join(output_dir, 'photon_cleaned.txt')
    with open(cleaned_path, 'w') as f:
        for sub in sorted(all_subs):
            f.write(sub + "\n")
    debug(f"photon found {len(all_subs)} subdomains")
    return all_subs

def run_crawlee(target, output_dir):
    debug(f"Running Crawlee for {target}")
    crawlee_path = os.path.join(os.getcwd(), "crawlee")
    raw_output_file = os.path.join(crawlee_path, f"output_{target}.txt")
    final_output_file = os.path.join(output_dir, f"crawlee_crawl_{safe_name(target)}.txt")

    cmd = ["node", "crawler.js", f"https://{target}"]
    try:
        debug(f"$ {' '.join(cmd)}  (cwd={crawlee_path})")
        subprocess.run(cmd, cwd=crawlee_path, check=True)

        if os.path.exists(raw_output_file):
            # Move raw output for record
            try:
                shutil.copyfile(raw_output_file, final_output_file)
            except Exception:
                shutil.move(raw_output_file, final_output_file)
        else:
            debug("Crawlee did not produce an output file.")
            return set()

    except subprocess.CalledProcessError as e:
        debug(f"Crawlee failed: {e}")
        return set()

    # Crawlee outputs full URLs; parse them accordingly
    return parse_urls_and_save(final_output_file, f"crawlee_crawl_{safe_name(target)}_urls_cleaned.txt", output_dir)


def run_katana(domain, output_dir):
    return generic_tool('katana', ['katana', '-u', f'https://{domain}'], 'katana_output.txt', domain, output_dir)

import shutil as _shutil

def _exe_exists(name: str) -> bool:
    """Return True if an executable is available in PATH."""
    return _shutil.which(name) is not None

def _run_pipe_bash(cmd: str, out_path: str, err_path: str, timeout: int):
    """Run a shell pipeline, capture stdout/stderr to files, log and soft-fail."""
    debug(f'$ bash -c "{cmd}"')
    try:
        with open(out_path, "w") as f_out, open(err_path, "w") as f_err:
            subprocess.run(['bash', '-c', cmd], stdout=f_out, stderr=f_err, check=True, timeout=timeout)
        return True
    except Exception as e:
        debug(f"XSS: command failed/skipped: {e}")
        return False

# -------------------- XSS TOOL HELPERS --------------------

def _exe_exists_any(names):
    """Return (name_found, abs_path_or_none). Accepts a list of candidate names."""
    if isinstance(names, str):
        names = [names]
    for n in names:
        p = _shutil.which(n)
        if p:
            return n, p
    return None, None

def _xss_pipe(name, bins, cmd, outfile, errfile, timeout, active=False):
    """Run a 'cat ... | tool ...' style pipeline."""
    if active and not ACTIVE_MODE:
        debug(f"XSS: skipping {name} (active mode not selected)")
        return False
    found, _ = _exe_exists_any(bins)
    if not found:
        debug(f"XSS: skipping {name} (not found in PATH: {bins})")
        return False
    return _run_pipe_bash(cmd, outfile, errfile, timeout)

def _xss_exec(name, bins, argv_list, outfile, errfile, timeout, active=False):
    """Run a direct executable with argv (no pipe)."""
    if active and not ACTIVE_MODE:
        debug(f"XSS: skipping {name} (active mode not selected)")
        return False
    found, _ = _exe_exists_any(bins)
    if not found:
        debug(f"XSS: skipping {name} (not found in PATH: {bins})")
        return False
    debug("$ " + " ".join(argv_list))
    try:
        with open(outfile, "w") as f_out, open(errfile, "w") as f_err:
            subprocess.run(argv_list, stdout=f_out, stderr=f_err, check=True, timeout=timeout)
        return True
    except Exception as e:
        debug(f"XSS: {name} failed/skipped: {e}")
        return False

# -------------------- PASSIVE XSS METHODS --------------------

def xss_gf(candidates_file, output_dir):
    """GF (passive filter)"""
    return _xss_pipe(
        name="gf",
        bins="gf",
        cmd=f"cat {candidates_file} | gf xss",
        outfile=os.path.join(output_dir, "xss_passive_gf.txt"),
        errfile=os.path.join(output_dir, "xss_gf_stderr.log"),
        timeout=300,
        active=False,
    )

# -------------------- ACTIVE XSS METHODS --------------------

def xss_kxss(candidates_file, output_dir):
    """KXSS (active reflection finder)"""
    return _xss_pipe(
        name="kxss",
        bins="kxss",
        cmd=f"cat {candidates_file} | kxss",
        outfile=os.path.join(output_dir, "xss_kxss_reflections.txt"),
        errfile=os.path.join(output_dir, "xss_kxss_stderr.log"),
        timeout=600,
        active=True,
    )

def xss_gxss(candidates_file, output_dir):
    return _xss_pipe(
        name="gxss",
        bins=["Gxss", "gxss"],
        cmd=f"cat {candidates_file} | (command -v Gxss >/dev/null 2>&1 && Gxss -p FUZZ || gxss -p FUZZ)",
        outfile=os.path.join(output_dir, "xss_gxss_reflections.txt"),
        errfile=os.path.join(output_dir, "xss_gxss_stderr.log"),
        timeout=600,
        active=True,
    )

def xss_dalfox(candidates_file, output_dir):
    """Dalfox (active)"""
    return _xss_pipe(
        name="dalfox",
        bins="dalfox",
        cmd=f"cat {candidates_file} | dalfox pipe --no-color --silence",
        outfile=os.path.join(output_dir, "xss_dalfox_results.txt"),
        errfile=os.path.join(output_dir, "xss_dalfox_stderr.log"),
        timeout=1800,
        active=True,
    )

def xss_nuclei(candidates_file, output_dir):
    """Nuclei (active) with xss-tagged templates"""
    outpath = os.path.join(output_dir, "xss_nuclei_results.txt")
    return _xss_exec(
        name="nuclei-xss",
        bins="nuclei",
        argv_list=["nuclei", "-l", candidates_file, "-tags", "xss", "-o", outpath],
        outfile=outpath,
        errfile=os.path.join(output_dir, "xss_nuclei_stderr.log"),
        timeout=1800,
        active=True,
    )

def xss_xsstrike(candidates_file, output_dir):
    """
    XSStrike (active) — run one URL per process with xargs.
    Force non-interactive by piping 'n' to the continue prompt.
    """
    out = os.path.join(output_dir, "xss_xsstrike_results.txt")
    if _shutil.which("xsstrike"):
        cmd = (
            f"cat {candidates_file} | "
            f"xargs -n1 -P4 -I{{}} sh -c 'yes n | xsstrike -u \"$1\" || true' _ {{}}"
        )
        return _xss_pipe(
            name="xsstrike",
            bins="xsstrike",
            cmd=cmd,
            outfile=out,
            errfile=os.path.join(output_dir, "xss_xsstrike_stderr.log"),
            timeout=3600,
            active=True,
        )

    XSSTRIKE_PY = "/opt/XSStrike/xsstrike.py"  # optional fallback
    if os.path.exists(XSSTRIKE_PY) and _shutil.which("python3"):
        cmd = (
            f"cat {candidates_file} | "
            f"xargs -n1 -P4 -I{{}} sh -c 'yes n | python3 {XSSTRIKE_PY} -u \"$1\" || true' _ {{}}"
        )
        return _xss_pipe(
            name="xsstrike(py)",
            bins="python3",
            cmd=cmd,
            outfile=out,
            errfile=os.path.join(output_dir, "xss_xsstrike_stderr.log"),
            timeout=3600,
            active=True,
        )

    debug("XSS: skipping XSStrike (binary/script not found)")
    return False

def xss_xsser(candidates_file, output_dir):
    """
    XSSer (active)
    - Rewrite each URL so params contain XSS/X1S placeholders (what XSSer expects).
    - Run inside output_dir so XSSer's own report writes are permitted.
    - Capture a full raw log and a filtered hits file.
    """
    from urllib.parse import urlsplit, urlencode, parse_qsl

    raw = os.path.join(output_dir, "xss_xsser_raw.log")
    out = os.path.join(output_dir, "xss_xsser_results.txt")
    err = os.path.join(output_dir, "xss_xsser_stderr.log")

    if not _shutil.which("xsser"):
        debug("XSS: skipping XSSer (binary not found)")
        return False
    if not ACTIVE_MODE:
        debug("XSS: skipping XSSer (active mode not selected)")
        return False

    # Build a TSV of:  <base>\t<gstring>  (e.g., http://host   /path?param=XSS&num=X1S)
    tmp_tsv = os.path.join(output_dir, "xsser_targets.tsv")
    written = 0
    with open(candidates_file, "r", errors="ignore") as src, open(tmp_tsv, "w") as dst:
        for line in src:
            u = line.strip()
            if not u or "?" not in u or "=" not in u:
                continue
            try:
                sp = urlsplit(u)
                if not (sp.scheme and sp.netloc):
                    continue
                base = f"{sp.scheme}://{sp.netloc}"
                qs = parse_qsl(sp.query, keep_blank_values=True)
                new_qs = []
                for k, v in qs:
                    if v and v.isdigit():
                        new_qs.append((k, "X1S"))
                    else:
                        new_qs.append((k, "XSS"))
                new_query = urlencode(new_qs, doseq=True)
                gstring = sp.path or "/"
                if new_query:
                    gstring += "?" + new_query
                dst.write(base + "\t" + gstring + "\n")
                written += 1
            except Exception:
                continue

    if written == 0:
        debug("XSSer: no XSSer-friendly targets produced; skipping")
        return False

    # Run inside output_dir to avoid permission issues with XSSer's own report file.
    cmd = (
        f"cd '{output_dir}' && "
        f"while IFS=$'\\t' read -r base g; do "
        f"  echo \"=== XSSer $base$g ===\"; "
        f"  xsser --auto -u \"$base\" -g \"$g\" 2>&1 || true; "
        f"done < '{tmp_tsv}' "
        f"| tee 'xss_xsser_raw.log' "
        f"| grep -iE '(vuln|xss|payload|reflected|injected|successful)' || true"
    )

    return _run_pipe_bash(cmd, out, err, timeout=3600)

def run_xss(domain, output_dir):
    """
    XSS stage with passive + optional active checks (GF, KXSS, Gxss, Dalfox, Nuclei, XSStrike, XSSer).

    Inputs:
      - combined_urls.txt
    Outputs (in output_dir):
      - xss_candidates.txt
      - xss_passive_gf.txt
      - xss_kxss_reflections.txt
      - xss_gxss_reflections.txt
      - xss_dalfox_results.txt
      - xss_nuclei_results.txt
      - xss_xsstrike_results.txt
      - xss_xsser_results.txt
      - *_stderr.log
    """
    debug("Running XSS stage")

    combined_urls_path = os.path.join(output_dir, "combined_urls.txt")
    if not os.path.exists(combined_urls_path):
        debug("XSS: combined_urls.txt not found; nothing to scan")
        return set()

    # 1) Gather parameterized URLs
    candidates_file = os.path.join(output_dir, "xss_candidates.txt")
    urls = set()
    with open(combined_urls_path, 'r', errors='ignore') as f:
        for line in f:
            u = line.strip()
            if u.startswith("http") and "?" in u and "=" in u:
                urls.add(u)
    if not urls:
        debug("XSS: No parameterized URLs found")
        return set()
    with open(candidates_file, "w") as cf:
        for u in sorted(urls):
            cf.write(u + "\n")

    # 2) Passive
    xss_gf(candidates_file, output_dir)

    # 3) Active (each respects ACTIVE_MODE)
    xss_kxss(candidates_file, output_dir)
    xss_gxss(candidates_file, output_dir)
    xss_dalfox(candidates_file, output_dir)
    xss_nuclei(candidates_file, output_dir)
    xss_xsstrike(candidates_file, output_dir)
    xss_xsser(candidates_file, output_dir)

        # 4) Summary counts + list of files we'll combine
    report_files = [
        ("candidates", candidates_file),
        ("gf", os.path.join(output_dir, "xss_passive_gf.txt")),
        ("kxss", os.path.join(output_dir, "xss_kxss_reflections.txt")),
        ("gxss", os.path.join(output_dir, "xss_gxss_reflections.txt")),
        ("dalfox", os.path.join(output_dir, "xss_dalfox_results.txt")),
        ("nuclei", os.path.join(output_dir, "xss_nuclei_results.txt")),
        ("xsstrike", os.path.join(output_dir, "xss_xsstrike_results.txt")),
        ("xsser", os.path.join(output_dir, "xss_xsser_results.txt")),
    ]
    try:
        counts = []
        for name, path in report_files:
            if os.path.exists(path):
                with open(path, 'r', errors='ignore') as fh:
                    n = sum(1 for _ in fh if _.strip())
                counts.append(f"{name}:{n}")
        if counts:
            debug("XSS results summary -> " + ", ".join(counts))
    except Exception:
        pass

    # 5) Combined results file (tagged per source)
    try:
        combined_out = os.path.join(output_dir, "xss_results_combined.txt")
        seen = set()
        with open(combined_out, "w") as outf:
            for name, path in report_files:
                if not os.path.exists(path):
                    continue
                with open(path, "r", errors="ignore") as fh:
                    for line in fh:
                        s = line.strip()
                        if not s:
                            continue
                        key = (name, s)
                        if key in seen:
                            continue
                        seen.add(key)
                        outf.write(f"[{name}] {s}\n")
        debug(f"XSS combined file -> {combined_out} (lines: {len(seen)})")
    except Exception as e:
        debug(f"Failed to write xss_results_combined.txt: {e}")

    return set()


    # -------------------- SSRF STAGE (auto-OAST) --------------------
import secrets as _secrets
import atexit
import re

# Heuristic keys often involved in SSRF-y params
SSRF_KEYS = [
    "url","uri","dest","destination","redirect","redirect_uri","return","returnto","next",
    "target","to","callback","cb","continue","link","u","path","file","feed","data","source",
    "img","image","load","open","endpoint","download","proxy","fetch","remote","go","out"
]

# keep a handle to the interactsh client if we start it
_INTERACTSH_PROC = None

def _normalize_oast(u: str) -> str:
    """Ensure OAST URL is well-formed and actually looks like an OAST/collab host."""
    import re as _re
    u = (u or "").strip().rstrip("/")
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    host = urlparse(u).netloc or ""
    if not host:
        return ""
    if not _re.search(r"(oast|interact|collaborator|dnslog|burpcollaborator)", host, _re.I):
        debug(f"SSRF: rejected OAST_URL (doesn't look like an OAST host): {host}")
        return ""
    return u

def _oast_with_token(oast_url: str, token: str) -> str:
    """Append a short per-run token to the OAST path for easy correlation."""
    from urllib.parse import urlsplit, urlunsplit
    sp = urlsplit(oast_url)
    path = (sp.path.rstrip("/") + "/" + token) if sp.path else ("/" + token)
    return urlunsplit((sp.scheme, sp.netloc, path, sp.query, sp.fragment))

def _url_has_ssrfy_key(u: str) -> bool:
    """
    True if any query key looks SSRF-ish.
    Accepts exact, _suffix, -suffix, and plain suffix (camelCase like imageUrl).
    """
    try:
        from urllib.parse import urlsplit, parse_qsl
        sp = urlsplit(u)
        if not sp.query:
            return False
        for k, _ in parse_qsl(sp.query, keep_blank_values=True):
            kk = k.lower()
            for needle in SSRF_KEYS:
                if (
                    kk == needle or
                    kk.endswith(needle) or
                    kk.endswith("_"+needle) or
                    kk.endswith("-"+needle)
                ):
                    return True
    except Exception:
        pass
    return False

def _is_ssrfy_key(k: str) -> bool:
    kk = (k or "").lower()
    return any(
        kk == n or kk.endswith(n) or kk.endswith("_"+n) or kk.endswith("-"+n)
        for n in SSRF_KEYS
    )

def _python_qsreplace_line(u: str, new_value: str) -> str:
    """Set ONLY SSRF-ish query param values to new_value."""
    try:
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        sp = urlsplit(u)
        if not sp.query:
            return u
        pairs = parse_qsl(sp.query, keep_blank_values=True)
        new_qs = [(k, new_value if _is_ssrfy_key(k) else v) for k, v in pairs]
        return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(new_qs, doseq=True), sp.fragment))
    except Exception:
        return u

def _mutate_with_qsreplace(candidates_file, oast_base_url, output_dir):
    """
    Create per-URL OAST values: <oast_base>/<tag>, tag = sha1(url)[:8].
    Writes:
      - ssrf_mutated.txt
      - ssrf_mutation_map.tsv   (tag \t original \t mutated)
    """
    import hashlib
    mutated = os.path.join(output_dir, "ssrf_mutated.txt")
    map_tsv = os.path.join(output_dir, "ssrf_mutation_map.tsv")

    try:
        out = []
        seen = set()
        with open(candidates_file, "r", errors="ignore") as fh, open(map_tsv, "w") as mf:
            for line in fh:
                orig = line.strip()
                if not orig:
                    continue
                tag = hashlib.sha1(orig.encode("utf-8")).hexdigest()[:8]
                oast_value = f"{oast_base_url}/{tag}"
                mutated_url = _python_qsreplace_line(orig, oast_value)
                if mutated_url not in seen:
                    out.append(mutated_url)
                    seen.add(mutated_url)
                mf.write(f"{tag}\t{orig}\t{mutated_url}\n")

        with open(mutated, "w") as f:
            for u in sorted(out):
                f.write(u + "\n")
        return mutated, map_tsv
    except Exception as e:
        debug(f"qsreplace(fallback) failed: {e}")
        return None, None

def _iso_now_z():
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _parse_iso(s: str):
    import datetime as _dt
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return _dt.datetime.fromisoformat(s)
    except Exception:
        return None

def ssrf_gf(input_file, output_dir):
    """Passive gf filter (if installed)."""
    out = os.path.join(output_dir, "ssrf_passive_gf.txt")
    err = os.path.join(output_dir, "ssrf_gf_stderr.log")
    if _shutil.which("gf"):
        return _run_pipe_bash(f"cat '{input_file}' | gf ssrf", out, err, timeout=300)
    return False

def ssrf_unfurl_keys(input_file, output_dir):
    """
    If 'unfurl' is present, extract keys and grep SSRF-ish names.
    Python fallback emits a hits file, too.
    """
    hits = os.path.join(output_dir, "ssrf_unfurl_key_hits.txt")
    log  = os.path.join(output_dir, "ssrf_unfurl_stderr.log")

    if _shutil.which("unfurl"):
        keys_all = os.path.join(output_dir, "ssrf_unfurl_keys.txt")
        _run_pipe_bash(f"cat '{input_file}' | unfurl keys | sort -u", keys_all, log, timeout=120)
        needles = r"(?:^|_|-)(?:%s)(?:$)" % "|".join(SSRF_KEYS)
        _run_pipe_bash(f"grep -Ei '{needles}' '{keys_all}' | sort -u", hits, log, timeout=30)
        return True

    # Python fallback
    try:
        seen = set()
        from urllib.parse import urlsplit, parse_qsl
        with open(input_file, "r", errors="ignore") as fh:
            for line in fh:
                sp = urlsplit(line.strip())
                for k, _ in parse_qsl(sp.query or "", keep_blank_values=True):
                    kk = k.lower().strip()
                    if kk:
                        seen.add(kk)
        ssrfish = sorted({k for k in seen for needle in SSRF_KEYS
                          if k == needle or k.endswith(needle) or
                             k.endswith("_"+needle) or k.endswith("-"+needle)})
        with open(hits, "w") as f:
            for k in ssrfish: f.write(k + "\n")
        return True
    except Exception as e:
        debug(f"unfurl(fallback) failed: {e}")
        return False

def _build_ssrf_candidates(combined_urls_path, output_dir):
    """Build ssrf_candidates.txt from combined_urls.txt using heuristics + gf (if present)."""
    all_param = []
    try:
        with open(combined_urls_path, "r", errors="ignore") as fh:
            for line in fh:
                u = line.strip()
                if u.startswith("http") and "?" in u and "=" in u:
                    all_param.append(u)
    except FileNotFoundError:
        debug("SSRF: combined_urls.txt not found; nothing to scan")
        return None

    # Save all param URLs for reference
    all_param_path = os.path.join(output_dir, "ssrf_all_param_urls.txt")
    with open(all_param_path, "w") as f:
        for u in sorted(set(all_param)):
            f.write(u + "\n")

    # Heuristic filter
    cand = {u for u in all_param if _url_has_ssrfy_key(u)}

    # gf ssrf (if installed) as extra source
    if _shutil.which("gf"):
        tmp = os.path.join(output_dir, "ssrf_gf_tmp.txt")
        _run_pipe_bash(f"cat '{all_param_path}' | gf ssrf", tmp,
                       os.path.join(output_dir, "ssrf_gf_stderr.log"), timeout=300)
        try:
            with open(tmp, "r", errors="ignore") as fh:
                for line in fh:
                    u = line.strip()
                    if u:
                        cand.add(u)
        except Exception:
            pass

        # Fallback so we still actively probe if heuristics/gf found nothing
    if not cand and all_param:
        debug("SSRF: heuristic+gf found 0; falling back to ALL parameterized URLs for active probing")
        cand = set(all_param)

    # Write final candidates
    out = os.path.join(output_dir, "ssrf_candidates.txt")
    with open(out, "w") as f:
        for u in sorted(cand):
            f.write(u + "\n")


    # Helpful passive artifact
    ssrf_unfurl_keys(all_param_path, output_dir)
    debug(f"SSRF: candidates -> {out} (count: {len(cand)})")
    return out


def _run_httpx(mutated_file, output_dir):
    out = os.path.join(output_dir, "ssrf_httpx.json")
    if not _shutil.which("httpx"):
        debug("SSRF: httpx not found; skipping httpx probe")
        return None
    cmd = f"httpx -l '{mutated_file}' -silent -status-code -location -json -timeout 5 -threads 50"
    ok = _run_pipe_bash(cmd, out, os.path.join(output_dir, "ssrf_httpx_stderr.log"), timeout=1200)
    return out if ok else None

def _run_nuclei_ssrf(mutated_file, output_dir):
    if not _shutil.which("nuclei"):
        debug("SSRF: nuclei not found; skipping")
        return None
    out = os.path.join(output_dir, "ssrf_nuclei.jsonl")
    try:
        run_cmd(["nuclei", "-l", mutated_file, "-tags", "ssrf", "-jsonl", "-o", out],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
        return out
    except Exception as e:
        debug(f"nuclei(ssrf) failed: {e}")
        return None
def _find_ssrfmap():
    """
    Return a tuple (base_argv, label) where base_argv is the command prefix to run SSRFmap.
    Priority:
      1) 'ssrfmap' in PATH
      2) env SSRFMAP_PATH (binary or ssrfmap.py)
      3) common clone locations for ssrfmap.py
    """
    paths_py = [
        os.environ.get("SSRFMAP_PATH"),
        "/opt/SSRFmap/ssrfmap.py",
        "/usr/local/share/SSRFmap/ssrfmap.py",
        os.path.join(SCRIPT_DIR, "tools", "SSRFmap", "ssrfmap.py"),
    ]
    paths_bin = [
        shutil.which("ssrfmap"),  # if installed with a wrapper/binary
        os.environ.get("SSRFMAP_PATH")
    ]

    # binary first
    for p in paths_bin:
        if p and shutil.which(p):
            return ([p], "bin")

    # python script paths
    for p in paths_py:
        if p and os.path.exists(p):
            if p.endswith(".py"):
                return (["python3", p], "py")
            if shutil.which(p):
                return ([p], "bin")

    return (None, None)

def _run_ssrfmap(mutated_file, output_dir):
    """
    Build tiny raw GET requests from each mutated URL and run SSRFmap properly:
      ssrfmap -r <req.txt> -p <param> -m <modules> [--ssl]
    Pick SSRF-ish params using _is_ssrfy_key(). Tag output blocks so we can map
    hits back to original URLs later.
    """
    from urllib.parse import urlsplit, parse_qsl

    base_argv, label = _find_ssrfmap()
    if not base_argv:
        debug("SSRF: SSRFmap not found; set SSRFMAP_PATH or add 'ssrfmap' to PATH")
        return None

    # SSRFmap's correct module name is 'portscan'
    modules = (os.environ.get("SSRFMAP_MODULES") or "portscan").split(",")
    modules = [m.strip() for m in modules if m.strip()] or ["portscan"]

    out = os.path.join(output_dir, "ssrf_ssrfmap.txt")
    err = os.path.join(output_dir, "ssrf_ssrfmap_stderr.log")
    reqdir = os.path.join(output_dir, "ssrfmap_reqs")
    os.makedirs(reqdir, exist_ok=True)

    def _url_to_raw(u: str):
        sp = urlsplit(u)
        path_q = sp.path or "/"
        if sp.query:
            path_q += "?" + sp.query
        raw = (
            f"GET {path_q} HTTP/1.1\r\n"
            f"Host: {sp.netloc}\r\n"
            "User-Agent: SuperSubEnumTool/ssrfmap-bridge\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        return raw, (sp.scheme.lower() == "https")

    any_run = False
    idx = 0

    with open(out, "w") as outf, open(err, "w") as errf, open(mutated_file, "r", errors="ignore") as src:
        for line in src:
            u = line.strip()
            if not u:
                continue
            sp = urlsplit(u)
            params = [k for k, _ in parse_qsl(sp.query or "", keep_blank_values=True) if _is_ssrfy_key(k)]
            if not params:
                continue

            raw, is_https = _url_to_raw(u)
            req_path = os.path.join(reqdir, f"req_{idx}.txt"); idx += 1
            try:
                with open(req_path, "w") as rf:
                    rf.write(raw)
            except Exception as e:
                debug(f"SSRFmap: failed to write request file: {e}")
                continue

            for pname in params:
                argv = base_argv + ["-r", req_path, "-p", pname, "-m", ",".join(modules)]
                if is_https:
                    argv += ["--ssl"]

                # Marker so we can attribute output to this URL/param block
                outf.write(f"\n### SSRFMAP URL: {u} PARAM: {pname}\n")
                debug("$ " + " ".join(argv))
                try:
                    subprocess.run(argv, stdout=outf, stderr=errf, check=False, timeout=1800)
                    any_run = True
                except Exception as e:
                    debug(f"SSRFmap({pname}) failed/skipped: {e}")

    if not any_run:
        debug("SSRF: SSRFmap executed but produced no output")
        return None
    return out

def _summarize_httpx(httpx_json_path):
    if not httpx_json_path or not os.path.exists(httpx_json_path):
        return {}
    counts = {"total":0, "2xx":0, "3xx":0, "4xx":0, "5xx":0}
    try:
        with open(httpx_json_path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                counts["total"] += 1
                try:
                    obj = json.loads(line)
                    sc = int(obj.get("status-code", 0))
                    if   200 <= sc < 300: counts["2xx"] += 1
                    elif 300 <= sc < 400: counts["3xx"] += 1
                    elif 400 <= sc < 500: counts["4xx"] += 1
                    elif 500 <= sc < 600: counts["5xx"] += 1
                except Exception:
                    pass
    except Exception:
        pass
    return counts

def _collect_interactsh_since(oast_host: str, since_iso: str, output_dir: str):
    """
    Read interactsh NDJSON (env INTERACTSH_LOG or ./interactsh_hits.json),
    return hits for our host since the scan started (excluding /ping).
    """
    log_path = os.environ.get("INTERACTSH_LOG", "interactsh_hits.json")
    hits_out = os.path.join(output_dir, "ssrf_interactsh_hits_since.jsonl")
    found = []

    if not os.path.exists(log_path):
        debug(f"SSRF: interactsh log '{log_path}' not found; run \"interactsh-client -json -o {log_path}\" in parallel if you want hit counts")
        return 0

    t0 = _parse_iso(since_iso) or _parse_iso(_iso_now_z())

    try:
        import re as _re
        with open(log_path, "r", errors="ignore") as fh, open(hits_out, "w") as out:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                ts = _parse_iso(obj.get("timestamp", "")) or t0
                if ts < t0:
                    continue
                raw_req = obj.get("raw-request", "") or ""

                # Case-insensitive Host: match on its own line
                if not _re.search(rf"(?i)^host:\s*{_re.escape(oast_host)}\s*$", raw_req, _re.M):
                    continue

                if "/ping" in raw_req:
                    continue
                found.append(obj)
                out.write(line + "\n")
    except Exception:
        pass
    return len(found)

def _start_interactsh_client(log_path: str = "interactsh_hits.json") -> str:
    """
    Start interactsh-client and return the auto-generated OAST URL (https://<id>.<host>).
    Keeps the client running so hits are captured while scanning.
    """
    global _INTERACTSH_PROC
    if not _shutil.which("interactsh-client"):
        debug("SSRF: interactsh-client not found in PATH")
        return ""

    import os as _os, re as _re
    # Use an absolute path so readers pick up the same file later.
    log_path = _os.path.abspath(log_path)

    # -v ensures a "Listing URL/Domain:" banner on stdout across client versions.
    args = ["interactsh-client", "-json", "-o", log_path, "-v"]
    debug("$ " + " ".join(args))
    try:
        _INTERACTSH_PROC = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
    except Exception as e:
        debug(f"SSRF: failed to start interactsh-client: {e}")
        return ""

    domain = ""
    bootlog_path = "interactsh_bootstrap.log"
    # Accept either an explicit label or any oast-like FQDN
    pat_any   = _re.compile(r'([a-z0-9]{6,}\.[\w.-]*(?:oast|interact|collaborator|dnslog)[\w.-]*\.[a-z.]+)', _re.I)
    pat_label = _re.compile(r'(?:Listing URL|URL|Domain|DNS Domain|Registered|Server)\s*:\s*(?:https?://)?([^\s/]+)', _re.I)

    deadline = time.time() + 60.0  # give slower networks time
    try:
        with open(bootlog_path, "w") as bootlog:
            while time.time() < deadline and _INTERACTSH_PROC and _INTERACTSH_PROC.stdout:
                line = _INTERACTSH_PROC.stdout.readline()
                if not line:
                    if _INTERACTSH_PROC.poll() is not None:
                        break
                    time.sleep(0.05)
                    continue
                s = line.strip()
                bootlog.write(s + "\n")

                m = pat_label.search(s) or pat_any.search(s)
                if m:
                    candidate = m.group(1).strip().rstrip("/")
                    # leftmost label should have entropy (>=6 chars)
                    if candidate and len(candidate.split(".", 1)[0]) >= 6:
                        domain = candidate
                        break
    except Exception as e:
        debug(f"SSRF: error while parsing interactsh stdout: {e}")

    # Late parser: some builds print the banner after a chunked JSON line.
    if not domain:
        try:
            with open(bootlog_path, "r", errors="ignore") as bl:
                text = bl.read()
                m = pat_label.search(text) or pat_any.search(text)
                if m:
                    candidate = m.group(1).strip().rstrip("/")
                    if candidate and len(candidate.split(".", 1)[0]) >= 6:
                        domain = candidate
        except Exception:
            pass

    if not domain:
        debug("SSRF: interactsh started but no valid OAST domain detected; see interactsh_bootstrap.log")
        try:
            if _INTERACTSH_PROC and _INTERACTSH_PROC.poll() is None:
                _INTERACTSH_PROC.terminate()
        except Exception:
            pass
        _INTERACTSH_PROC = None
        return ""

    os.environ["INTERACTSH_LOG"] = log_path  # export absolute path
    url = "https://" + domain
    debug(f"SSRF: interactsh auto-OAST -> {url}")
    return url

def _stop_interactsh_client():
    global _INTERACTSH_PROC
    try:
        if _INTERACTSH_PROC and _INTERACTSH_PROC.poll() is None:
            _INTERACTSH_PROC.terminate()
    except Exception:
        pass
    _INTERACTSH_PROC = None

atexit.register(_stop_interactsh_client)

def _load_map_tsv(map_tsv):
    tag2orig = {}
    mutated2orig = {}
    try:
        with open(map_tsv, "r", errors="ignore") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 3:
                    tag, orig, mutated = parts[0], parts[1], parts[2]
                    tag2orig[tag] = orig
                    mutated2orig[mutated] = orig
    except Exception:
        pass
    return tag2orig, mutated2orig

def _extract_tag_from_raw_request(raw_request, tag_keys):
    try:
        line0 = (raw_request or "").splitlines()[0]
        import re
        candidates = re.findall(r"/([0-9a-f]{8})(?:[\W/]|$)", line0, flags=re.IGNORECASE)
        for c in candidates:
            c = c.lower()
            if c in tag_keys:
                return c
    except Exception:
        pass
    return None

def _collect_interactsh_hits_to_urls(output_dir, tag2orig):
    log_path = os.environ.get("INTERACTSH_LOG", "interactsh_hits.json")
    out_urls = os.path.join(output_dir, "ssrf_interactsh_hit_urls.txt")
    hit_urls = set()
    if not os.path.exists(log_path):
        return hit_urls
    try:
        with open(log_path, "r", errors="ignore") as fh, open(out_urls, "w") as outf:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                raw_req = obj.get("raw-request", "") or ""
                tag = _extract_tag_from_raw_request(raw_req, set(tag2orig.keys()))
                if not tag:
                    continue
                orig = tag2orig.get(tag)
                if not orig:
                    continue
                hit_urls.add(orig)
                outf.write(orig + "\n")
    except Exception:
        pass
    return hit_urls

def _collect_nuclei_hits_to_urls(nuclei_jsonl, mutated2orig):
    hits = set()
    if not nuclei_jsonl or not os.path.exists(nuclei_jsonl):
        return hits
    try:
        with open(nuclei_jsonl, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                mut = obj.get("matched-at") or obj.get("host") or ""
                if mut in mutated2orig:
                    hits.add(mutated2orig[mut])
    except Exception:
        pass
    return hits

def _collect_ssrfmap_hits_to_urls(ssrfmap_out, mutated2orig):
    import re
    hits = set()
    if not ssrfmap_out or not os.path.exists(ssrfmap_out):
        return hits

    begin_re = re.compile(r"^###\s+SSRFMAP\s+URL:\s+(\S+)\s+PARAM:\s+(\S+)\s*$", re.IGNORECASE)
    # Loosely match success-y lines across modules
    success_re = re.compile(r"(?i)\b(vulnerable|open port|found|exposed|internal|200\s+OK|leaked)\b")

    cur_url = None
    cur_hit = False

    try:
        with open(ssrfmap_out, "r", errors="ignore") as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                m = begin_re.match(line)
                if m:
                    if cur_url and cur_hit:
                        hits.add(mutated2orig.get(cur_url, cur_url))
                    cur_url, cur_hit = m.group(1), False
                    continue
                if cur_url and success_re.search(line):
                    cur_hit = True
        if cur_url and cur_hit:
            hits.add(mutated2orig.get(cur_url, cur_url))
    except Exception:
        pass

    return hits

def _write_ssrf_findings(output_dir, map_tsv, nuclei_jsonl=None, ssrfmap_out=None):
    tag2orig, mutated2orig = _load_map_tsv(map_tsv)
    from_interact = _collect_interactsh_hits_to_urls(output_dir, tag2orig)
    from_nuclei   = _collect_nuclei_hits_to_urls(nuclei_jsonl, mutated2orig)
    from_ssrfmap  = _collect_ssrfmap_hits_to_urls(ssrfmap_out, mutated2orig)

    vuln_urls = sorted(set().union(from_interact, from_nuclei, from_ssrfmap))
    vuln_path = os.path.join(output_dir, "ssrf_vuln_urls.txt")
    with open(vuln_path, "w") as f:
        for u in vuln_urls:
            f.write(u + "\n")

    combined_path = os.path.join(output_dir, "ssrf_results_combined.txt")
    with open(combined_path, "w") as f:
        for u in sorted(from_interact):
            f.write(f"[callback] {u}\n")
        for u in sorted(from_nuclei):
            f.write(f"[nuclei]   {u}\n")
        for u in sorted(from_ssrfmap):
            f.write(f"[ssrfmap]  {u}\n")

    debug(f"SSRF vulnerable URLs -> {vuln_path}  (count: {len(vuln_urls)})")
    debug(f"SSRF combined results -> {combined_path}")

def run_ssrf(domain, output_dir):
    """
    SSRF stage:
      - Build candidates (heuristics + gf)
      - PASSIVE: write candidates + passive summary only
      - ACTIVE: auto-provision OAST if not provided (via interactsh-client),
                mutate & probe (httpx, nuclei, SSRFmap), summarize + interactsh hits
    """
    combined_urls_path = os.path.join(output_dir, "combined_urls.txt")
    if not os.path.exists(combined_urls_path):
        debug("SSRF: combined_urls.txt not found; nothing to scan")
        return set()

    # 1) Always build candidates (+ passive artifacts)
    candidates_file = _build_ssrf_candidates(combined_urls_path, output_dir)
    if not candidates_file or os.path.getsize(candidates_file) == 0:
        debug("SSRF: no candidates found")
        return set()

    # 2) Passive-only branch
    if not ACTIVE_MODE:
        debug("SSRF: passive mode selected — built candidates only; skipping network probes")
        try:
            with open(os.path.join(output_dir, "ssrf_summary.txt"), "w") as f:
                f.write("Mode: PASSIVE\n")
                f.write(f"Candidates: {sum(1 for _ in open(candidates_file))}\n")
        except Exception:
            pass
        return set()

    # 3) Active branch — get OAST automatically if needed
    oast_url_env = os.environ.get("OAST_URL", "").strip()
    if oast_url_env:
        oast_url = _normalize_oast(oast_url_env)
        debug(f"SSRF: using OAST_URL from env -> {oast_url}")
    else:
        log_path = os.environ.get("INTERACTSH_LOG", "interactsh_hits.json")
        oast_url = _start_interactsh_client(log_path=log_path)
        if not oast_url:
            debug("SSRF: could not auto-provision OAST (install 'interactsh-client' or set OAST_URL); skipping ACTIVE probes")
            return set()

    token = _secrets.token_hex(4)
    oast_for_run = _oast_with_token(oast_url, token)

    start_iso = _iso_now_z()
    debug(f"SSRF: ACTIVE start {start_iso}; OAST endpoint configured")

    # 4) Mutate & probe
    mutated_file, map_tsv = _mutate_with_qsreplace(candidates_file, oast_for_run, output_dir)
    if not mutated_file or os.path.getsize(mutated_file) == 0:
        debug("SSRF: failed to create mutated URLs")
        return set()
    debug(f"SSRF: mutated URLs -> {mutated_file}")

    httpx_json = _run_httpx(mutated_file, output_dir)
    nuclei_out = _run_nuclei_ssrf(mutated_file, output_dir)
    ssrfmap_out = _run_ssrfmap(mutated_file, output_dir)
    time.sleep(8)  # small grace period for callbacks to land
    _write_ssrf_findings(output_dir, map_tsv, nuclei_out, ssrfmap_out)

    # 5) Summaries
    counts = _summarize_httpx(httpx_json)
    from urllib.parse import urlparse as _urlparse
    oast_host = _urlparse(oast_url).netloc or oast_url.replace("http://","").replace("https://","").strip("/")
    hits = _collect_interactsh_since(oast_host, start_iso, output_dir)

    # 6) Write a tiny human summary
    summary_path = os.path.join(output_dir, "ssrf_summary.txt")
    try:
        with open(summary_path, "w") as f:
            f.write("Mode: ACTIVE\n")
            f.write(f"OAST_URL: {oast_url}\n")
            f.write(f"Token: {token}\n")
            f.write(f"Start: {start_iso}\n")
            f.write(f"Candidates: {sum(1 for _ in open(candidates_file))}\n")
            f.write(f"Mutated:   {sum(1 for _ in open(mutated_file))}\n")
            if counts:
                f.write(f"httpx: total={counts.get('total',0)}  "
                        f"2xx={counts.get('2xx',0)}  3xx={counts.get('3xx',0)}  "
                        f"4xx={counts.get('4xx',0)}  5xx={counts.get('5xx',0)}\n")
            if nuclei_out and os.path.exists(nuclei_out):
                f.write(f"nuclei(ssrf): {sum(1 for _ in open(nuclei_out) if _.strip())} lines\n")
            if ssrfmap_out and os.path.exists(ssrfmap_out):
                f.write(f"SSRFmap(networkscan): {sum(1 for _ in open(ssrfmap_out) if _.strip())} lines\n")
            f.write(f"Interactsh (since start, excluding /ping): {hits}\n")
    except Exception as e:
        debug(f"SSRF: failed to write summary: {e}")

    dbg = [f"SSRF summary -> {summary_path}"]
    if counts: dbg.append(f"httpx:{counts}")
    dbg.append(f"interactsh_hits:{hits}")
    debug(" | ".join(dbg))

    return set()
# -------------------- END SSRF STAGE (auto-OAST) --------------------



# -------------------- CRAWLERS (FULL URL COLLECTION) --------------------

def generic_crawler_tool(tool_name, cmd, out_name, output_dir):
    debug(f"Crawler: {tool_name}")
    out_file = os.path.join(output_dir, out_name)
    err_file = os.path.join(output_dir, f"{tool_name.lower().replace(' ', '_')}_crawler_stderr.log")
    try:
        with open(out_file, 'w') as f, open(err_file, 'w') as ef:
            run_cmd(cmd, stdout=f, stderr=ef, timeout=600, check=True)
    except TimeoutExpired:
        debug(f"{tool_name} crawler timed out; skipping")
        return set()
    except subprocess.CalledProcessError as e:
        debug(f"{tool_name} crawler failed: {e}")
        return set()
    cleaned_name = os.path.splitext(out_name)[0] + '_urls_cleaned.txt'
    return parse_urls_and_save(out_file, cleaned_name, output_dir)

def crawl_wayback_urls(target, output_dir):
    # wayback as crawler (full URLs)
    return generic_crawler_tool('waybackurls_crawl', ['waybackurls', target], f'wayback_crawl_{safe_name(target)}.txt', output_dir)

def crawl_gau_urls(target, output_dir):
    # gau as crawler (full URLs)
    return generic_crawler_tool('gau_crawl', ['gau', target], f'gau_crawl_{safe_name(target)}.txt', output_dir)

def crawl_gospider(target, output_dir):
    # Write to stdout so generic_crawler_tool can capture it
    # -d 2 depth, -a include subdomains from JS, -r follow redirects
    return generic_crawler_tool(
        'gospider_crawl',
        ['gospider', '-s', f'https://{target}', '-d', '2', '-a', '-r'],
        f'gospider_crawl_{safe_name(target)}.txt',
        output_dir
    )


def crawl_hakrawler(target, output_dir):
    out_file = os.path.join(output_dir, f'hakrawler_crawl_{safe_name(target)}.txt')
    err_file = os.path.join(output_dir, 'hakrawler_crawl_stderr.log')
    debug(f"$ echo https://{target} | hakrawler -insecure -u")
    try:
        with open(out_file, 'w') as f, open(err_file, 'w') as ef:
            echo = subprocess.Popen(
                ['echo', f'https://{target}'],
                stdout=subprocess.PIPE
            )
            subprocess.run(
                ['hakrawler', '-insecure', '-u'],
                stdin=echo.stdout,
                stdout=f, stderr=ef,
                check=True,
                timeout=300
            )
            echo.stdout.close()
    except subprocess.CalledProcessError as e:
        debug(f"hakrawler crawl failed: {e}")
        return set()
    except TimeoutExpired:
        debug("hakrawler crawl timed out after 300s; skipping")
        return set()
    return parse_urls_and_save(out_file, f'hakrawler_crawl_{safe_name(target)}_urls_cleaned.txt', output_dir)

def crawl_katana(target, output_dir):
    # Katana prints to stdout by default; -silent keeps only URLs
    return generic_crawler_tool(
        'katana_crawl',
        ['katana', '-u', f'https://{target}', '-silent'],
        f'katana_crawl_{safe_name(target)}.txt',
        output_dir
    )


def crawl_linkfinder(target, output_dir):
    # CLI output prints discovered endpoints; keep as URLs
    return generic_crawler_tool('linkfinder_crawl', ['python3', '/opt/LinkFinder/linkfinder.py', '-i', f'https://{target}', '-o', 'cli'], f'linkfinder_crawl_{safe_name(target)}.txt', output_dir)

def crawl_arjun(target, output_dir):
    # Arjun writes to stdout unless -o used; we'll let it print and capture
    return generic_crawler_tool('arjun_crawl', ['arjun', '-u', f'https://{target}'], f'arjun_crawl_{safe_name(target)}.txt', output_dir)

def crawl_paramspider(target, output_dir):
    # ParamSpider shim using Wayback CDX
    debug(f"Running ParamSpider crawl (CDX shim) for {target}")
    urls = _wayback_fetch_urls_for_domain(target)
    if not urls:
        debug("CDX shim returned 0 URLs")
        return set()

    # Save raw, then reuse existing cleaner/deduper
    norm_file = os.path.join(output_dir, f'paramspider_crawl_{safe_name(target)}.txt')
    with open(norm_file, 'w') as out:
        for u in sorted(urls):
            out.write(u + '\n')

    cleaned = parse_urls_and_save(
        norm_file,
        f'paramspider_crawl_{safe_name(target)}_urls_cleaned.txt',
        output_dir
    )
    debug(f"[ParamSpider CDX] raw:{len(urls)} cleaned:{len(cleaned)}")
    return cleaned



def crawl_photon(target, output_dir):
    # Photon outputs multiple files, we'll merge and parse URLs
    photon_dir = os.path.join(output_dir, f'photon_crawl_{safe_name(target)}')
    os.makedirs(photon_dir, exist_ok=True)
    cmd = ['python3', '/opt/Photon/photon.py', '-u', f'https://{target}', '-o', photon_dir]
    try:
        debug(f"$ {' '.join(cmd)}")
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        debug(f"photon crawl error: {e.stderr.decode().strip()}")
        return set()
    import glob
    merged = os.path.join(output_dir, f'photon_crawl_{safe_name(target)}.txt')
    with open(merged, 'w') as out:
        for txt in glob.glob(os.path.join(photon_dir, '*.txt')):
            try:
                with open(txt, 'r', errors='ignore') as f:
                    for line in f:
                        out.write(line)
            except Exception:
                continue
    return parse_urls_and_save(merged, f'photon_crawl_{safe_name(target)}_urls_cleaned.txt', output_dir)

def _find_chromium():
    candidates = [
        os.environ.get("CHROMIUM_PATH"),
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None

def _load_crawlergo_json(path, stdout_text):
    # 1) If file exists and has JSON, use it.
    try:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "r", errors="ignore") as f:
                return json.load(f)
    except Exception:
        pass

    # 2) Fallback to stdout if provided.
    if stdout_text:
        # try raw
        try:
            return json.loads(stdout_text)
        except Exception:
            pass
        # try line-by-line (NDJSON-ish)
        for line in reversed(stdout_text.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except Exception:
                    continue
        # try extracting the last {...} block
        s = stdout_text
        last_open = s.rfind("{")
        last_close = s.rfind("}")
        if last_open != -1 and last_close != -1 and last_close > last_open:
            try:
                return json.loads(s[last_open:last_close+1])
            except Exception:
                pass

    return {}

def crawl_crawlergo(target, output_dir):
    chromium = _find_chromium()
    if not chromium:
        debug("crawlergo: Chromium not found (set CHROMIUM_PATH). Skipping.")
        return set()

    out_json = os.path.join(output_dir, f'crawlergo_crawl_{safe_name(target)}.json')
    urls_out = os.path.join(output_dir, f'crawlergo_crawl_{safe_name(target)}.txt')

    cmd = [
        "/usr/local/bin/crawlergo",
        "--chromium-path", chromium,
        "--output-mode", "json",
        "-f", "smart",
        f"https://{target}",
        "--output-json", out_json
    ]

    try:
        debug(f"$ {' '.join(cmd)}")
        res = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600
        )
    except subprocess.CalledProcessError as e:
        debug(f"crawlergo crawl failed: {e}\nSTDERR: {e.stderr.strip() if e.stderr else ''}")
        return set()
    except TimeoutExpired:
        debug("crawlergo crawl timed out")
        return set()

    data = _load_crawlergo_json(out_json, res.stdout)

    urls = set()
    try:
        # prefer all_req_list; fallback to req_list
        reqs = data.get("all_req_list") or data.get("req_list") or []
        for req in reqs:
            u = req.get("url") if isinstance(req, dict) else req
            if isinstance(u, str) and (u.startswith("http://") or u.startswith("https://")):
                urls.add(u.strip())
    except Exception as e:
        debug(f"crawlergo JSON parse error: {e}")

    with open(urls_out, 'w') as f:
        for u in sorted(urls):
            f.write(u + "\n")

    debug(f"crawlergo crawl collected {len(urls)} URLs")
    return urls




def crawl_burp_urls(target, output_dir):
    # Reuse Burp run but parse URLs instead of hosts
    burp_jar = os.environ.get("BURP_JAR_PATH")
    if not burp_jar or not os.path.isfile(burp_jar):
        debug("Skipping Burp crawl (BURP_JAR_PATH not set or file missing)")
        return set()
    project_file = os.path.join(output_dir, f"burp_crawl_{safe_name(target)}.project")
    api_port = 1338  # use a different port than the enumerator's helper
    export_json = os.path.join(output_dir, f"burp_crawl_{safe_name(target)}.json")
    cmd = [
        "java", "-Xmx2G", "-jar", burp_jar,
        "--project-file", project_file,
        "--spider-only",
        "--url", f"https://{target}",
        "--api-listener", f"127.0.0.1:{api_port}"
    ]
    try:
        debug(f"$ {' '.join(cmd)}  (cwd={output_dir})")
        subprocess.run(cmd, cwd=output_dir, check=True, timeout=600)
        debug(f"$ GET http://127.0.0.1:{api_port}/burp/spider/results")
        resp = requests.get(f"http://127.0.0.1:{api_port}/burp/spider/results", timeout=20)
        resp.raise_for_status()
        with open(export_json, "w") as f:
            f.write(resp.text)
    except Exception as e:
        debug(f"Burp crawl failed: {e}")
        return set()
    urls = set()
    try:
        data = json.loads(open(export_json).read())
        for entry in data.get("urls", []):
            u = entry.get("url")
            if isinstance(u, str) and (u.startswith('http://') or u.startswith('https://')):
                urls.add(u)
    except Exception:
        pass
    debug(f"burp crawl collected {len(urls)} URLs")
    # Save cleaned
    out_clean = os.path.join(output_dir, f'burp_crawl_{safe_name(target)}_urls_cleaned.txt')
    with open(out_clean, 'w') as f:
        for u in sorted(urls):
            f.write(u + "\n")
    return urls

def crawl_zap_urls(target, output_dir):
    # zap-cli spider prints progress; we assume it can output URLs to stdout is limited.
    # We'll still capture stdout and parse URLs.
    return generic_crawler_tool('zap_spider_crawl', ['zap-cli', 'spider', f'https://{target}'], f'zap_crawl_{safe_name(target)}.txt', output_dir)

# -------------------- MAIN --------------------

def main():
    global ACTIVE_MODE  # declare once, at the very top

    parser = argparse.ArgumentParser(
        description="Super Subdomain Enumerator (extended active/passive/tools)"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument(
        "-w", "--wordlist",
        default="/opt/Seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        help="Wordlist for ffuf"
    )
    args = parser.parse_args()

    # ----------------------
# TEMPORARY: XSS-ONLY TEST (set to False when you're done testing)
# ----------------------
    XSS_TEST_ONLY = False

    if XSS_TEST_ONLY:
        output_dir = make_output_dir(args.domain.strip())
        src = "test_urls.txt"  # 1 URL per line
        dst = os.path.join(output_dir, "combined_urls.txt")

        try:
            shutil.copyfile(src, dst)
        except FileNotFoundError:
            debug(f"XSS-ONLY: '{src}' not found. Create it with URLs to test.")
            return

        # For testing you can choose active/passive behavior here:
        ACTIVE_MODE = True  # set False to test passive-only
        debug(f"XSS-ONLY mode -> ACTIVE_MODE={ACTIVE_MODE}")

        run_xss(args.domain.strip(), output_dir)
        return
# ----------------------

    # ----------------------
    # TEMPORARY: SSRF-ONLY TEST (set to False when you're done testing)
    # ----------------------
    SSRF_TEST_ONLY = False

    if SSRF_TEST_ONLY:
        output_dir = make_output_dir(args.domain.strip())

        # Create output_dir/combined_urls.txt from local test file (1 URL per line)
        src = "test_urls_ssrf.txt"
        dst = os.path.join(output_dir, "combined_urls.txt")
        try:
            shutil.copyfile(src, dst)
        except FileNotFoundError:
            debug(f"SSRF-ONLY: '{src}' not found. Create it with URLs to test (one per line).")
            # Example contents:
            # https://example.com/page?url=http://127.0.0.1/
            # https://example.com/redirect?next=https://attacker.tld/
            # https://example.com/download?file=http://169.254.169.254/latest/meta-data/
            # https://example.com/open?path=http://internal/
            # https://example.com/return?returnUrl=/home
            # https://example.com/image?imageUrl=https://attacker.tld/poc
            return

        # Force ACTIVE branch so we exercise auto-OAST + probes
        ACTIVE_MODE = True
        debug(f"SSRF-ONLY mode -> ACTIVE_MODE={ACTIVE_MODE}")

        # Prefer auto-OAST via interactsh-client; if it's not installed,
        # require OAST_URL to be set by the user.
        if not _shutil.which("interactsh-client") and not os.environ.get("OAST_URL"):
            debug("SSRF-ONLY: 'interactsh-client' not found and OAST_URL not set; set OAST_URL like:")
            debug("           export OAST_URL='https://<your-id>.oast.pro'")

        run_ssrf(args.domain.strip(), output_dir)
        return
    # ----------------------
    use_vpn = False
    vpn_managed = False
    nordvpn_location = None
    answer = input("Do you want to use NordVPN? (y/n): ").strip().lower()
    if answer == 'y':
        nordvpn_location = input("Enter NordVPN country code (e.g. us, de, jp): ").strip()
        use_vpn = True
    if use_vpn:
        if os.path.exists(LOCK_FILE):
            debug("Detected existing script-managed VPN connection; reusing it")
        else:
            vpn_managed = True
            debug("Disconnecting any existing NordVPN session")
            try:
                subprocess.run(["nordvpn", "disconnect"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            except subprocess.CalledProcessError:
                debug("NordVPN disconnect failed or wasn't connected—continuing anyway")
            debug(f"Connecting NordVPN to {nordvpn_location}")
            try:
                subprocess.run(["nordvpn", "connect", nordvpn_location], check=True)
                with open(LOCK_FILE, 'w') as f:
                    f.write(str(os.getpid()))
            except subprocess.CalledProcessError as e:
                debug(f"NordVPN connect failed ({e}); continuing without VPN")
    else:
        debug("Skipping NordVPN as per user choice")

    mode = input("Select mode - Passive only (p) or Active+Passive (a): ").strip().lower()
    if mode not in {'p', 'a'}:
        debug(f"Invalid mode '{mode}', defaulting to passive")
        mode = 'p'

    # set ACTIVE_MODE once here (no other 'global' lines needed)
    ACTIVE_MODE = (mode == 'a')
    debug(f"Mode selected: {'ACTIVE+PASSIVE' if ACTIVE_MODE else 'PASSIVE only'}")

    print("Select an operation method:")
    print("[0] Only subdomain scan")
    print("[1] Subdomain + spidering (crawling)")
    print("[2] Subdomain + spidering + XSS finder")
    print("[3] Subdomain + spidering + SSRF finder")
    print("[4] Full scan (subdomain + spidering + XSS + SSRF)")
    method = input("Enter method number [0-4]: ").strip()
    if method not in {'0', '1', '2', '3', '4'}:
        debug(f"Invalid method '{method}', defaulting to 0")
        method = '0'

    output_dir = make_output_dir(args.domain.strip())
    debug(f"Output directory: {output_dir}")

    all_subdomains = set()

    # ---- 1) Subdomain enumeration
    enumerators = [
        run_crtsh,
        run_amass_passive,
        run_gau,
        run_wayback,
        run_urlscan,
        run_shodan,
        run_censys,
        run_dnsdumpster
    ]
    for fn in enumerators:
        try:
            all_subdomains.update(fn(args.domain.strip(), output_dir))
        except KeyboardInterrupt:
            debug(f"{fn.__name__} interrupted by user; skipping")
            continue

    if mode == 'a':
        try:
            all_subdomains.update(run_amass_active(args.domain.strip(), output_dir))
        except KeyboardInterrupt:
            debug("run_amass_active interrupted; skipping")
        all_subdomains.update(run_ffuf(args.domain.strip(), output_dir, args.wordlist))

    # ---- 2) Combine deduped subdomains
    final_subdomains, combined_path = save_combined_results(all_subdomains, args.domain.strip(), output_dir)
    debug(f"Combined file: {combined_path}")

    # ---- 3) Crawl to gather URLs
    combined_urls_path = os.path.join(output_dir, "combined_urls.txt")
    if method in {'1', '2', '3', '4'}:
        targets = final_subdomains if final_subdomains else [args.domain.strip()]
        debug(f"Crawling targets: {len(targets)}")

        passive_crawlers = [crawl_wayback_urls, crawl_gau_urls]
        active_crawlers = [
            crawl_gospider,
            crawl_crawlergo,
            crawl_burp_urls,
            crawl_zap_urls,
            crawl_hakrawler,
            crawl_photon,
            run_crawlee,
            crawl_katana,
            crawl_linkfinder,
            crawl_arjun,
            crawl_paramspider
        ]
        crawlers_to_run = passive_crawlers if mode == 'p' else (passive_crawlers + active_crawlers)

        for sub in targets:
            for fn in crawlers_to_run:
                try:
                    urls = fn(sub, output_dir)
                    append_urls_to_combined(urls, combined_urls_path)
                except KeyboardInterrupt:
                    debug(f"{fn.__name__} interrupted by user; skipping")
                    continue

        try:
            with open(combined_urls_path, 'r') as f:
                total_urls = sum(1 for _ in f)
            debug(f"Combined total unique URLs: {total_urls}")
        except FileNotFoundError:
            debug("No URLs were collected by crawlers.")

    # ---- 4) Vuln stages
    if method in {'2', '4'}:
        run_xss(args.domain.strip(), output_dir)
    if method in {'3', '4'}:
        run_ssrf(args.domain.strip(), output_dir)

    if use_vpn and vpn_managed:
        debug("Disconnecting NordVPN")
        try:
            subprocess.run(["nordvpn", "disconnect"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except subprocess.CalledProcessError:
            debug("NordVPN final disconnect failed—no worries.")
        try:
            os.remove(LOCK_FILE)
        except OSError:
            pass


if __name__ == "__main__":
    main()
