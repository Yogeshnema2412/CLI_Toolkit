import os
import sys
import socket
from scapy.all import ARP, Ether, srp
import ipaddress
import time

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
        time.sleep(1)  # Adding a delay to avoid overwhelming the network

# Comprehensive port and service mappings
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

if __name__ == "__main__":
    check_permissions()
    network_range = get_network_range()
    port_range = list(port_service_map.keys())  # Use keys from the dictionary for scanning
    scanned_devices = scan_network(network_range)
    display_results(scanned_devices)