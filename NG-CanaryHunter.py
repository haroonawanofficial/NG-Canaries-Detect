import argparse
import subprocess
from scapy.all import *
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.dns import DNS, DNSQR
import sqlite3
import random
import time
import re
from datetime import datetime
from cryptography.fernet import Fernet
from ipaddress import ip_network
import socket
import requests
from bs4 import BeautifulSoup

# Database setup
conn = sqlite3.connect('scan_results.db')
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS scans (
    timestamp TEXT,
    target_ip TEXT,
    scan_type TEXT,
    result TEXT,
    details TEXT
)
''')
conn.commit()

# Global arrays to store detected tripwires
detected_sessions = []
detected_tokens = []
detected_auths = []
detected_secrets = []

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Regex patterns for canary token detection
canary_patterns = [
    r'\b[0-9a-f]{40}\b',  # Generic SHA-1 like pattern, often used in canary tokens
    r'https?://canarytokens\.org/[\w]+',  # Pattern to match URLs from canarytokens.org
]

def enable_promiscuous_mode(interface):
    subprocess.run(['ifconfig', interface, 'promisc'])

def disable_promiscuous_mode(interface):
    subprocess.run(['ifconfig', interface, '-promisc'])

def ipv6_extension_header_scan(target_ip):
    print(f"IPv6 Extension Header Scan on {target_ip}")
    pkt = IPv6(dst=target_ip) / IPv6ExtHdrHopByHop(nh=59) / TCP(dport=80, flags="S")
    send(pkt, verbose=0)
    print(f"Sent IPv6 Extension Header Scan to {target_ip}")

def custom_payload_tcp_scan(target_ip, target_port):
    payload = "X" * 1024  # Unique payload to potentially trigger analysis
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="PA") / Raw(load=payload)
    send(pkt, verbose=0)
    print(f"Sent Custom Payload TCP Scan to {target_ip}:{target_port}")

def encrypted_payload_scan(target_ip, target_port):
    payload = "X" * 1024  # Unique payload to potentially trigger analysis
    encrypted_payload = cipher_suite.encrypt(payload.encode())
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="PA") / Raw(load=encrypted_payload)
    send(pkt, verbose=0)
    print(f"Sent Encrypted Payload TCP Scan to {target_ip}:{target_port}")

def fingerprint_device(target_ip):
    pkt = IP(dst=target_ip) / TCP(dport=80, flags="S")
    response = sr1(pkt, timeout=2, verbose=0)
    if response:
        ttl = response.ttl
        window = response.window
        if ttl < 64 or window != 65535:
            print(f"Possible canary device detected at {target_ip} (Fingerprint: TTL={ttl}, Window={window})")
        else:
            print(f"{target_ip} seems to be a legitimate device (Fingerprint: TTL={ttl}, Window={window})")
    else:
        print(f"No response from {target_ip} (could be filtered or down)")

def timing_analysis(target_ip):
    pkt = IP(dst=target_ip) / TCP(dport=80, flags="S")
    start_time = time.time()
    response = sr1(pkt, timeout=2, verbose=0)
    end_time = time.time()
    if response:
        rtt = end_time - start_time
        if rtt > 1:  # Arbitrary threshold, adjust as needed
            print(f"High latency detected ({rtt} seconds), {target_ip} may be a canary device")
        else:
            print(f"Normal latency detected ({rtt} seconds) for {target_ip}")
    else:
        print(f"No response from {target_ip} for timing analysis")

def protocol_anomaly_scan(target_ip):
    pkt = IP(dst=target_ip) / TCP(dport=80, flags="S", options=[('WScale', 10), ('Timestamp', (12345, 0)), ('NOP', None), ('MSS', 1460)])
    response = sr1(pkt, timeout=2, verbose=0)
    if response:
        options = response.getlayer(TCP).options
        if ('Timestamp', (12345, 0)) not in options:
            print(f"Protocol anomaly detected in {target_ip}'s response")
        else:
            print(f"{target_ip} responded with expected protocol behavior")
    else:
        print(f"No response from {target_ip} for protocol anomaly scan")

def non_standard_port_scan(target_ip):
    ports = [8080, 8443, 9999, 31337]  # Example of non-standard ports
    for port in ports:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=2, verbose=0)
        if response:
            print(f"Response from {target_ip} on non-standard port {port}, potential canary device")

def send_spoofed_packet(dst_ip, dst_port, src_ip):
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S")
    send(pkt, verbose=0)
    print(f"Sent spoofed packet from {src_ip} to {dst_ip}:{dst_port}")

def detect_canaries(target_ip, methods, invisible, spoof_ip=None):
    print("Starting canary detection phase...")

    if invisible:
        encrypted_payload_scan(target_ip, 80)

    if spoof_ip:
        send_spoofed_packet(target_ip, 80, spoof_ip)

    if "ipv6" in methods or "all" in methods:
        ipv6_extension_header_scan(target_ip)
    if "custom_payload" in methods or "all" in methods:
        custom_payload_tcp_scan(target_ip, 80)
    if "fingerprinting" in methods or "all" in methods:
        fingerprint_device(target_ip)
    if "timing" in methods or "all" in methods:
        timing_analysis(target_ip)
    if "protocol" in methods or "all" in methods:
        protocol_anomaly_scan(target_ip)
    if "non_standard_ports" in methods or "all" in methods:
        non_standard_port_scan(target_ip)

def crawl_and_detect(target_ip, target_port):
    url = f"http://{target_ip}:{target_port}"
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        js_files = [script['src'] for script in soup.find_all('script') if 'src' in script.attrs]
        css_files = [link['href'] for link in soup.find_all('link', rel='stylesheet') if 'href' in link.attrs]

        for file in js_files + css_files:
            if not file.startswith('http'):
                file = f"http://{target_ip}:{target_port}/{file}"
            try:
                file_response = requests.get(file, timeout=5)
                for pattern in canary_patterns:
                    if re.search(pattern, file_response.text):
                        detected_tokens.append(file)
                        print(f"Detected token in {file}")
                        record_scan(target_ip, 'Canary Detection', 'Token Detected', file)
            except requests.RequestException as e:
                print(f"Failed to fetch {file}: {e}")
    except requests.RequestException as e:
        print(f"Failed to crawl {url}: {e}")

def hunt_for_secrets(interface, stealth=False):
    print("Starting hunting phase in promiscuous mode...")
    enable_promiscuous_mode(interface)
    
    def packet_callback(packet):
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode('utf-8', errors='ignore')
            for pattern in canary_patterns:
                if re.search(pattern, load):
                    detected_tokens.append(load)
                    print(f"Detected token: {load}")
            if "secret" in load.lower():
                detected_secrets.append(load)
                print(f"Detected secret: {load}")
    
    if stealth:
        sniff(iface=interface, prn=packet_callback, store=0, timeout=60, filter="tcp and (port 80 or port 443)", count=100)
    else:
        sniff(iface=interface, prn=packet_callback, store=0, timeout=60)
    
    disable_promiscuous_mode(interface)

def generate_dynamic_payload(size=1024):
    return ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=size))

def send_stealthy(packet):
    time.sleep(random.uniform(0.5, 3))
    send(packet, verbose=0)

def send_fragmented(packet, fragsize=8):
    frags = fragment(packet, fragsize=fragsize)
    for frag in frags:
        send_stealthy(frag)

def detect_honeypot(target_ip):
    pkt = IP(dst=target_ip) / TCP(dport=80, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp and (resp.haslayer(TCP) and (resp.getlayer(TCP).window != 65535 or resp.getlayer(TCP).options)):
        return "Likely Honeypot"
    return "No Honeypot Detected"

def polymorphic_scan(target_ip, target_port, invisible=False):
    options = [('WScale', random.randint(0, 15)), ('Timestamp', (random.randint(1000, 9999), 0)), ('MSS', random.choice([1460, 1380, 1360]))]
    payload = generate_dynamic_payload()
    if invisible:
        payload = cipher_suite.encrypt(payload.encode())
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="S", options=options) / Raw(load=payload)
    send_stealthy(pkt)
    return "Scan Completed"

def detect_canary_tokens(data):
    for pattern in canary_patterns:
        if re.search(pattern, data):
            return True
    return False

def record_scan(target_ip, scan_type, result, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('INSERT INTO scans (timestamp, target_ip, scan_type, result, details) VALUES (?, ?, ?, ?, ?)',
              (timestamp, target_ip, scan_type, result, details))
    conn.commit()

def display_results():
    c.execute('SELECT * FROM scans')
    rows = c.fetchall()
    print("Timestamp\t\tTarget IP\tScan Type\t\tResult\tDetails")
    for row in rows:
        print(f"{row[0]}\t{row[1]}\t{row[2]}\t{row[3]}\t{row[4]}")

def generate_html_report():
    c.execute('SELECT * FROM scans')
    rows = c.fetchall()
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #f4f4f4; }
        </style>
    </head>
    <body>
        <h1>Network Scan Report</h1>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Target IP</th>
                <th>Scan Type</th>
                <th>Result</th>
                <th>Details</th>
            </tr>
    """
    
    for row in rows:
        html += f"""
        <tr>
            <td>{row[0]}</td>
            <td>{row[1]}</td>
            <td>{row[2]}</td>
            <td>{row[3]}</td>
            <td>{row[4]}</td>
        </tr>
        """
    
    html += """
        </table>
    </body>
    </html>
    """
    
    with open("scan_report.html", "w") as f:
        f.write(html)

def custom_tool_scan(target_ip, target_port, tool_path):
    print(f"Starting custom tool scan using {tool_path} on {target_ip}:{target_port}")
    
    # Construct the command to run the custom tool
    command = f"perl {tool_path} -h {target_ip} -p {target_port}"
    
    # Execute the custom tool and capture the output
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode == 0:
        print(f"Custom tool scan completed successfully:\n{stdout.decode()}")
        record_scan(target_ip, 'Custom Tool Scan', 'Completed', stdout.decode())
    else:
        print(f"Custom tool scan failed:\n{stderr.decode()}")
        record_scan(target_ip, 'Custom Tool Scan', 'Failed', stderr.decode())

def auto_detect_and_change_osi(target_ip):
    # Function to attempt various OSI layer manipulations
    print(f"Auto-detecting and changing OSI layers for target {target_ip}...")
    # Example: DNS-based detection (Layer 7)
    pkt = IP(dst=target_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    response = sr1(pkt, timeout=2, verbose=0)
    if response:
        if response.haslayer(DNS) and response.getlayer(DNS).ancount > 0:
            print("Target responds to DNS queries. Using Layer 7 manipulation.")
            return "Layer 7"
    # Default to Layer 3 manipulation if no response
    print("Defaulting to Layer 3 manipulation.")
    return "Layer 3"

def main():
    parser = argparse.ArgumentParser(description='Advanced Network Scanner for Stealth Operations')
    
    parser.add_argument('--target_ip', type=str, help='Target IP address')
    parser.add_argument('--cidr', type=str, help='Target network in CIDR notation')
    parser.addendant('--multiple_ips', type=str, nargs='+', help='Multiple target IP addresses')
    parser.add_argument('--domain', type=str, help='Target domain name')
    parser.add_argument('--port', type=int, default=80, help='Target port (default: 80)')
    
    parser.add_argument('--methods', type=str, nargs='+', required=True, 
                        help='Detection methods (e.g., ipv6, custom_payload, fingerprinting, timing, protocol, non_standard_ports, stealth, all)')
    
    parser.add_argument('--hunt', action='store_true', help='Hunt for secrets after detection')
    parser.add_argument('--invisible', action='store_true', help='Use invisible mode with encrypted payloads')
    parser.add_argument('--spoofip', type=str, help='Spoof source IP address')
    parser.add_argument('--scan_type', type=str, choices=['polymorphic', 'detect_honeypot', 'full_scan'], help='Type of scan')
    parser.add_argument('--interface', type=str, default='eth0', help='Network interface to use for promiscuous mode')
    parser.add_argument('--crawl', action='store_true', help='Crawl .js and .css files for canary tokens')
    parser.add_argument('--tripwire', action='store_true', help='Combine all tripwire detection methods')
    parser.add_argument('--stealth', action='store_true', help='Use stealth mode for promiscuous sniffing')
    parser.add_argument('--customtool', type=str, help='Path to a custom tool (e.g., nikto.pl)')
    parser.add_argument('--auto_osi', action='store_true', help='Auto-detect and change OSI layers for stealth')

    args = parser.parse_args()

    targets = []

    if args.target_ip:
        targets.append(args.target_ip)
    
    if args.cidr:
        network = ip_network(args.cidr)
        targets.extend([str(ip) for ip in network.hosts()])
    
    if args.multiple_ips:
        targets.extend(args.multiple_ips)
    
    if args.domain:
        try:
            ip = socket.gethostbyname(args.domain)
            targets.append(ip)
        except socket.gaierror:
            print(f"Could not resolve domain: {args.domain}")
    
    for target in targets:
        print(f"Scanning {target}")
        if args.tripwire:
            detect_canaries(target, ['ipv6', 'custom_payload', 'fingerprinting', 'timing', 'protocol', 'non_standard_ports', 'stealth'], args.invisible, args.spoofip)
        else:
            detect_canaries(target, args.methods, args.invisible, args.spoofip)
        
        if args.hunt:
            hunt_for_secrets(args.interface, args.stealth)
        
        if args.crawl:
            crawl_and_detect(target, args.port)
        
        if args.scan_type:
            if args.scan_type == 'detect_honeypot':
                result = detect_honeypot(target)
                record_scan(target, 'Honeypot Detection', result, '')
            elif args.scan_type == 'polymorphic':
                result = polymorphic_scan(target, args.port, args.invisible)
                record_scan(target, 'Polymorphic Scan', result, 'Invisible mode: ' + str(args.invisible))
            elif args.scan_type == 'full_scan':
                # Simulate a full scan with all features
                honeypot_result = detect_honeypot(target)
                polymorphic_result = polymorphic_scan(target, args.port, args.invisible)
                record_scan(target, 'Full Scan', 'Completed', f'Honeypot: {honeypot_result}, Polymorphic: {polymorphic_result}, Invisible: {args.invisible}')
        
        if args.customtool:
            custom_tool_scan(target, args.port, args.customtool)

        if args.auto_osi:
            osi_layer = auto_detect_and_change_osi(target)
            if osi_layer == "Layer 7":
                # Perform DNS-based detection
                pkt = IP(dst=target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
                send(pkt, verbose=0)
            elif osi_layer == "Layer 3":
                # Default to IP-based detection
                pkt = IP(dst=target) / TCP(dport=80, flags="S")
                send(pkt, verbose=0)
        
    display_results()
    generate_html_report()

if __name__ == "__main__":
    main()
