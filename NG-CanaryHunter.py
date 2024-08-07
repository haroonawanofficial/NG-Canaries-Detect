import argparse
from scapy.all import *
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from ipaddress import ip_network
import random
import time
from cryptography.fernet import Fernet

# Global arrays to store detected tripwires
detected_sessions = []
detected_tokens = []
detected_auths = []
detected_secrets = []

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

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

def detect_canaries(target_ip, methods, invisible):
    print("Starting canary detection phase...")

    if invisible:
        encrypted_payload_scan(target_ip, 80)

    if "ipv6" in methods:
        ipv6_extension_header_scan(target_ip)
    if "custom_payload" in methods:
        custom_payload_tcp_scan(target_ip, 80)
    if "fingerprinting" in methods:
        fingerprint_device(target_ip)
    if "timing" in methods:
        timing_analysis(target_ip)
    if "protocol" in methods:
        protocol_anomaly_scan(target_ip)
    if "non_standard_ports" in methods:
        non_standard_port_scan(target_ip)

def hunt_for_secrets(target_ip, target_port):
    print("Starting hunting phase...")
    payload = "GET /secrets HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip)
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="PA") / Raw(load=payload)
    response = sr1(pkt, timeout=2, verbose=0)
    if response:
        detected_sessions.append(response.getlayer(Raw).load.decode('utf-8'))
        print(f"Response from {target_ip}:{target_port}: {response.show(dump=True)}")
    else:
        print(f"No response from {target_ip}:{target_port} during hunting")

def main():
    parser = argparse.ArgumentParser(description='Detect and interact with potential canary devices.')
    
    parser.add_argument('--target_ip', type=str, help='Target IP address')
    parser.add_argument('--cidr', type=str, help='Target network in CIDR notation')
    parser.add_argument('--multiple_ips', type=str, nargs='+', help='Multiple target IP addresses')
    parser.add_argument('--domain', type=str, help='Target domain name')
    parser.add_argument('--port', type=int, default=80, help='Target port (default: 80)')
    
    parser.add_argument('--methods', type=str, nargs='+', required=True, 
                        help='Detection methods (e.g., ipv6, custom_payload, fingerprinting, timing, protocol, non_standard_ports, stealth)')
    
    parser.add_argument('--hunt', action='store_true', help='Hunt for secrets after detection')
    parser.add_argument('--invisible', action='store_true', help='Use invisible mode with encrypted payloads')

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
        detect_canaries(target, args.methods, args.invisible)
        if args.hunt:
            hunt_for_secrets(target, args.port)

if __name__ == "__main__":
    main()
