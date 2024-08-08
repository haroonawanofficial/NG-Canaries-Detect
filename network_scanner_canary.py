import os
import hashlib
import argparse
from scapy.all import sniff, send, IP, TCP, SMB
import socket
import struct
import random

# Known hashes for canary tokens
known_md5_hashes = [
    "9b0d48c05b832409a5db8250a4a7b1d1", "8d65ef4e184ef9174a37b1b63c1f241d",
    "2c6ee24b09816a6f14f95d1698b24ead", "c33b5a1c709c9e9c4a340f9c82b49b62",
    "5eb63bbbe01eeed093cb22bb8f5acdc3", "7d97e19d2e0a264ffb3dcb21f90f3d48",
    "6f1ed002ab5595859014ebf0951522d9", "ab56b4d92b40713acc5a1d2065f3d8d2",
    "f0c1d2a5b034a4c1eae44a2eb8e1c235", "9e0f21e9ef66bdf4c314af7b41ee08b4",
    "8c3d00f2f4eeb0b9c5c68e87e8c1cda6", "7c6a180b36896a351a8f3b69e1b8b20f",
    "f9c3d7c0477be1685d95e0c97c946a59", "a2b1b9b8c7b9de94f3c6b5161ef86e98",
    "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "e7f8a6d4c52bfaed2483e9a5eb37307b",
    "4b227777d4eeaa7f8676e3c5c19c6c86", "f4b2cb0a4c46e2b7d88aaaf96c9780ff",
    "e48c5148e4fef9bb6b3490f401279f39", "a5d3e35c3fbc61d11bb7e7b7e1b0e83e",
    "827ccb0eea8a706c4c34a16891f84e7b", "5e884898da28047151d0e56f8dc6292773603d0d",
    "1a79a4d60de6718e8e5b326e338ae533", "d8578edf8458ce06fbc5bb76a58c5ca5",
    "7d793037a0760186574b0282f2f8c46"
]
known_sha1_hashes = [
    "16b74a546312f69d7a7b1dfe35c60760d7398f56", "2c503158c582ec44aa2c251d6e240bbd5e632bcd",
    "c93c1d6f6d6ae9e5f548e879c178953f9c3fbd6b", "2f5471b2c8f6b1e4d15c6fbcdfc23b474eef1d7d",
    "2b73a1c0286d31767d17c5b97917dcbcf14dc818", "d2a62d69c65c647e054982c22ec2cb1979b7cb4f",
    "f68c407645554bcdf0a8265c56be8e37d2cf876d", "e1f7d2b0552e5b4a6e15763f60c0fd85cb0c248b",
    "1b33e7d6f9d633b027c44fdbfd58362d3a9bc30e", "e99a18c428cb38d5f260853678922e03",
    "c4c36c2cd1b8e12f3256f761cb20a302219e03b5", "7a5b0f160a1d98d94fc02c4c9c74b892f6a1a5aa",
    "d74d1573c9b74d60bfa0c14c0d5f3f73e5d8ae62", "f1dcb25d8f7b83c2f4d12a8e43190a4dbfbc8d2e",
    "cf0c01f1d4f1866e1aef34435ab7fc885de6ae61", "d48dc9143f70f12905d6b0a33dc1246d62b22d8b",
    "c94b2d7c8e5b1ae24e1f8c6e3e5419159d8a2376", "15f5c340793e0d8ab36b4d6f09544b2f7b9c2f1b",
    "9d9c1d0f6c5e01302e394375ef0e1f0f9df4c71c", "16b74a546312f69d7a7b1dfe35c60760d7398f56",
    "d95f2e4a08d1f2c56ed31a01c4dc8231c5b21c98", "6dcd4ce23d88e2ee9568ba546c007c63",
    "6f1ed002ab5595859014ebf0951522d9", "9c56cc24771a308dc4bc93ecf39d5fef",
    "6dcd4ce23d88e2ee9568ba546c007c63"
]

# Known SMB packet patterns for T-POT Canary
known_smb_patterns = [
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    "FF 53 EF 00 00 00 00 00 00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
]

# CLI argument parsing
parser = argparse.ArgumentParser(description="Stealth Network Scanner for Canary Tokens")
parser.add_argument("-s", "--subnet", required=True, help="Subnet to scan (e.g., 192.168.1.0/24)")
parser.add_argument("-m", "--mode", choices=["stealth", "normal"], default="stealth", help="Scanning mode: stealth or normal")
parser.add_argument("--spoof", action="store_true", help="Enable IP spoofing to appear outside the network")
parser.add_argument("--spoof-ip", help="Specify a custom IP address to spoof")
parser.add_argument("--normal-user", action="store_true", help="Simulate normal user traffic to bypass IDS/IPS")
args = parser.parse_args()

# Function to generate dynamic hashes based on custom logic
def generate_dynamic_hashes(metadata):
    md5_hasher = hashlib.md5()
    sha1_hasher = hashlib.sha1()
    
    metadata_str = str(metadata).encode('utf-8')
    md5_hasher.update(metadata_str)
    sha1_hasher.update(metadata_str)
    
    md5_hash = md5_hasher.hexdigest()
    sha1_hash = sha1_hasher.hexdigest()
    
    return md5_hash, sha1_hash

# Function to retrieve file metadata and generate hashes
def get_file_metadata(file_path):
    try:
        stat_info = os.stat(file_path)
        metadata = {
            'size': stat_info.st_size,
            'ctime': stat_info.st_ctime,
            'mtime': stat_info.st_mtime,
            'atime': stat_info.st_atime
        }
        return metadata
    except Exception as e:
        print(f"Error retrieving metadata for {file_path}: {e}")
        return None

def check_for_canary(file_path):
    metadata = get_file_metadata(file_path)
    if metadata:
        md5_hash, sha1_hash = generate_dynamic_hashes(metadata)
        
        if md5_hash in known_md5_hashes or sha1_hash in known_sha1_hashes:
            print(f"Canary token detected in {file_path}")

# Function to perform IP spoofing
def spoof_ip(src_ip, dst_ip, dst_port):
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=12345, dport=dst_port, flags="S")
    packet = ip_layer / tcp_layer
    send(packet, verbose=False)

# Function to process captured SMB packets
def smb_packet_callback(packet):
    if packet.haslayer(SMB):
        smb_layer = packet.getlayer(SMB)
        smb_hex_data = bytes(smb_layer).hex()
        for pattern in known_smb_patterns:
            if pattern in smb_hex_data:
                print(f"Canary token activity detected in SMB packet from {packet[IP].src}")

# Function to scan the subnet
def scan_subnet(subnet, mode, spoof, normal_user, spoof_ip):
    print(f"Scanning subnet: {subnet} in {mode} mode with spoofing {'enabled' if spoof else 'disabled'}")
    for ip in generate_ip_range(subnet):
        try:
            # Simulate legitimate traffic pattern
            if mode == "stealth":
                if spoof:
                    src_ip = spoof_ip if spoof_ip else generate_random_ip()
                    spoof_ip(src_ip, ip, 445)
                else:
                    socket.gethostbyaddr(ip)
            
            # Check SMB shares for canary tokens
            smb_check(ip, normal_user)
        except Exception as e:
            print(f"Error scanning {ip}: {e}")

# Function to check SMB shares for canary tokens
def smb_check(ip, normal_user):
    try:
        network_share_paths = [f"\\\\{ip}\\finance", f"\\\\{ip}\\tripwire", f"\\\\{ip}\\engineering"]
        for share_path in network_share_paths:
            if normal_user:
                # Simulate normal user activity
                normal_user_activity(share_path)
            for root, dirs, files in os.walk(share_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    check_for_canary(file_path)
    except Exception as e:
        print(f"Error accessing SMB share on {ip}: {e}")

# Function to simulate normal user activity
def normal_user_activity(network_share_path):
    try:
        # Example of normal user activity: accessing a known safe file
        safe_file_path = os.path.join(network_share_path, "safe_file.txt")
        with open(safe_file_path, 'r') as f:
            content = f.read()
        print(f"Simulated normal user activity: read {len(content)} bytes from {safe_file_path}")
    except Exception as e:
        print(f"Error simulating normal user activity: {e}")

# Function to generate IP range from subnet
def generate_ip_range(subnet):
    ip, cidr = subnet.split('/')
    cidr = int(cidr)
    host_bits = 32 - cidr
    ip_int = struct.unpack('>I', socket.inet_aton(ip))[0]
    start_ip = ip_int & (~((1 << host_bits) - 1))
    end_ip = start_ip | ((1 << host_bits) - 1)
    return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start_ip + 1, end_ip)]

# Function to generate random IP
def generate_random_ip():
    random_ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    return random_ip

# Start scanning
scan_subnet(args.subnet, args.mode, args.spoof, args.normal_user, args.spoof_ip)

# Capture and analyze SMB packets and perform heuristic analysis (requires root/administrator privileges)
sniff(filter="tcp port 445", prn=smb_packet_callback)
