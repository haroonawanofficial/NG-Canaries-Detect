# NG-CanaryHunter 
- It is an advanced assessment network scanning tool designed for security professionals to detect and interact with canary devices, such as Thinkst Canary and T-Pot while minimizing the risk of detection.

# Features of NG-CanaryHunter 
- Advanced Scanning Techniques: Utilizes sophisticated methods like IPv6 extension header scans, custom payload TCP scans, fingerprinting, timing analysis, and protocol anomaly detection.
- Stealth Mode: Operates in an invisible mode using encrypted payloads to blend with legitimate traffic, reducing the chances of detection.
- Flexible Targeting: Supports single IPs, CIDR notation, multiple IPs, and domain resolution.
- Harmless Simulation: Includes a harmless mode to simulate benign user behavior.
- Hunting Capabilities: Option to hunt for secrets and tripwires after detection.

# Scanning Detection of Canary as Preliminary Step
- NG-CanaryHunter uses very unsual method to scan and generate legitimate network traffic.
- NG-CanaryHunter provides security professionals with a powerful and discreet tool for identifying security traps and tripwires in a network.
- Its advanced techniques and stealth capabilities ensure thorough and undetected security assessments, enhancing the overall security posture.

# Algorithms to Deafeat Canaries such as Thinkst Canary and T-Pot
- Dynamic Payload Generation: Use more complex, dynamically changing payloads that are less likely to be fingerprinted by defensive systems.
- Random Timing Delays: Introduce random timing delays between packet sends to mimic human behavior and evade rate-based detection systems.
- Packet Fragmentation: Use packet fragmentation to sneak past simple packet inspection systems that do not properly reassemble packets.
- Polymorphic Code: Change the code structure dynamically, making the scanning activity harder to detect via static signatures.
- Protocol Obfuscation: Implement techniques to modify protocol headers in ways that are still compliant but might confuse security devices.
- Stealth by Confusion: Use decoy traffic that appears legitimate to distract from the scanning activities.
- Encrypted Payloads: Fernet encryption before sending which Uses the cryptography library to generate a key and encrypt the payloads

# Invisible Method with --invisible flag
- Canary devices may not directly process encrypted payloads because they are designed to detect and respond to specific patterns in traffic. When payloads are encrypted, the canary device cannot easily analyze them, making it less likely to detect the scan. Therefore, using encrypted payloads can help in remaining undetected, which is why it is termed "invisible."

# More Information on Invisible Mode
- Invisible mode encrypts the payloads using a unique key, making them difficult for canary devices to analyze. By encrypting the traffic, the scan appears as harmless or regular encrypted communication, reducing the likelihood of detection. This stealth technique ensures that the payloads are only interpretable by the intended operating system, not by the security traps.

# Finding Tokens and Confirming Tripwires for T-Pot and Thinkst Canary:
- The script sends special messages (payloads) to the target computer to see how it reacts.
- It uses methods to send these messages and look for specific responses that indicate a token or tripwire.
- It looks for patterns in the responses that match common token formats using regex (a tool for finding patterns in text).
- Any detected tokens or unusual responses are saved in a database to keep a record.
- The hunt_for_secrets function sends specific requests to find hidden secrets or tokens on the target.

# Sending Spoofed Requests to Appear Outside the Network for T-Pot and Thinkst Canary:
- The script can send messages that look like they come from a different computer.
- It creates a packet with a fake source IP address and sends it to the target.
- This makes the message appear as if it is coming from outside the network, which can trick the target into thinking it is being attacked from a different location.

# Usage
```bash
sudo python NG-CanaryHunter.py --target_ip <target_ip> --methods <method1> <method2> --invisible --hunt
```

# Polymorpic Decoy
```bash
sudo python NG-CanaryHunter.py --target_ip 192.168.1.10 --methods polymorphic decoy --hunt
```

# The Great Invisible Hunt
```bash
python script.py --target_ip 192.168.1.10 --methods obfuscation --invisible --hunt
```


# R&D Company
Cyber Zeus

# R&D Contact
Haroon Ahmad Awan

# Email
haroon@cyberzeus.pk
