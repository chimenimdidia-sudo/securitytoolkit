# Security Toolkit

An integrated cybersecurity toolkit with a phishing URL detector, hash generator and file integrity checker, web honeypot, and network intrusion detection (port scan and SYN flood), all reporting to one dashboard.

## Modules
- Phishing URL detector: rule-based risk score from 0 to 100%
- Hash generator and file integrity checker: MD5, SHA-1, SHA-256, SHA-512
- Honeypot: fake admin login on port 8080 that logs attempts
- IDS: Scapy packet capture with port scan and SYN flood detection
- Dashboard: shared SQLite alerts database and web interface on port 5000

## Setup (Windows)
1. Install Python (tick "Add Python to PATH") and Npcap (npcap.com).
2. In the project folder, run:
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
3. Start the services in separate terminals (each with venv activated):
   python app.py
   python honeypot.py
   python sniffer.py <adapter number>
4. Open http://127.0.0.1:5000

To find the adapter number for the sniffer, run:
python -c "from scapy.all import show_interfaces; show_interfaces()"

## Testing
Tested in a VirtualBox lab with a Kali Linux VM on a host-only network. Only scan machines you own.

## Limitations
Rule-based detection (no machine learning), fixed IDS thresholds, no dashboard login, and Flask's development server.