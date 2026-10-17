# PrismStrike

PrismStrike is a lightweight, single-file network reconnaissance and automated assessment framework written entirely in Python. Designed for certified penetration testers and network administrators, it packs high-fidelity raw packet tools into a fully interactive terminal workflow with zero configuration or heavy external dependencies.

## 🧬 Framework Suite Matrix

| Module ID | Subsystem Component | Scope & Operational Coverage |
| :---: | :--- | :--- |
| **01** | **ICMP Reconnaissance** | Subnet ping sweeps, granular type/code probing, and path traceroutes. |
| **02** | **TCP Flag Crafter** | Custom flag combination injections (SYN, ACK, FIN, RST, PSH, URG, NULL, XMAS). |
| **03** | **Hping Replicator** | High-throughput raw frame generation, flood modes, and source address spoofing. |
| **04** | **Nmap Sub-Engine** | Native execution of fast/aggressive profiles using python-nmap bindings. |
| **05** | **Live Packet Sniffer** | Passive capture with real-time layer dissection and custom BPF stream filters. |
| **06** | **ARP Discovery** | Op=1 cache sweeps, hardware OUI mapping, and segment collision checks. |
| **07** | **ARP Spoofing / MITM** | Bi-directional cache poisoning with auto kernel routing and active traffic logging. |
| **08** | **PCAP Analyst** | Offline PCAP/PcapNG file forensics, live rolling telemetry, and HTTP(S) asset ingest. |
| **13** | **Network Utilities** | Socket banner grabs, TCP stream reassembly, and path MTU blackhole diagnostics. |
| **14** | **DHCP Operations** | Pool starvation stress testing and rogue DHCP server simulation with lease ledgering. |
| **15** | **DNS Toolkit** | Query resolution, tunneling/DGA heuristic monitoring, and DNSBL reputation traps. |
| **16** | **Wireless Lab** | Monitor-mode scanner with automated interface state restoration and deauth simulations. |
| **17** | **Awareness Listeners** | Low-interaction honeypots, basic credential pattern traps, and HTTP phishing harvesters. |

## 🚀 Getting Started

### Prerequisites
PrismStrike targets raw sockets and modifies network interfaces, requiring superuser authority to access raw modes:
```bash
sudo python3 prismstrike.py --self-test
```

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com
   cd prismstrike-framework
   ```
2. Run the **Dependency Doctor** to verify or install local system packages:
   ```bash
   python3 prismstrike.py --module doctor
   ```

## 🔒 Safe Credential Masking & Logging
Every session creates a structured ledger inside the logs directory containing text traces (`*.log.txt`) and newline-delimited event streams (`*.events.json`). PrismStrike uses an automated pattern scrubbing mechanism that masks discovered credentials at the ingest boundary to protect production values from accidental plaintext log pollution.

## ⚖️ Legal Disclaimer
This framework transmits raw frames, forged ARP replies, and crafted TCP/IP packets. Run this tool **ONLY** on target segments you explicitly own or hold an active, written penetration testing authorization for. 
