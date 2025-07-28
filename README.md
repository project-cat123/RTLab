# RTLab

<p align="center">
<img width="300" height="240" alt="logo-search-grid-1x" src="https://github.com/user-attachments/assets/c52f1449-8dd2-4729-8460-b320ffcb2296" />
</p>

## 🧩 Level 1 – Foundations: Networking & Basic Crypto
Goal: Master basic TCP/UDP communication, encryption, and custom tooling fundamentals.
| # | Topic | Description |
|---|---|---|
| 1 |TCP/UDP Message Server | Basic server that receives messages |
| 2 | TCP/UDP Chat Server | Build a chat app over TCP/UDP |
| 3 | Multithreaded Chat Server | Handle multiple clients concurrently |
| 4 | File Transfer Server | Send and receive files over TCP |
| 5 | Caesar / ROT13 Cipher Tool | Basic encryption/decryption implementation |
| 6 | Encrypted Chat Server | Integrate Caesar or ROT13 into chat |
| 7 | Netcat Clone | Custom-built tool to replicate Netcat behavior |
| 8 | Remote Command Execution | Send commands to remote systems over TCP |
| 9 | Basic Reverse Shell Payload | One-liner shell connection back to attacker |
| 10 | Simple File Encryptor | Symmetric encryption utility for local files |


## 🔍 Level 2 – Recon & Brute Force: Enumeration and Target Profiling
Goal: Build tools for service discovery, brute force, and basic exploitation.
| # | Topic | Description |
|---|---|---|
| 11 | Basic Port Scanner | TCP Connect / SYN scanner |
| 12 | OS Fingerprinting via TTL | Guess OS based on TTL differences |
| 13 | Port-to-Service Mapper | Identify services by common port behavior |
| 14 | Web Directory Bruteforcer | Multi-threaded, wordlist-based |
| 15 | Web Login Bruteforcer | CSRF-safe, session-aware brute force tool |
| 16 | FTP/SSH Brute Forcer | Brute force common auth protocols |
| 17 | FTP/MySQL Username Enum | Error-based or behavior-based user guessing |
| 18 | Search Engine OSINT Bot | Scrape and correlate intel via Google/Bing |
| 19 | Basic SQLi & XSS Tester | Inject common payloads and detect response |
| 20 | Wordpress Bruteforce Tool | Exploit XML-RPC or /wp-login brute force |

## 🕷️ Level 3 – Real-World Attack Components
Goal: Build working components for botnets, phishing, persistence, and post-exploitation.
| # | Topic | Description |
|---|---|---|
| 21 | Reverse Shell Payload | Multi-platform (Windows/Linux) |
| 22 | Auto-Start Payload (Regedit/Daemon) | Ensure persistence on reboot |
| 23 | Basic Botnet Framework | C2 server with multiple client heartbeat |
| 24 | ARP Poisoning Tool | MITM implementation using ARP spoofing |
| 25 | Connect to Tor Network | Integrate Tor proxy routing |
| 26 | Phishing HTTP Server | Credential capture with custom HTML |
| 27 | Honeypot Setup | Fake services to detect attackers |
| 28 | Packet Capture Tool | PCAP collection and filtering |
| 29 | Powershell / Bash Payload Generator | Templated payloads with obfuscation |
| 30 | C2 Client/Server Communication | Basic secure comms simulation |


## 🧠 Level 4 – Post-Exploitation & Persistence
Goal: Automate post-exploitation phases: enumeration, evasion, privilege escalation.
| # | Topic | Description |
|---|---|---|
| 31 | OS Enumeration Script | Collect local OS info post-compromise |
| 32 | Application Enumeration | List installed programs, detect backdoors |
| 33 | Browser Info Extractor | Cookies, passwords, history |
| 34 | Windows Token Escalator | Privilege escalation via token manipulation |
| 35 | Shortcut Spawner | Create fake or confusing desktop shortcuts |
| 36 | Self-Spreading Worm | Minimal worm with LAN-based propagation |
| 37 | Man-in-the-Browser PoC | Modify DOM, intercept credentials |
| 38 | DLL Injection Utility | Inject into remote process memory |
| 39 | Stack Buffer Overflow PoC | Fully working exploit with shellcode |
| 40 | VPN/Proxy Detection Bypass | Fingerprint and evade anti-proxy measures |

## 🔐 Level 5 – Reverse Engineering & Exploit Development
Goal: Master binary analysis, payload crafting, and custom exploit development.
| # | Topic | Description |
|---|---|---|
| 41 | Simple Disassembler | x86 or ARM disassembler written from scratch |
| 42 | Antivirus Evasion Tool | Modify payloads to bypass detection |
| 43 | Password Hash Cracker | Implement brute-force + rainbow table logic |
| 44 | Hexdump & Memory Viewer | Format memory and binary output like xxd |
| 45 | RSA / Vigenère Cipher Tool | Manual encryption + cryptanalysis logic |
| 46 | WPA2 Handshake Capture | Monitor and capture handshake for cracking |
| 47 | Build Metasploit Module | Custom exploit or post module |
| 48 | Bluetooth Attack PoC | RFCOMM or BLE enumeration and fuzzing |
| 49 | Exploit Dev (Stack / Heap) | Write working exploits from CVEs or scratch |
| 50 | Post-Exploitation Toolkit | Persistence, enumeration, screenshot, etc. |

---
### 🧠 Credits & Reference

The idea for building a structured Red Team portfolio originated from kurogai's public repository.
This version is a custom adaptation with additional tooling, restructured difficulty levels, and extended real-world use cases tailored for offensive security training.
