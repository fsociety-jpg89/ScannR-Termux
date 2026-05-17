#!/usr/bin/env python3
# Security Scanner optimized for Termux - English version
# Install dependencies: pip install requests colorama

import socket
import requests
import re
import os
import sys
from urllib.parse import urlparse
from colorama import Fore, init

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def logo():
    clear_screen()
    print(Fore.RED + """
 ██████  ▄████▄   ▄▄▄       ███▄    █  ███▄    █  ██▀███
▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █ ▓██ ▒ ██▒
░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒▓██ ░▄█ ▒
  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒██▀▀█▄
▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░░██▓ ▒██▒
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░ ▒▓ ░▒▓░
░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░  ░▒ ░ ▒░
░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░   ░░   ░
      ░  ░ ░            ░  ░         ░          ░    ░
         ░
""")

def expand_url(url):
    """Follow redirects and return final URL"""
    try:
        resp = requests.head(url, allow_redirects=True, timeout=5)
        return resp.url if resp.url else url
    except:
        try:
            resp = requests.get(url, allow_redirects=True, timeout=5, stream=True)
            return resp.url
        except:
            return url

def check_link(url):
    clear_screen()
    print(Fore.YELLOW + f"\n[~] Original URL: {url}")

    real_url = expand_url(url)
    if real_url != url:
        print(Fore.CYAN + f"[i] Real URL: {real_url}")
        url = real_url

    risk = 0
    reasons = []

    suspicious_domains = [
        "bit.ly", "tinyurl", "t.co", "cutt.ly", "2no.co",
        "grabify", "iplogger", "shorte.st", "ow.ly", "is.gd"
    ]
    for d in suspicious_domains:
        if d in url.lower():
            risk += 3
            reasons.append(f"Shortener/tracker domain: {d}")

    if "@" in url:
        risk += 1
        reasons.append("Contains '@' (phishing pattern)")
    if len(url) > 75:
        risk += 1
        reasons.append("Unusually long URL")
    keywords = ["login", "verify", "secure", "update", "bank", "account"]
    if any(k in url.lower() for k in keywords):
        risk += 1
        reasons.append("Suspicious keywords detected")

    if risk >= 4:
        print(Fore.RED + "\n[!!!] HIGH RISK (DANGEROUS)")
        print(Fore.RED + f"RISK SCORE: {min(risk*20, 100)}/100")
    elif risk >= 2:
        print(Fore.YELLOW + "\n[!] SUSPICIOUS LINK")
        print(Fore.YELLOW + f"RISK SCORE: {risk*20}/100")
    else:
        print(Fore.GREEN + "\n[✓] LOW RISK LINK")
        print(Fore.GREEN + f"RISK SCORE: {risk*10}/100")

    if reasons:
        print(Fore.WHITE + "\n--- DETECTION LOG ---")
        for r in reasons:
            print(Fore.RED + f"[+] {r}")

    input(Fore.WHITE + "\nPress Enter to continue...")

def scan_ports(target, custom_ports=None):
    clear_screen()
    print(Fore.YELLOW + f"\n[~] Scanning: {target}")
    try:
        ip = socket.gethostbyname(target)
        print(Fore.CYAN + f"[i] IP: {ip}")
    except:
        print(Fore.RED + "[!] Cannot resolve target")
        input(Fore.WHITE + "\nPress Enter to continue...")
        return

    if custom_ports is None:
        ports = [21,22,23,25,53,80,110,443,445,3306,3389,8080]
    else:
        ports = custom_ports

    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
    }

    print(Fore.WHITE + "\n--- OPEN PORTS ---")
    open_ports = 0
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                service = services.get(port, "Unknown")
                print(Fore.GREEN + f"[OPEN] {port} ({service})")
                open_ports += 1
            s.close()
        except:
            pass
    if open_ports == 0:
        print(Fore.RED + "[!] No open ports found")
    print(Fore.WHITE + "-----------------")
    input(Fore.WHITE + "\nPress Enter to continue...")

def geo_ip(ip_or_domain):
    clear_screen()
    print(Fore.CYAN + f"\n[~] Geolocating: {ip_or_domain}")
    try:
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_or_domain):
            ip_or_domain = socket.gethostbyname(ip_or_domain)
            print(Fore.CYAN + f"[i] Resolved IP: {ip_or_domain}")
        resp = requests.get(f"http://ip-api.com/json/{ip_or_domain}", timeout=5).json()
        if resp["status"] == "success":
            print(Fore.WHITE + "\n--- GEO INFO ---")
            print(f"Country : {resp['country']}")
            print(f"City    : {resp['city']}")
            print(f"ISP     : {resp['isp']}")
            print(f"Lat/Lon : {resp['lat']}, {resp['lon']}")
            print("----------------")
        else:
            print(Fore.RED + "[!] Information not found")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")
    input(Fore.WHITE + "\nPress Enter to continue...")

def dns_lookup(domain):
    clear_screen()
    print(Fore.CYAN + f"\n[~] Resolving: {domain}")
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"IP: {ip}")
        try:
            name = socket.gethostbyaddr(ip)[0]
            print(Fore.GREEN + f"Reverse: {name}")
        except:
            pass
    except:
        print(Fore.RED + "[!] Cannot resolve")
    input(Fore.WHITE + "\nPress Enter to continue...")

def full_scan(target):
    clear_screen()
    print(Fore.MAGENTA + "\n[***] FULL SCAN ***")
    if target.startswith(('http://', 'https://')):
        real_target = target
        check_link(real_target)  # This will print inside but we need to avoid double input
        # Extract domain
        parsed = urlparse(real_target)
        domain = parsed.netloc
        if domain:
            print(Fore.CYAN + f"\n[i] Extracted domain: {domain}")
            scan_ports(domain)
            geo_ip(domain)
    else:
        scan_ports(target)
        geo_ip(target)
    input(Fore.WHITE + "\nPress Enter to continue...")

def menu():
    while True:
        clear_screen()
        logo()
        print(Fore.CYAN + """
╔══════════════════════════════╗
║  SCANNR - TOOL       ║
╠══════════════════════════════╣
║ [1] Analyze Link             ║
║ [2] Port Scan                ║
║ [3] Geolocate IP/Domain      ║
║ [4] DNS Lookup               ║
║ [5] Full Scan                ║
║ [0] Exit                     ║
╚══════════════════════════════╝
""")
        option = input("SCANNR > ").strip()

        if option == "1":
            url = input("URL (include http:// or https://): ").strip()
            if not url.startswith(('http://', 'https://')):
                url = "http://" + url
            check_link(url)
        elif option == "2":
            target = input("Domain or IP: ").strip()
            ports_input = input("Custom ports? (e.g., 80,443,8080 or empty): ").strip()
            if ports_input:
                try:
                    ports = [int(p.strip()) for p in ports_input.split(',')]
                    scan_ports(target, ports)
                except:
                    print(Fore.RED + "[!] Invalid format, using default ports")
                    scan_ports(target)
            else:
                scan_ports(target)
        elif option == "3":
            target = input("IP or domain: ").strip()
            geo_ip(target)
        elif option == "4":
            domain = input("Domain or IP: ").strip()
            dns_lookup(domain)
        elif option == "5":
            target = input("URL, domain or IP: ").strip()
            full_scan(target)
        elif option == "0":
            clear_screen()
            print(Fore.GREEN + "Exiting... Goodbye!")
            sys.exit(0)
        else:
            print(Fore.RED + "Invalid option")
            input(Fore.WHITE + "\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        clear_screen()
        print(Fore.YELLOW + "\n[!] Interrupted. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[!] Unexpected error: {e}")
        sys.exit(1)