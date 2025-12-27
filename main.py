import socket
from rich import print
import requests
import os
import hashlib


def scanner_banner():
    banner = r"""
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

    [*] Port Scanner with Service Detection
"""
    print(banner) 
    

def clean_target(target):
    target = target.strip()

    if target.startswith("http://"):
        target = target
    elif target.startswith("https://"):
        target = target

    if target.startswith("www."):
        target = target

    return target

def scanner():
    common = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }

    scanner_banner()
    target = input("Enter Target IP or Hostname: ").strip()

    target = clean_target(target)
 
    print(f"\nScanning {target} for common ports...\n")

    for port, service in common.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))

            if result == 0:
                print(f"[green][OPEN][/] {port} : {service}")

            s.close()
        except socket.error:
            print(f"[red][!][/] Error scanning port {port}")


def directory_enumeration():
    
    banner = r"""
██████╗ ██╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗
██╔══██╗██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
██║  ██║██║██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝ ╚████╔╝ 
██║  ██║██║██╔══██╗██╔══╝  ██║        ██║   ██║   ██║██╔══██╗  ╚██╔╝  
██████╔╝██║██║  ██║███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║   ██║   
╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   

          D I R E C T O R Y   E N U M E R A T I O N
"""
    print(banner) 

    target = input("Enter The Domain Name or The IP: ").strip()

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    print(f"\n[blue] Trying to find common directories on : {target} [/]\n")

    
    try:
        with open("directory.txt", "r") as f:
            wordlist = f.read().splitlines()
    except FileNotFoundError:
        print("[red][!][/] Wordlist file not found!")
        return

    for directory in wordlist:
        url = target + "/" + directory

        try:
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                print(f"[green][FOUND][/] {url}")

            elif response.status_code == 403:
                print(f"[yellow][FORBIDDEN][/] {url}")

        except requests.exceptions.RequestException:
            pass

        

def subdomain_enumeration():
    
    banner = r"""
███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
███████╗██║   ██║██████╔╝██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

               S U B D O M A I N   E N U M E R A T I O N
"""
    print(banner) 

    domain = input("Enter The Target Domain (example.com) : ").strip()


    print(f"\n[*] Enumerating subdomains for {domain}\n")

    #
    try:
        with open("subdomains.txt", "r") as f:
            subdomains = f.read().splitlines()
    except FileNotFoundError:
        print("[!] subdomains.txt not found!")
        return

    for sub in subdomains:
        url = f"http://{sub}.{domain}"

        try:
            response = requests.get(url, timeout=5)

            if response.status_code in [200, 301, 302, 403]:
                print(f"[FOUND] {url} ({response.status_code})")

        except requests.exceptions.RequestException:
            pass

def detect_hash_type(hash_value):
    length = len(hash_value)

    hash_types = {
        32: "md5",
        40: "sha1",
        56: "sha224",
        64: "sha256",
        96: "sha384",
        128: "sha512"
    }

    return hash_types.get(length, None)


def hash_cracker():
    banner = r"""
██╗  ██╗ █████╗ ███████╗██╗  ██╗     ██████╗██████╗  █████╗  ██████╗██╗  ██╗
██║  ██║██╔══██╗██╔════╝██║  ██║    ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
███████║███████║███████╗███████║    ██║     ██████╔╝███████║██║     █████╔╝ 
██╔══██║██╔══██║╚════██║██╔══██║    ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
██║  ██║██║  ██║███████║██║  ██║    ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
"""
    print(banner)

    hash_value = input("Enter the hash to crack: ").strip().lower()
    hash_type = detect_hash_type(hash_value)

    if not hash_type:
        print("[red][!][/] Unknown or unsupported hash type")
        return

    print(f"[blue][*][/] Detected hash type: {hash_type.upper()}")

    if not os.path.exists("passwords.txt"):
        print("[red][!][/] passwords.txt not found!")
        return

    print("[yellow][*][/] Cracking hash, please wait...\n")

    with open("passwords.txt", "r", errors="ignore") as wordlist:
        for word in wordlist:
            word = word.strip()

            hashed_word = getattr(hashlib, hash_type)(
                word.encode("utf-8")
            ).hexdigest()

            if hashed_word == hash_value:
                print(f"[green][+][/] HASH CRACKED!")
                print(f"[green][+][/] Password:[blue]{word} [/] ")
                return

    print("[red][✘][/] Password not found in wordlist")



def reconx_banner():
    banner = f"""

██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗       ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║       ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ██████ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║        ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝  ╚═╝

[green]            ░▒▓  R E C O N - X  ▓▒░  [/]

        Name    : Recon-X
        Author  : Mansri Wissem
        Purpose : Educational Only / CTF Player

[red bold]        [!] Authorized Use Only [/]

"""
    print(banner) 



def main():
    while True:
        reconx_banner()
        print("""
        \t[1] Port Scanner                 - Scan Common Open Ports  
        \t[2] Directory Enumeration        - Enumerate The Hidden Directorys 
        \t[3] Subdomain Enumeration        - Enumerate The Hidden Sub-Domains
        \t[4] Hash Crack                   - Craking Given Hash (by default : using the rockyou.txt)
        \t[5] Exit                         - Stop And Exit 
""")
        try:
            choice = int(input("\t \tWannaTry ? >  "))
        except ValueError:
            continue

        if choice == 1:
            scanner()
        elif choice == 2:
            directory_enumeration()
        elif choice == 3:
            subdomain_enumeration()
        elif choice == 4 :
            hash_cracker()
        elif choice == 5:
            break
        else:
            print("Invalid choice!")
            choice = int(input("\t \tWannaTry ? >  "))


if __name__ == "__main__":
    main()
