import ipinfo
import os
import subprocess
import socket
import whois
import dns.resolver
import requests
from colorama import init, Fore, Style

def get_ip_info(ip):
    access_token = "8c6e00a9812edd"
    handler = ipinfo.getHandler(access_token)
    details = handler.getDetails(ip)
    return details

def print_ip_info(ip_info, verbose=False):
    print(Fore.CYAN + "IP Information:")
    print(Style.RESET_ALL + "---------------")
    print(f"IP Address: {ip_info.ip}")
    print(f"Hostname: {ip_info.hostname}")
    print(f"City: {ip_info.city}")
    print(f"Region: {ip_info.region}")
    print(f"Country: {ip_info.country}")
    print(f"Location: {ip_info.loc}")
    print(f"Postal Code: {ip_info.postal}")
    print(f"Organization/ISP: {ip_info.org}")
    print(f"Timezone: {ip_info.timezone}")
    if verbose:
        print(f"ASN: {ip_info.asn}")
        print(f"Company: {ip_info.company}")
        print(f"Carrier: {ip_info.carrier}")
        print(f"Hosting: {ip_info.hosting}")
        print(f"Proxy: {ip_info.proxy}")
    print("---------------")

def ping_ip(ip):
    try:
        output = subprocess.check_output(['ping', '-c', '4', ip]).decode('utf-8')
        print(Fore.GREEN + "Ping Results:")
        print(Style.RESET_ALL + "---------------")
        print(output)
    except subprocess.CalledProcessError:
        print(Fore.RED + "Error: Unable to ping the IP address.")

def reverse_dns_lookup(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(Fore.YELLOW + "Reverse DNS Lookup:")
        print(Style.RESET_ALL + "---------------")
        print(f"Hostname: {hostname}")
    except socket.herror:
        print(Fore.RED + "Error: Unable to perform reverse DNS lookup.")

def traceroute(ip):
    try:
        output = subprocess.check_output(['traceroute', '-m', '15', ip]).decode('utf-8')
        print(Fore.BLUE + "Traceroute Results:")
        print(Style.RESET_ALL + "---------------")
        print(output)
    except subprocess.CalledProcessError:
        print(Fore.RED + "Error: Unable to perform traceroute.")

def port_scan(ip):
    try:
        print(Fore.MAGENTA + "Port Scan:")
        print(Style.RESET_ALL + "---------------")
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"Port {port}: Open")
            sock.close()
    except socket.gaierror:
        print(Fore.RED + "Error: Unable to perform port scan.")

def whois_lookup(ip):
    try:
        print(Fore.MAGENTA + "WHOIS Lookup:")
        print(Style.RESET_ALL + "---------------")
        whois_info = whois.whois(ip)
        print(whois_info)
    except Exception as e:
        print(Fore.RED + "Error: Unable to perform WHOIS lookup.")

def dns_records(ip):
    try:
        print(Fore.MAGENTA + "DNS Records:")
        print(Style.RESET_ALL + "---------------")
        resolver = dns.resolver.Resolver()
        result = resolver.query(ip, 'A')
        print("A Records:")
        for ip in result:
            print(ip)
    except Exception as e:
        print(Fore.RED + "Error: Unable to retrieve DNS records.")

def http_headers(ip):
    try:
        print(Fore.MAGENTA + "HTTP Headers:")
        print(Style.RESET_ALL + "---------------")
        response = requests.get(f"http://{ip}")
        headers = response.headers
        for key, value in headers.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(Fore.RED + "Error: Unable to retrieve HTTP headers.")

def main():
    init(autoreset=True)  # Initialize colorama
    print(Fore.MAGENTA + "-----------------------------------")
    print("|      IP Information Checker     |")
    print("-----------------------------------")

    while True:
        ip = input("\nEnter IP address or domain name (or 'q' to quit, 'h' for help): ")
        if ip.lower() == 'q':
            break
        elif ip.lower() == 'h':
            print_help()
            continue
        elif ip.lower() == 'c':
            clear_screen()
            continue

        try:
            ip_info = get_ip_info(ip)
            print_ip_info(ip_info)
            save_option = input("Do you want to save the results to a file? (y/n): ")
            if save_option.lower() == 'y':
                save_to_file(ip_info)
            verbose_option = input("Do you want to display verbose information? (y/n): ")
            if verbose_option.lower() == 'y':
                print_ip_info(ip_info, verbose=True)
            ping_option = input("Do you want to ping the IP address? (y/n): ")
            if ping_option.lower() == 'y':
                ping_ip(ip)
            reverse_dns_option = input("Do you want to perform a reverse DNS lookup? (y/n): ")
            if reverse_dns_option.lower() == 'y':
                reverse_dns_lookup(ip)
            traceroute_option = input("Do you want to perform a traceroute? (y/n): ")
            if traceroute_option.lower() == 'y':
                traceroute(ip)
            port_scan_option = input("Do you want to perform a port scan? (y/n): ")
            if port_scan_option.lower() == 'y':
                port_scan(ip)
            whois_option = input("Do you want to perform a WHOIS lookup? (y/n): ")
            if whois_option.lower() == 'y':
                whois_lookup(ip)
            dns_records_option = input("Do you want to retrieve DNS records? (y/n): ")
            if dns_records_option.lower() == 'y':
                dns_records(ip)
            http_headers_option = input("Do you want to retrieve HTTP headers? (y/n): ")
            if http_headers_option.lower() == 'y':
                http_headers(ip)
        except Exception as e:
            print(Fore.RED + "Error:", e)

def print_help():
    print("\nCommands:")
    print("  - Enter an IP address or domain name to check its information.")
    print("  - 'q' to quit the program.")
    print("  - 'h' for help (display this message).")
    print("  - 'c' to clear the screen.")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def save_to_file(ip_info):
    filename = input("Enter filename to save (without extension): ")
    directory = "saves"
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(os.path.join(directory, f"{filename}.txt"), "w") as file:
        file.write("IP Information:\n")
        file.write("---------------\n")
        file.write(f"IP Address: {ip_info.ip}\n")
        file.write(f"Hostname: {ip_info.hostname}\n")
        file.write(f"City: {ip_info.city}\n")
        file.write(f"Region: {ip_info.region}\n")
        file.write(f"Country: {ip_info.country}\n")
        file.write(f"Location: {ip_info.loc}\n")
        file.write(f"Postal Code: {ip_info.postal}\n")
        file.write(f"Organization/ISP: {ip_info.org}\n")
        file.write(f"Timezone: {ip_info.timezone}\n")

if __name__ == "__main__":
    main()
