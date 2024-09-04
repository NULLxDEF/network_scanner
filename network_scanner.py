#!/usr/bin/env python

import scapy.all as scapy
import optparse
import re
import socket
import netifaces
import time
import sys
from threading import Thread, Event

# Function to get the local IP address of the machine
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error:
        return None

# Function to get the interface and its IP address
def get_interface_info():
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            return interface, addrs[netifaces.AF_INET][0]['addr']
    return None, None

# Function to parse command-line arguments
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="range", help="Network range to scan.")
    (options, arguments) = parser.parse_args()

    # Use local IP if no range is specified
    if not options.range:
        local_ip = get_local_ip()
        if local_ip:
            print(f"\n[-] Using local IP address: {local_ip}/24")
            options.range = f"{local_ip}/24"
        else:
            parser.error("[-] Please specify TARGET IP / RANGE, use --help for more info.")

    # Validate the IP range format
    if not is_valid_ip(options.range):
        parser.error("[-] Invalid input. Please provide a valid network range.")

    return options

# Function to validate the IP address format
def is_valid_ip(input_string):
    ip_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-2]?[0-9]|/3[0-2])?$')
    return re.fullmatch(ip_regex, input_string) is not None

# Function to perform ARP scan on the given IP range
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

    clients_list = []
    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

# Function to print the scan results
def print_result(results_list):
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

# Function to continuously scan the network
def scan_loop(options, stop_event):
    while not stop_event.is_set():
        scan_result = scan(options.range)
        print_result(scan_result)
        print("\r------------------------------------------------------------")
        time.sleep(5)  # Adjust the sleep interval as needed

# Main function to handle program execution
def main():
    options = get_arguments()
    stop_event = Event()

    try:
        print("Press 'q' or Ctrl+C to quit.\n")
        print("\rIP\t\t\tMAC Address")
        print("\r------------------------------------------------------------")
        scan_thread = Thread(target=scan_loop, args=(options, stop_event))
        scan_thread.start()

        scan_thread.join()
    except (KeyboardInterrupt, SystemExit):
        print("\n[-] Exiting gracefully.")
        stop_event.set()
        sys.exit(0)

if __name__ == "__main__":
    main()

