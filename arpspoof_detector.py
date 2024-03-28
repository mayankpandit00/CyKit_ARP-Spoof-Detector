import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to sniff")
    (arguments, options) = parser.parse_args()

    ifconfig_results = subprocess.check_output(["ifconfig"])
    all_interfaces = re.findall(r"[a-z]{3,4}\d", str(ifconfig_results))

    if (not arguments.interface or not bool(re.match(r"^[a-z]{3,4}\d$", arguments.interface)) or
            arguments.interface not in all_interfaces):
        print("[-] Invalid input; Please specify an interface; Use -h or --help for more info")
    else:
        return arguments


def get_mac_for_ip(ip):
    answered_arp_request_list = scapy.srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=1, verbose=False)[0]
    return answered_arp_request_list[0][1].hwsrc


def sniff_packets(interface):
    print("[+] Starting ARP spoof detector")
    print("[+] ARP spoof detector started successfully!")
    print("[+] Sniffing packets at " + interface + "\n")
    scapy.sniff(iface=interface, store=False, prn=processed_packets)


def processed_packets(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        try:
            real_gateway_mac = get_mac_for_ip(packet[ARP].psrc)
            arp_response_mac = packet[ARP].hwsrc

            if real_gateway_mac != arp_response_mac:
                print("[+] You are under attack !")

        except IndexError:
            pass


arguments = get_arguments()
sniff_packets(arguments.interface)
