from scapy.all import ARP, Ether, srp
import socket
from DBhandler import getAddress, saveAddress, createTable

def get_hostname(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return None

def scan_network(ip_range):
    # create ARP packet
    arp = ARP(pdst=ip_range)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        hostname = get_hostname(received.psrc) or "Unknown"
        clients.append({'hostname': hostname, 'ip': received.psrc, 'mac': received.hwsrc})
    return clients

        