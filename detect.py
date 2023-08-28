import sys
from decimal import Decimal
# import time
# import schedule
import socket
# from DBhandler import getAddress, saveflaggedAddress, getFlaggedAddress, createTable
from scapy.all import sniff, ARP, IP, Ether, TCP

# # get the ip range from the arguments passes by the GUI
# # target_ip_range = sys.argv[1]
# # IotIP = sys.argv[2]
# # IotPort = sys.argv[3]

# #testing
# IotIP = "0.0.0.0"
# IotPort = "4455"

# dbList = []
# flaggedList = []

# # When you see this know that you are working on scanning the network and checking if the blocked 
# # MAC address is trying to access the IOT device. Then blocking the connection.

print('working')

from scapy.all import *

# Define the IP address and port of your IoT device
iot_device_ip = sys.argv[1]
iot_device_port = int(sys.argv[2])

def packet_handler(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if dst_ip == iot_device_ip and packet[TCP].dport == iot_device_port:
            ether_packet = Ether(raw(packet))
            src_mac = ether_packet.src

            print(f"Packet captured from device {src_ip}:{packet[TCP].sport} to {iot_device_ip}:{iot_device_port}")
            print(f"Source MAC: {src_mac}")
            print("=" * 40)

def main():
    # Set up packet capturing on the desired network interface
    interface = "eth0"  # Replace with your network interface
    sniff(filter=f"ip and dst host {iot_device_ip} and dst port {iot_device_port}", prn=packet_handler, iface=interface)

if __name__ == "__main__":
    main()










# import socket
# from scapy.all import ARP, Ether, srp

# allowed_macs = ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"]  # List of allowed MAC addresses
# target_ip = sys.argv[1]
# target_port = int(sys.argv[2])

# def get_mac_address(ip):
#     arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
#     result = srp(arp_request, timeout=2, verbose=0)[0]

#     if result:
#         return result[0][1].hwsrc

# def main():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind((target_ip, target_port))
#     server_socket.listen(1)

#     print(f"Listening on {target_ip}:{target_port}...")

#     try:
#         while True:
#             client_socket, client_address = server_socket.accept()
#             client_ip, _ = client_address


#             print(f"Incoming connection from {client_ip}")

#             client_mac = get_mac_address(client_ip)
#             if client_mac is None:
#                 print("Failed to retrieve MAC address.")
#             else:
#                 if client_mac in allowed_macs:
#                     print(f"Allowed MAC address: {client_mac}")
#                 else:
#                     print(f"Blocked MAC address: {client_mac}")

#             client_socket.close()

#     except KeyboardInterrupt:
#         print("Server stopped.")
#     finally:
#         server_socket.close()

# if __name__ == "__main__":
#     main()


# createTable()

# def scanAndFlag():
#     db = getAddress()
#     for data in db:
#         dbList.append(data[2])

#     for data in getFlaggedAddress():
#         flaggedList.append(data[2])

#     # client_socket, client_address = socket.accept()
#     scannedIp = scan.scan_network(target_ip_range)
#     found = False



    

#     for ip in scannedIp:
#         if ip['mac'] not in dbList and ip['mac'] not in flaggedList:
#             found = True
#             print(f"flagged {ip['ip']}")

#             # block the ip
#             try:
#                 server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                 server_socket.bind((IotIP, IotPort))
#                 server_socket.listen(1)

#                 client_socket, client_address = server_socket.accept()
#                 client_socket.close()

#                 saveflaggedAddress(ip['ip'], ip['mac'])
#             except:
#                 server_socket.close()

#         else:
#             message = "No new intruder detected"

#     if found == False:
#         print(message)


# schedule.every(5).minutes.do(scanAndFlag)

# while True:
#     schedule.run_pending()
#     time.sleep(1)

