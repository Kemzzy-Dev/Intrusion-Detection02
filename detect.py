import sys
import scan
import time
import schedule
from DBhandler import getAddress, saveflaggedAddress, getFlaggedAddress, createTable
from scapy.all import sniff, ARP, IP, Ether, TCP

# get the ip range from the arguments passes by the GUI
target_ip_range = sys.argv[1]

dbList = []
flaggedList = []

createTable()

# scan for potential treats and flag if found
def scanAndFlag():
    db = getAddress()
    for data in db:
        dbList.append(data[2])

    for data in getFlaggedAddress():
        flaggedList.append(data[2])

    scannedIp = scan.scan_network(target_ip_range)
    found = False
    message = ''

    for ip in scannedIp:
         
        if ip['mac'] not in dbList and ip['mac'] not in flaggedList:
            found = True
            saveflaggedAddress(ip['ip'], ip['mac'])

        else:
            message = "No new intruder detected"

    if found == False:
        print(message)


schedule.every(5).seconds.do(scanAndFlag)

while True:
    schedule.run_pending()
    time.sleep(1)

