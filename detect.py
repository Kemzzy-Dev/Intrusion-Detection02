import scan
import sys
import time
import schedule
from DBhandler import getAddress, saveflaggedAddress, getFlaggedAddress, createTable

# get the ip range from the arguments passes by the GUI
target_ip_range = sys.argv[1]
dbList = []
flaggedList = []

createTable()

def scanAndFlag():
    db = getAddress()
    for data in db:
        dbList.append(data[2])

    for data in getFlaggedAddress():
        flaggedList.append(data[2])

    # client_socket, client_address = socket.accept()
    scannedIp = scan.scan_network(target_ip_range)
    found = False

    for ip in scannedIp:
        if ip['mac'] not in dbList and ip['mac'] not in flaggedList:
            found = True
            print(f"flagged {ip['ip']}")
            saveflaggedAddress(ip['ip'], ip['mac'])
        else:
            message = "No new intruder detected"

    if found == False:
        print(message)


schedule.every(10).seconds.do(scanAndFlag)

while True:
    schedule.run_pending()
    time.sleep(1)

