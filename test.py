import scan
import socket
import time
import schedule
from DBhandler import getAddress, saveflaggedAddress, getFlaggedAddress, createTable

host = socket.gethostbyaddr(socket.gethostname())
port = 5678


# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect((host, port))
# s.listen(5)
target_ip_range = "192.168.75.0/24"
dbList = []
flaggedList = []

createTable()

def scanAndFlag():
    db = getAddress()
    for data in db:
        dbList.append(data[1])

    for data in getFlaggedAddress():
        flaggedList.append(data[1])

    # client_socket, client_address = socket.accept()
    scannedIp = scan.scan_network(target_ip_range)
    found = False

    for ip in scannedIp:
        if ip['ip'] not in dbList and ip['ip'] not in flaggedList:
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

