from PyQt5 import QtWidgets, uic
import sys
import qtvscodestyle as qtvsc
import scan
import DBhandler
import subprocess
import time
import socket

process = None
    
class Ui(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui, self).__init__()
        uic.loadUi('intrusion.ui', self)
        self.show()
        self.dir = ''
        self.dbPopulate()
        self.flaggedPopulate()
        self.terminate_other_script()

        # callbacks
        self.allowIP.clicked.connect(self.allowip)
        self.save.clicked.connect(self.saveMac)
        self.scan.clicked.connect(self.scanPopulate)
        self.exit.clicked.connect(self.closeWindow)
        self.saveAndExit.clicked.connect(self.saveandexit)
        self.actionApp.triggered.connect(self.about_window)
        self.actionHow_to_use.triggered.connect(self.help_window)


        #functions
    def scanPopulate(self):
        network = self.network.text()
        subnet = self.subnet.text()
        target_ip_range = network + subnet

        # check if wifi is available
        try:
            # Attempt to create a socket and connect to Google's DNS server
            socket.create_connection(("8.8.8.8", 53))
            connected = True
        except OSError:
            connected = False

        if connected:
            popup = QtWidgets.QDialog(self)
            popup.setWindowTitle("Scanning")

            label = QtWidgets.QLabel("Scanning....Please wait!!!!", popup)
            label.move(20, 20)
            
            popup.show()

            results = scan.scan_network(target_ip_range)
            count = 0
            self.detectedIP.clear()
            for result in results:
                self.detectedIP.addItem(f"{count}\t{result['hostname']}\t{result['ip']}\t{result['mac']}")
                count+=1

            popup.close()
        else:
            msg = QtWidgets.QMessageBox(self)
            msg.setIcon(QtWidgets.QMessageBox.Warning)
            msg.setWindowTitle('Help!')
            msg.setText("No wifi detected!!!")
            msg.exec_()
        
        
        
    # run the other script to detect malicious mac addresses
    def run_other_script(self):
        global process
        network = self.network.text()
        subnet = self.subnet.text()
        target_ip_range = network + subnet

        # Start the other Python script as a subprocess
        # var1 = target_ip_range
        var1 = self.iotIP.text()
        var2 = self.iotPort.text()
        process = subprocess.run(['python3', 'detect.py', var1, var2], text=True)

    # terminate the above script when application starts
    def terminate_other_script(self):
        global process
        if process and process.poll() is None:
            # Terminate the subprocess if it's still running
            process.terminate()

    # about the application
    def about_window(self):
        msg = QtWidgets.QMessageBox(self)
        msg.setWindowTitle('About')
        msg.setIcon(QtWidgets.QMessageBox.Information)
        msg.setText("""The idea behind this application is to find out all the devices connected to your network/IOT devices and alert you of the untrusted ones.
        It takes a few seconds to run, it runs every 5 minutes to check for intruders. This script will scan the network of your choice and will alert you of any devices not present in the whitelist. 
        
        The whitelist is a list of MAC address that YOU trust. The first time you run the application, the whitelist will be empty, it's up to up to add your trusted devices to the whitelist.
                        
        For information on how to use check the help menu.
                        """)
        x = msg.exec_()

    # help center
    def help_window(self):
        msg = QtWidgets.QMessageBox(self)
        msg.setIcon(QtWidgets.QMessageBox.Information)
        msg.setWindowTitle('Help!')
        msg.setText("""                                     How to use!!!

    1. Check for your network IP and copy the first 3 set of numbers and attach ".0" at the end e.g "192.168.22.0" or "192.163.222.0" 
    
    2. Paste the copied IP address in the network address section
    
    3. The default netmask is "/24". If your network netmask is different don't forget to modify this or leave as default 

    4. Enter the IP address and port of connection to the IOT device.
    
    5. Click on the scan button and wait for the application to scan your network for the list of devices connected to your network.
    
    6. A list of IP addresses and the corresponding MAC address will be displayed in the detected IP section 
    
    7. Click on the IP you want to add to the whitelist and click on allow device
    
    8. After selecting all, click on save and the application will save the selected IP to the allowed IP list
    
    9. Click on exit to start the script in the background.

            
                        """)
        x = msg.exec_()
            
    # exit the program 
    def closeWindow(self):
        self.close()
        self.run_other_script()
    
    # save the program and exit
    def saveandexit(self):
        self.saveMac()
        self.close()
        self.run_other_script()

    # function to add an ip to the whitelist
    def allowip(self):
        clicked = self.detectedIP.currentRow()
        item = self.detectedIP.item(clicked).text()
        splitItem = item.split("\t")

        if (self.allowedIP.count() > 0):
            for i in range(self.allowedIP.count()):
                if splitItem[3] != self.allowedIP.item(i).text().split(" ")[11]:
                    print(self.allowedIP.item(i).text().split(" "))

                    self.allowedIP.addItem(f"   {self.count}    {splitItem[2]}    {splitItem[3]}")
                    self.count += 1
                else:
                    msg = QtWidgets.QMessageBox(self)
                    msg.setIcon(QtWidgets.QMessageBox.Warning)
                    msg.setWindowTitle('Error')
                    msg.setText("DEVICE ALREADY PRESENT")
                    msg.exec_()

        else:
            self.allowedIP.addItem(f"   {self.count}    {splitItem[2]}    {splitItem[3]}")
            self.count += 1
        
    # saves the mac address
    def saveMac(self):
        items = []
        DBhandler.createTable()

        for i in range(self.allowedIP.count()):
            items.append(self.allowedIP.item(i))
        
        #get a list of the already saved list for comparison
        dataset = DBhandler.getAddress()
        dataList =[]
        for data in dataset:
            dataList.append(data[2])
        
        #get the items from the availble ip list items
        for item in items:
            data = item.text()
            splitData = data.split(" ")
            
            #checking if the data about to be saved is already present
            if splitData[11] not in dataList:
                DBhandler.saveAddress(splitData[7], splitData[11])#this is where the ipaddress and mac are located
        
        # display a saved window
        msg = QtWidgets.QMessageBox(self)
        msg.setIcon(QtWidgets.QMessageBox.Information)
        msg.setWindowTitle('Save!')
        msg.setText("   Saved!!!    ")
        msg.exec_()

    # poppulate the interface with a list of whitelisted mac addresses
    def dbPopulate(self):
        try:
            self.count = 0
            datas = DBhandler.getAddress()
            for data in datas:
                self.allowedIP.addItem(f"   {self.count}    {data[1]}    {data[2]}")
                self.count+=1
                
        except(Exception):
            pass
    
    # poppulate the interface with a list of flagged mac addresses
    def flaggedPopulate(self):
        try:
            datas = DBhandler.getFlaggedAddress()
            count = 0
            for data in datas:
                self.flaggedIP.addItem(f"   {count}    {data[1]}    {data[2]}")
                count +=1 
        except(Exception):
            pass



if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    # the sytlesheet i'm using for the project
    stylesheet = qtvsc.load_stylesheet(qtvsc.Theme.DARK_VS)
    app.setStyleSheet(stylesheet)
    window = Ui()
    app.exec_()