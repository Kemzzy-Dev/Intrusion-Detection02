from PyQt5 import QtWidgets, uic
import sys
import qtvscodestyle as qtvsc
import scan
import DBhandler
import subprocess

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

        # #callbacks
        self.allowIP.clicked.connect(self.allowip)
        self.save.clicked.connect(self.saveIP)
        self.scan.clicked.connect(self.scanPopulate)
        self.exit.clicked.connect(self.closeWindow)
        self.saveAndExit.clicked.connect(self.saveandexit)


        #functions
    def run_other_script(self):
        global process
        # Start the other Python script as a subprocess
        process = subprocess.run(['python3', 'test.py'], capture_output=True, text=True)

    def terminate_other_script(self):
        global process
        if process and process.poll() is None:
            # Terminate the subprocess if it's still running
            process.terminate()

    def scanPopulate(self):
        network = self.network.text()
        subnet = self.subnet.text()
        target_ip_range = network + subnet

        results = scan.scan_network(target_ip_range)

        count = 0
        self.detectedIP.clear()
        for result in results:
            self.detectedIP.addItem(f"{count}\t{result['hostname']}\t{result['ip']}\t{result['mac']}")
            count+=1
            
    def closeWindow(self):
        self.close()
    
    def saveandexit(self):
        self.saveIP()
        self.close()

    def allowip(self):
        clicked = self.detectedIP.currentRow()
        item = self.detectedIP.takeItem(clicked).text()
        splitItem = item.split("\t")

        for i in range(self.allowedIP.count()):
            if splitItem[3] != self.allowedIP.item(i).text().split(" ")[4]:
                self.allowedIP.addItem(f"{self.count}  {splitItem[2]}  {splitItem[3]}")
                self.count += 1
            else:
                print('Already present')
        
        

    #this function compares mac address instead of IP addresses
    def saveIP(self):
        items = []
        flaggedItems = []
        DBhandler.createTable()

        for i in range(self.allowedIP.count()):
            items.append(self.allowedIP.item(i))
        
        #get a list of the already saved list for comparison
        dataset = DBhandler.getAddress()
        dataList =[]
        for data in dataset:
            dataList.append(data[2])

        flaggeddataset = DBhandler.getFlaggedAddress()
        flaggeddataList =[]
        for data in flaggeddataset:
            flaggeddataList.append(data[2])
        
        #get the items from the availble ip list items
        for item in items:
            data = item.text()
            splitData = data.split(" ")
            
            #checking if the data about to be saved is already present
            if splitData[4] not in dataList and splitData[4] not in flaggeddataList:
                DBhandler.saveAddress(splitData[2], splitData[4])#this is where the ipaddress and mac are located

        # self.run_other_script()
        # self.close()

    def dbPopulate(self):
        try:
            self.count = 0
            datas = DBhandler.getAddress()
            for data in datas:
                self.allowedIP.addItem(f"{self.count}  {data[1]}  {data[2]}")
                self.count+=1
                
        except(Exception):
            pass
    
    def flaggedPopulate(self):
        try:
            datas = DBhandler.getFlaggedAddress()
            for data in datas:
                self.flaggedIP.addItem(f"  {data[1]}  {data[2]}")
                
        except(Exception):
            pass




if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    # the sytlesheet i'm using for the project
    stylesheet = qtvsc.load_stylesheet(qtvsc.Theme.DARK_VS)
    app.setStyleSheet(stylesheet)
    window = Ui()
    app.exec_()