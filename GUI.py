from PyQt5 import QtWidgets, uic
import sys
import scan
import DBhandler
import subprocess

sys.path.append("./env/lib/python3.10/site-packages")
import qtvscodestyle as qtvsc

process = None

class Ui(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui, self).__init__()
        uic.loadUi('intrusion.ui', self)
        self.show()
        self.dir = ''
        self.dbPopulate()
        # self.flaggedPopulate()
        # self.terminate_other_script()

        #callbacks
        self.pushButton.clicked.connect(self.allowip)
        self.saveButton.clicked.connect(self.saveIP)
        self.saveButton_2.clicked.connect(self.scanPopulate)


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
        network = self.lineEdit.text()
        subnet = self.lineEdit_2.text()
        target_ip_range = network + subnet

        results = scan.scan_network(target_ip_range)

        count = 0
        self.listWidget.clear()
        for result in results:
            print(f"  {result['ip']}  {result['mac']}")
            self.listWidget.addItem(f"{count}\t{result['hostname']}\t{result['ip']}\t{result['mac']}")
            count+=1
            


    def allowip(self):
        clicked = self.listWidget.currentRow()
        item = self.listWidget.takeItem(clicked)
        splitItem = item.split(" ")
        print(splitItem)

        # self.listWidget_2.addItem(item)

    def saveIP(self):
        items = []
        DBhandler.createTable()

        for i in range(self.listWidget_2.count()):
            items.append(self.listWidget_2.item(i))
        
        #get a list of the already saved list for comparison
        datas = DBhandler.getAddress()
        dataList =[]
        for data in datas:
            dataList.append(data[2])

        for item in items:
            data = item.text()
            splitData = data.split(" ")
        print(splitData)
            
            #checking if the data about to be saved is already present
            # if splitData[4] not in dataList:
            #     # DBhandler.saveAddress(splitData[2], splitData[4])#this is where the ipaddress and mac are located
            #     print(splitData[2], splitData[4])
            #     print(split)

        self.run_other_script()
        self.close()

    def dbPopulate(self):
        try:
            datas = DBhandler.getAddress()
            for data in datas:
                self.listWidget_2.addItem(f"{data[1]}  {data[2]}")
                
        except(Exception):
            pass
    
    def flaggedPopulate(self):
        try:
            datas = DBhandler.getFlaggedAddress()
            for data in datas:
                self.listWidget_3.addItem(f"  {data[1]}  {data[2]}")
                
        except(Exception):
            pass


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    # the sytlesheet i'm using for the project
    qtvsc.list_themes()
    stylesheet = qtvsc.load_stylesheet(qtvsc.Theme.DARK_VS)
    app.setStyleSheet(stylesheet)
    window = Ui()
    app.exec_()