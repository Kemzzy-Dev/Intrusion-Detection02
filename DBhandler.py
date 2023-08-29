import sqlite3

# connect
conn = sqlite3.connect("database.db")
cursor = conn.cursor()

def createTable():
    cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS addresses(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ipaddress TEXT,
                mac_address TEXT)
        ''')
    cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS flaggedAddresses(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ipaddress TEXT,
                mac_address TEXT)
        ''')
    conn.commit()

# add an ip or mac address to the database
def saveAddress(ipaddress, mac_address):
    cursor.execute('''
        INSERT INTO addresses(ipaddress, mac_address) VALUES(?, ?)
    ''', (ipaddress, mac_address))
    conn.commit()

# save any address that has been flag
def saveflaggedAddress(ipaddress, mac_address):
    cursor.execute('''
        INSERT INTO flaggedAddresses(ipaddress, mac_address) VALUES(?, ?)
    ''', (ipaddress, mac_address))
    conn.commit()

#to get all the saved/allowed address
def getAddress():
    cursor.execute('''
        SELECT * FROM addresses 
    ''') 
    data = cursor.fetchall()

    return data

#to get all the flagged address
def getFlaggedAddress():
    cursor.execute('''
        SELECT * FROM flaggedAddresses 
    ''') 
    data = cursor.fetchall()

    return data

# to delete an ip from the database
def deleteAddress():
    cursor.execute('''
        DELETE FROM addresses
    ''') 
    conn.commit()

