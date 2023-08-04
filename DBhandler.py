import sqlite3


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

def saveAddress(ipaddress, mac_address):
    cursor.execute('''
        INSERT INTO addresses(ipaddress, mac_address) VALUES(?, ?)
    ''', (ipaddress, mac_address))
    conn.commit()

def saveflaggedAddress(ipaddress, mac_address):
    cursor.execute('''
        INSERT INTO flaggedAddresses(ipaddress, mac_address) VALUES(?, ?)
    ''', (ipaddress, mac_address))
    conn.commit()

def getAddress():
    cursor.execute('''
        SELECT * FROM addresses 
    ''') 
    data = cursor.fetchall()

    return data

def getFlaggedAddress():
    cursor.execute('''
        SELECT * FROM flaggedAddresses 
    ''') 
    data = cursor.fetchall()

    return data

def deleteAddress():
    cursor.execute('''
        DELETE FROM addresses
    ''') 
    conn.commit()

