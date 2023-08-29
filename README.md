
# Intrusion Detection System For IoT Devices

The purpose of this script is to identify all devices connected to your network and provide alerts about any untrusted ones. This functionality can be helpful to monitor anyone trying to get access to your IoT network. The script operates quickly, and you can set it to run at intervals as short as every 30 seconds.

This script scans a network that you specify and issues alerts for any devices that are not included in the list of allowed devices in the database. The whitelist or allowed devices comprises MAC addresses that you personally trust. Initially, when you execute the script for the first time, the allowed IP list will be empty. It's your responsibility to gradually populate the allowed IP with MAC addresses of devices you consider trustworthy.

For more details on the whitelist, refer to the corresponding section.

## Getting Started

These instructions will assist you in obtaining a copy of the project and setting it up on your local machine for development and testing purposes. For information on deploying the project in a live environment, please consult the deployment section.

### Prerequisites

Software Requirements: python3

## Cloning And Running

1. Clone the application to your local environment and set up a virtual environment.
2. CD into the application and run `pip install -r requirements.txt`. This will install all the modules needed to run the application.
3. Run the `GUI.py` file and proceed to use the application.
4. More about using the GUI can be located in the about section in the GUI application.

The database filename is `database.db`, it is an sqlite3 database. It will be created if absent. The network must be specified in the network/mask notation.

Example of valid networks:

- 192.168.0.0/24
- 192.168.1.0/24
- 192.168.2.0/24

You should launch all programs with `sudo`:

- `detect.py`: This file is responsible for scanning the network and identifying MAC addresses not specified or allowed. `nmon` requires root privileges to get the MAC addresses.
- `scan.py`: Scans the network and returns a list of available devices. It also requires root privileges.
- `DBhandler.py`: This python file is responsible for connecting and passing queries to the database. It is used to add, delete or get items from the database.
- `GUI.py`: This is the python file that connects with the UI and gives a graphical interface of the application.
- `intrusion.ui`: An XML file that contains the blueprint for the GUI.
```
Just save this content in a `.md` file, and it will be correctly formatted as Markdown text.