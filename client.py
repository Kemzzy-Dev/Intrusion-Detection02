import socket

ip_address = "0.0.0.0"
port = 4455

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect((ip_address, port))

print("Connected to", ip_address, "on port", port)

# Remember to close the socket when done
client_socket.close()
