import socket

ip_address = "0.0.0.0"
port = 4455

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the IP address and port
server_socket.bind((ip_address, port))

# Listen for incoming connections
server_socket.listen()

print("Server listening on", ip_address, "port", port)

while True:
    # Accept a connection from a client
    client_socket, client_address = server_socket.accept()
    
    print("Connection established with", client_address)
    
    # Send a welcome message to the client
    message = "Welcome to the server!"
    client_socket.send(message.encode())
    
    # Close the connection with the client
    client_socket.close()
