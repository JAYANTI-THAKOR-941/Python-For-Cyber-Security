import socket

print(socket.gethostname())
print(socket.getdefaulttimeout())
print(socket.getfqdn())
print(socket.gethostbyname(socket.gethostname()))