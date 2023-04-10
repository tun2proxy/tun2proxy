import socket
import sys
import time

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    ip, port = sys.argv[1].split(':', 1)
    port = int(port)
    s.connect((ip, port))
    while True:
        data = s.recv(1024)
        if not data:
            break
        print(data.decode())
    time.sleep(3)
    s.sendall('Message after server write end close'.encode())
