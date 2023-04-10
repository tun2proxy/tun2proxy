import socket
import time

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('116.203.215.166', 1337))
    while True:
        data = s.recv(1024)
        if not data:
            break
        print(data.decode())
    time.sleep(3)
    s.sendall('Message after server write end close'.encode())
