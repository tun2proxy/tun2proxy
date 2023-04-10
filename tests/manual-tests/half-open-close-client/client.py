import socket
import time

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('116.203.215.166', 1337))
    s.sendall('I am closing the write end, but I can still receive data'.encode())
    s.shutdown(socket.SHUT_WR)
    while True:
        data = s.recv(1024)
        if not data:
            break
        print(data.decode())
