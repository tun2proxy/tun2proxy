import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 1337))
    s.listen()
    conn, addr = s.accept()
    with conn:
        conn.sendall('I am closing the write end, but I can still receive data'.encode())
        conn.shutdown(socket.SHUT_WR)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(data.decode())
