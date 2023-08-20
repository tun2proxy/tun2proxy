import dns.message
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 0))

s.sendto(dns.message.make_query('example.org', 'A').to_wire(), ('8.8.8.8', 53))
s.sendto(dns.message.make_query('example.org', 'AAAA').to_wire(), ('8.8.8.8', 53))

data, _ = s.recvfrom(0xffff)
print(dns.message.from_wire(data))
data, _ = s.recvfrom(0xffff)
print(dns.message.from_wire(data))
