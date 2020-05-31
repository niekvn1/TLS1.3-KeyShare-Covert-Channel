import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("nice.prac.os3.nl", 5001))
s.listen(1)
s.accept()

msg = socket.recv(2048)
print(msg)
