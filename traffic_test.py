import socket
import time

CAMERA_IP = "192.168.1.10"
PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

payload = b"HELLO_OMID_" + b"X" * 990

for i in range(1000):
    sock.sendto(payload, (CAMERA_IP, PORT))
    time.sleep(0.01)

print("Sent 1000 packets")
