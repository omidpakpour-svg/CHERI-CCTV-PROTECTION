import socket
import time

TARGET = "192.168.1.10"
PORT = 55559
INTERFACE_IP = "192.168.1.25"
PAYLOAD = b"hello omid"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((INTERFACE_IP, 0))

print(f"Sending {PAYLOAD.decode()!r} to {TARGET}:{PORT}")
print("Ctrl+C to stop")

try:
    while True:
        sock.sendto(PAYLOAD, (TARGET, PORT))
        print(f"sent UDP payload: {PAYLOAD.decode()!r}")
        time.sleep(0.1)
except KeyboardInterrupt:
    print("\nStopped.")
finally:
    sock.close()