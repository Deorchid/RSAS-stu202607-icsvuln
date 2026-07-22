"""
OPC UA PoC: Enumerate endpoints.
Usage: python poc/enumerate_endpoints.py <target_ip> [port]
"""
import socket, struct, sys

def probe(host, port=4840):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5); sock.connect((host, port))
    url = f"opc.tcp://{host}:{port}/".encode()
    body = struct.pack(">IIII", 65536, 65536, 65536, 0) + url
    hello = struct.pack(">IBBBB", 8 + len(body), 0, 72, 69, 76) + body
    sock.sendall(hello)
    resp = sock.recv(8192)
    if resp and len(resp) > 8:
        msg_type = resp[5:8]
        if msg_type == b"ACK":
            recv_buf = struct.unpack(">I", resp[8:12])[0]
            send_buf = struct.unpack(">I", resp[12:16])[0]
            print(f"[+] OPC UA at {host}:{port} ACK")
            print(f"    recv_buf={recv_buf} send_buf={send_buf}")
        elif msg_type == b"ERR":
            print(f"[-] Error: {resp[8:].hex()}")
        else:
            print(f"[?] Unknown: {msg_type}")
    else:
        print("[-] No response")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: python enumerate_endpoints.py <target> [port]"); sys.exit(1)
    probe(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 4840)
