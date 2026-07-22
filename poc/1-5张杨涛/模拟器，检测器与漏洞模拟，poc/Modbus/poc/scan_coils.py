"""
Modbus PoC: Scan coils without authentication.
Usage: python poc/scan_coils.py <target_ip> [port]
"""
import socket, struct, sys
MBAP = struct.Struct(">HHHB")

def scan(host, port=502, start=0, count=100):
    pdu = struct.pack(">BHH", 1, start, count)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5); sock.connect((host, port))
    sock.sendall(MBAP.pack(1, 0, len(pdu) + 1, 1) + pdu)
    resp = sock.recv(1024)
    if resp[7] & 0x80:
        print(f"[!] Exception: 0x{resp[8]:02X}")
    else:
        coils = [(resp[9 + i // 8] >> (i % 8)) & 1 for i in range(count)]
        print(f"[+] Coils {start}-{start+count-1}: {coils[:50]}...")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: python scan_coils.py <target> [port]"); sys.exit(1)
    scan(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 502)
