"""
CIP PoC: 枚举设备对象和属性
"""
import socket, struct, sys

def enum(host, port=44819):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5); sock.connect((host, port))

    tests = [
        (0x01, "GetAttributeAll", bytes([0x01, 0x02, 0x04, 0x24])),
        (0x0E, "GetAttributeSingle(Identity)", bytes([0x0E, 0x03, 0x04, 0x24, 0x01, 0x01]) + struct.pack("<H", 1)),
        (0x0E, "GetAttributeSingle(vendor)", bytes([0x0E, 0x03, 0x04, 0x24, 0x01, 0x01]) + struct.pack("<H", 1)),
        (0x0E, "GetAttributeSingle(serial)", bytes([0x0E, 0x03, 0x04, 0x24, 0x01, 0x01]) + struct.pack("<H", 6)),
    ]

    for svc, name, req in tests:
        try:
            sock.sendall(req)
            resp = sock.recv(8192)
            if resp and (resp[0] == svc | 0x80 or resp[0] == svc):
                status = struct.unpack("<H", resp[2:4])[0] if len(resp) > 4 else 0
                if status == 0 or len(resp) > 4:
                    data = resp[2+resp[1]*2:]
                    print(f"[+] {name} OK ({len(data)}B): {data[:40].hex()}")
                else:
                    print(f"[-] {name} error: 0x{status:04X}")
            else:
                print(f"[-] {name}: {resp.hex()[:60] if resp else 'no response'}")
        except Exception as e:
            print(f"[!] {name}: {e}")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python poc/cip_enum.py <target_ip> [port]"); sys.exit(1)
    enum(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 44819)
