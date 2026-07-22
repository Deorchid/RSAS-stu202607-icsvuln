"""
EtherNet/IP PoC: ListIdentity
Usage: python poc/list_identity.py <target_ip> [port]
"""
import socket, struct, sys, time

def scan(host, port=44818):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5); sock.connect((host, port))
    encap = struct.pack("<HHIQII", 0x0063, 0, 0, time.time_ns() & 0xFFFFFFFFFFFFFFFF, 0, 0)
    sock.sendall(encap)
    resp = sock.recv(8192)
    if len(resp) >= 24:
        cmd = struct.unpack("<H", resp[:2])[0]
        print(f"[+] Response cmd=0x{cmd:04X} ({len(resp)}B)")
        if len(resp) > 24:
            data = resp[24:]
            print(f"    Data: {data[:80].hex()}")
            for chunk in data.split(b'\x00'):
                if chunk.strip() and len(chunk) > 2:
                    try: print(f"    -> {chunk.decode(errors='replace')}")
                    except: pass
    else:
        print("[-] No response")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: python list_identity.py <target> [port]"); sys.exit(1)
    scan(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 44818)
