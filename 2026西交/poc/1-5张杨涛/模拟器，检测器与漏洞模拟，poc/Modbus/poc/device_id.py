"""
Modbus PoC: Read Device Identification (功能码 43, MEI 类型 0x0E)
"""
import socket, struct, sys
MBAP = struct.Struct(">HHHB")

def get_device_id(host, port=502, obj_id=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5); sock.connect((host, port))
    pdu = struct.pack(">BBBB", 43, 0x0E, 0x01, obj_id)
    sock.sendall(MBAP.pack(1, 0, len(pdu) + 1, 1) + pdu)
    resp = sock.recv(1024)
    if resp and resp[7] == 43 and not (resp[7] & 0x80):
        mei = resp[8:]
        print(f"[+] Device Identification response ({len(mei)} bytes)")
        print(f"    Raw: {mei.hex()}")
        off = 4
        while off < len(mei):
            oid = mei[off]; con = mei[off+1]; length = mei[off+2]
            val = mei[off+3:off+3+length]
            labels = {0:"VendorName",1:"ProductCode",2:"MajorMinorRev",3:"VendorUrl",4:"ProductName",5:"ModelName",6:"UserAppName"}
            print(f"    [{oid}] {labels.get(oid,'?'):15s} = {val.rstrip(b'\\x00').decode(errors='replace')}")
            off += 3 + length
    else:
        print(f"[-] No response or exception: {resp.hex()}" if resp else "[-] No response")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python poc/device_id.py <target_ip> [port]")
        sys.exit(1)
    get_device_id(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 502)
