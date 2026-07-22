"""
Modbus PoC: 全功能码模糊测试扫描
"""
import socket, struct, sys
MBAP = struct.Struct(">HHHB")
FUNCS = [1,2,3,4,5,6,7,8,11,12,15,16,17,20,21,22,23,24,43]
FNAMES = {1:"Read Coils",2:"Read Discrete",3:"Read Holding Reg",4:"Read Input Reg",
          5:"Write Coil",6:"Write Reg",7:"Read Exc Status",8:"Diagnostics",
          11:"Event Counter",12:"Event Log",15:"Write Coils",16:"Write Regs",
          17:"Report ID",20:"Read File",21:"Write File",22:"Mask Write",
          23:"R/W Regs",24:"FIFO",43:"Device ID"}

def scan(host, port=502):
    results = []
    for func in FUNCS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3); sock.connect((host, port))
            if func in {1,2,3,4,15,16}:
                pdu = struct.pack(">BHH", func, 0, 1)
            elif func == 8:
                pdu = struct.pack(">BHH", func, 0, 0)
            elif func == 20:
                pdu = struct.pack(">BBBHB", func, 7, 6, 1, 0) + struct.pack(">HH", 0, 1)
            elif func == 22:
                pdu = struct.pack(">BHHH", func, 0, 0xFFFF, 0)
            elif func == 23:
                pdu = struct.pack(">BHHHHB", func, 0, 1, 0, 1, 2) + struct.pack(">H", 0)
            elif func == 24:
                pdu = struct.pack(">BH", func, 0)
            elif func == 43:
                pdu = struct.pack(">BBBB", func, 0x0E, 0x01, 0x00)
            else:
                pdu = bytes([func])
            sock.sendall(MBAP.pack(func, 0, len(pdu) + 1, 1) + pdu)
            resp = sock.recv(1024)
            if resp and not (resp[7] & 0x80):
                status = "[+] SUPPORTED"
                extra = f"resp_len={len(resp)}"
            elif resp:
                status = f"[~] EXCEPTION (0x{resp[8]:02X})"
                extra = ""
            else:
                status = "[?] NO RESPONSE"
                extra = ""
            results.append((func, status, extra))
            sock.close()
        except Exception as e:
            results.append((func, f"[!] ERROR", str(e)))
    for func, status, extra in results:
        print(f"  0x{func:02X} ({FNAMES.get(func,'?')}): {status} {extra}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python poc/function_scan.py <target_ip> [port]"); sys.exit(1)
    scan(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 502)
