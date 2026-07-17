# mms_simulator.py
import socket
import struct
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import tag, univ
# 简化的MMS PDU构建（实际MMS很复杂，这里使用精简模板）
# 更多实现需引入完整的MMS ASN.1定义，此处展示核心逻辑

def build_initiate_response():
    # 手动构建一个简单的initiate-Response PDU（BER编码）
    # 实际项目建议使用asn1tools或mms库
    pass

def handle_mms(data):
    # 尝试解析MMS PDU类型
    # 根据confirmed-RequestPDU中的service选择处理
    return b'\x03\x00\x00\x16...'  # 示例响应

def mms_server(host='0.0.0.0', port=102):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f"[MMS Simulator] Listening on {host}:{port}")
    while True:
        conn, addr = s.accept()
        data = conn.recv(4096)
        print(f"Received from {addr}: {data.hex()}")
        resp = handle_mms(data)
        conn.send(resp)
        conn.close()

if __name__ == '__main__':
    mms_server()