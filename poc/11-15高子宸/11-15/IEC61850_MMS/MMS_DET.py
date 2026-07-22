"""
MMS 协议信息检测逻辑
解析 TPKT + MMS PDU，提取服务类型、变量名等关键字段
"""
import struct

def detect_mms(data):
    """
    解析并打印 MMS 报文的关键字段
    :param data: 完整的 TPKT + MMS 数据字节串
    """
    if len(data) < 4:
        print("[检测] 数据太短，不是 MMS")
        return

    # 1. TPKT 头部解析
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

    # 2. MMS PDU 类型
    pdu_tag = mms_pdu[0]
    pdu_length = mms_pdu[1]  # 简单长度，若长度 >127 这里简化，仅演示
    if pdu_length > 127:
        # 长编码长度，这里不深入解析，直接跳过
        print("[检测] MMS PDU 使用长编码长度，简化解析可能不完整")
        return

    pdu_names = {
        0xA0: "confirmed-Request",
        0xA1: "confirmed-Response",
        0xA2: "confirmed-Error",
        0xA3: "unconfirmed-PDU",
        0xA8: "initiate-Request",
        0xA9: "initiate-Response",
        0xAA: "initiate-Error",
        0xAB: "conclude-Request",
        0xAC: "conclude-Response",
        0xAD: "conclude-Error",
    }
    pdu_type = pdu_names.get(pdu_tag, f"未知 (0x{pdu_tag:02X})")
    print(f"[检测] MMS PDU 类型: {pdu_type}")

    # 3. 如果是 confirmed-Request (0xA0) 或 initiate-Request (0xA8) 尝试进一步解析
    if pdu_tag in (0xA0, 0xA8):
        # 跳过 PDU 头 (2字节) + invokeID (1字节长度+内容)
        if len(mms_pdu) < 4:
            return
        invoke_id_len = mms_pdu[2]
        offset = 3 + invoke_id_len
        if offset >= len(mms_pdu):
            return

        # 服务类型位于 invokedID 之后
        service_tag = mms_pdu[offset]
        # 常见服务类型 (confirmed-Request 内部)
        service_names = {
            0x01: "status",
            0x02: "getNameList",
            0x04: "read",
            0x05: "write",
            0x06: "informationReport",
            0x0A: "fileOpen",
            0x0B: "fileRead",
            0x0C: "fileClose",
            0x0F: "identify",
        }
        service = service_names.get(service_tag, f"未知服务 (0x{service_tag:02X})")
        print(f"[检测] MMS 服务: {service}")

        # 尝试提取变量名（仅演示读请求中的变量列表）
        if service_tag == 0x04:  # read
            # 跳过服务标签和长度，进入变量列表 (SEQUENCE OF)
            if offset + 2 > len(mms_pdu):
                return
            list_tag = mms_pdu[offset+1]
            list_len = mms_pdu[offset+2]
            var_offset = offset + 3
            if var_offset + list_len > len(mms_pdu):
                return
            # 变量通常是 CHOICE of ObjectName, 这里简单演示长度
            var_name_len = list_len
            print(f"[检测] 读请求变量列表总长度: {list_len} 字节")
            # 如果有明显长变量名（>500字节），给出告警
            if list_len > 500:
                print("[检测] ⚠️ 警告：变量列表长度异常大，可能是栈溢出攻击！")