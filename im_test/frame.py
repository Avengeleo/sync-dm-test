"""IM 长连接帧编解码(TCP 与 WebSocket 二进制帧内字节完全一致)。

帧布局(全大端,读 im-gateway/server/im_protocol.go + im_message.go 核实):
  [0:4]   uint32 总长 = 12 + bodyLen(partA 长度前缀)
  [4]     uint8  Flags   客户端固定 0x12
  [5]     uint8  AppID   固定 0x11
  [6:8]   uint16 Command cmdId
  [8:12]  uint32 BodyLen
  [12:16] uint32 MsgSeq
  [16:]   protobuf body
WS:整串(含 4 字节前缀)作为一个 Binary 帧发送;服务端 len>4 时剥掉前 4 字节再解析。
"""

import struct

FLAGS = 0x12
APPID = 0x11
_HEADER = ">BBHII"  # Flags, AppID, Command(u16), BodyLen(u32), MsgSeq(u32) = 12 字节


def build_frame(cmd, body, seq=0):
    header = struct.pack(_HEADER, FLAGS, APPID, cmd, len(body), seq)
    payload = header + body
    return struct.pack(">I", len(payload)) + payload  # 前置 4 字节总长


def parse_frame(data):
    """返回 (cmd, body)。自动识别并剥掉 4 字节长度前缀。"""
    if len(data) >= 4:
        prefix = struct.unpack(">I", data[:4])[0]
        if prefix == len(data) - 4:  # 前缀=后续长度 → 剥掉
            data = data[4:]
    flags, appid, cmd, blen, seq = struct.unpack(_HEADER, data[:12])
    return cmd, data[12:12 + blen]
