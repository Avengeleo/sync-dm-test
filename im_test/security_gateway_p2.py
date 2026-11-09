"""V86 单连接、有界探测；正常登录正控之后才检查大小/业务命令限速。"""
import socket
import struct
import time
import uuid
import zlib

import websocket

from im_test import frame, proto_min as p
from im_test.security_login import _open_tcp, _parse_wire_frame, NON_ERR
from im_test.security_p2_config import P2Blocked, P2Error, require, require_live, idle_accounts

CASES = ("heartbeat", "oversize", "fragmented", "compressed", "rate")
MAX_REPLY = 64 * 1024


class Closed(Exception):
    def __init__(self, code=None):
        self.code = code
        super().__init__("测试连接已关闭")


class ProbeConnection:
    def __init__(self, config, *, compressed=False):
        self.config, self.compressed = config, compressed
        self.transport, self.conn, self.seq = config["p2_transport"], None, 0

    def __repr__(self):
        return "ProbeConnection(<连接配置已隐藏>)"

    def __enter__(self):
        cfg = self.config
        try:
            if self.transport == "tcp":
                self.conn = _open_tcp(cfg["tcp_url"], cfg["timeout"])
            else:
                headers = ["Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover"] if self.compressed else []
                self.conn = websocket.create_connection(cfg["ws_url"], timeout=cfg["timeout"], header=headers)
                if self.compressed:
                    extension = (self.conn.getheaders() or {}).get("sec-websocket-extensions", "").lower()
                    if "permessage-deflate" not in extension or "server_no_context_takeover" not in extension:
                        raise P2Blocked("入口未协商 permessage-deflate；压缩路径不能算通过")
            self.conn.settimeout(cfg["timeout"])
            body = p.cm_login(cfg["user_id"], cfg["token"], 2,
                              device_token="security-p2-" + uuid.uuid4().hex,
                              app_version=cfg["app_version"])
            seq = self.send(0x0101, body)
            event = self.wait(0x0102, seq)
            parsed = p.decode(event)
            require(parsed.get(1) == cfg["user_id"] and parsed.get(2) == NON_ERR, "V86 本连接登录正控未明确成功")
            return self
        except (P2Error, P2Blocked):
            self.close()
            raise
        except Exception:
            self.close()
            raise P2Error("V86 连接/登录正控失败；不能当作限流或大小拒绝") from None

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = None

    def exact(self, count):
        source = self.conn.sock if self.transport == "ws" else self.conn
        result = bytearray()
        while len(result) < count:
            try:
                chunk = source.recv(count - len(result))
            except (ConnectionResetError, BrokenPipeError):
                raise Closed() from None
            if not chunk:
                raise Closed()
            result.extend(chunk)
        return bytes(result)

    def packet(self, raw, *, fragmented=False, compressed=False):
        if self.transport == "tcp":
            if fragmented:
                for segment in (raw[:2], raw[2:7], raw[7:]):
                    self.conn.sendall(segment)
            else:
                self.conn.sendall(raw)
            return
        data = raw
        if compressed:
            compressor = zlib.compressobj(wbits=-15)
            data = (compressor.compress(raw) + compressor.flush(zlib.Z_SYNC_FLUSH))[:-4]
        if fragmented:
            middle = len(data) // 2
            self.conn.send_frame(websocket.ABNF(fin=0, rsv1=int(compressed), opcode=2, data=data[:middle]))
            self.conn.send_frame(websocket.ABNF(fin=1, opcode=0, data=data[middle:]))
        else:
            self.conn.send_frame(websocket.ABNF(fin=1, rsv1=int(compressed), opcode=2, data=data))

    def send(self, command, body=b"", **kwargs):
        self.seq += 1
        self.packet(frame.build_frame(command, body, self.seq), **kwargs)
        return self.seq

    def receive(self):
        """有界读取服务端 WS，支持本次协商的压缩响应，不关闭 TLS 验证。"""
        if self.transport == "tcp":
            size = struct.unpack(">I", self.exact(4))[0]
            require(12 <= size <= MAX_REPLY, "V86 TCP 响应长度异常")
            return _parse_wire_frame(struct.pack(">I", size) + self.exact(size))
        data, compressed, started = bytearray(), False, False
        for _ in range(128):
            a, b = self.exact(2)
            fin, opcode = bool(a & 128), a & 15
            require(not b & 128 and not a & 48, "V86 WS 服务端帧无效")
            length = b & 127
            if length == 126:
                length = struct.unpack(">H", self.exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self.exact(8))[0]
            require(length <= MAX_REPLY and len(data) + length <= MAX_REPLY, "V86 WS 响应超过本地读取预算")
            payload = self.exact(length)
            if opcode == 8:
                raise Closed(struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else None)
            if opcode in (9, 10):
                require(fin and length <= 125, "V86 WS 控制帧无效")
                if opcode == 9:
                    self.conn.send_frame(websocket.ABNF(fin=1, opcode=10, data=payload))
                continue
            require(opcode == (0 if started else 2), "V86 WS 数据帧类型异常")
            if not started:
                compressed = bool(a & 64)
                require(not compressed or self.compressed, "未协商压缩却收到压缩帧")
            else:
                require(not a & 64, "WS 连续帧错误设置压缩位")
            started = True
            data.extend(payload)
            if fin:
                raw = bytes(data)
                if compressed:
                    inflater = zlib.decompressobj(-15)
                    raw = inflater.decompress(raw + b"\x00\x00\xff\xff", MAX_REPLY + 1)
                    require(len(raw) <= MAX_REPLY and not inflater.unconsumed_tail, "V86 解压响应超出本地预算")
                return _parse_wire_frame(raw)
        raise P2Error("V86 WS 控制帧或分片过多；已停止")

    def wait(self, command, sequence):
        deadline = time.monotonic() + self.config["timeout"]
        for _ in range(128):
            self.conn.settimeout(max(.001, deadline - time.monotonic()))
            cmd, body, seq, flags, appid = self.receive()
            if cmd == command and seq == sequence:
                require(flags == frame.FLAGS and appid == frame.APPID, "V86 回应协议头不匹配")
                return body
            if time.monotonic() >= deadline:
                break
        raise P2Error("V86 未得到匹配正控响应")


def run_gateway_case(config, case, *, connection_factory=ProbeConnection, preflight=idle_accounts, clock=time.monotonic):
    require_live(config, "86")
    require(case in CASES, "未知 V86 阶段")
    kind = config["p2_transport"]
    if case == "compressed" and kind != "ws":
        raise P2Blocked("压缩只属于 WS，本阶段不适用于 TCP")
    if case in ("oversize", "compressed") or (case == "fragmented" and kind == "ws"):
        if not 12 <= config["p2_frame_limit"] <= 32 * 1024 * 1024:
            raise P2Blocked("缺少实际部署的 maxFrameBytes 有效值；不猜测大小边界")
    if case == "rate" and not 1 <= config["p2_rate"] <= 500:
        raise P2Blocked("限速探测需要实际 cmdLimitRate=1..500，最多单连接1002个心跳包")
    preflight(config, "86")
    with connection_factory(config, compressed=case == "compressed") as conn:
        if case == "heartbeat" or (case == "fragmented" and kind == "tcp"):
            seq = conn.send(1, fragmented=case == "fragmented")
            conn.wait(2, seq)
            return {"evidence": "authenticated_matching_heartbeat_ack"}
        if case == "rate":
            begin = clock()
            sent, closed = 0, False
            # 全部为正常心跳，不调用消息、踢设备、推送同步或登录重试。
            try:
                for _ in range(2 * config["p2_rate"] + 2):
                    conn.send(1)
                    sent += 1
            except (ConnectionResetError, BrokenPipeError, websocket.WebSocketConnectionClosedException):
                closed = True
            elapsed = clock() - begin
            require(sent > config["p2_rate"], "连接在达到限速预算前中断；不能证明限速")
            if elapsed >= 1:
                raise P2Blocked("本次发包未在1秒内形成超额突发；不自动加压或重跑")
            try:
                if not closed:
                    deadline = clock() + config["timeout"]
                    for _ in range(sent + 128):
                        remaining = deadline - clock()
                        if remaining <= 0:
                            break
                        conn.conn.settimeout(remaining)
                        event = conn.receive()
                        require(event[0] == 2, "限速阶段出现非心跳事件；不能把其他踢线当作限速")
            except Closed:
                closed = True
            except (socket.timeout, TimeoutError, websocket.WebSocketTimeoutException):
                pass
            require(closed, "超过已配置业务限速后未观察到主动关闭；超时不算通过")
            return {"evidence": "authenticated_heartbeat_burst_closed", "sent_packets": sent}
        maximum = config["p2_frame_limit"]
        try:
            if kind == "tcp":
                # 仅发4字节越界长度头，不传大包体；旧代码会等待，不能算通过。
                conn.packet(struct.pack(">I", maximum + 1))
            else:
                conn.send(1, b"\x00" * (maximum - 11), fragmented=case == "fragmented", compressed=case == "compressed")
        except (ConnectionResetError, BrokenPipeError, websocket.WebSocketConnectionClosedException):
            # 写入期间关闭也必须再检查读端，不能仅凭写异常通过。
            pass
        start = clock()
        try:
            conn.receive()
        except Closed as exc:
            require(exc.code in (None, 1009), "关闭码不是大小限制；不能当作大小保护通过")
            require(clock() - start <= 2, "关闭过晚，无法排除入口空闲超时")
            return {"evidence": "authenticated_oversize_closed", "close_code": exc.code}
        except (socket.timeout, TimeoutError, websocket.WebSocketTimeoutException):
            raise P2Error("越界包未被及时关闭；超时不算通过") from None
        raise P2Error("越界包仍返回业务数据，大小保护未验证通过")
