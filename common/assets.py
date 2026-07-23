"""测试资产生成器:纯 Python 造真实 PNG 与 ZIP,不依赖 Pillow。

服务端 ZIP 导入用 Go 的 image.DecodeConfig 读 PNG 的 IHDR 取宽高,
所以这里必须产出结构合法、能被解码的 PNG(而非随便的字节)。
"""

import io
import struct
import zlib
import zipfile


def make_png(width, height, rgb=(255, 0, 0)):
    """生成 width×height 的纯色 24 位 PNG(color type 2 = truecolor)。

    产物可被 Go image/png DecodeConfig 正确读出宽高。
    """

    def _chunk(tag, data):
        body = tag + data
        return (
            struct.pack(">I", len(data))
            + body
            + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    r, g, b = rgb
    row = bytes([r, g, b]) * width
    raw = bytearray()
    for _ in range(height):
        raw.append(0)  # 每行前置 filter type = 0
        raw.extend(row)
    idat = zlib.compress(bytes(raw), 9)
    return sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def make_zip(entries):
    """把 {文件名: 字节} 打包成 zip,返回 bytes。

    entries: dict[str, bytes]
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def zip_of_pngs(count, width=240, height=240, prefix="sticker"):
    """生成含 count 张合法 PNG 的 zip。"""
    entries = {}
    for i in range(count):
        entries[f"{prefix}_{i + 1:02d}.png"] = make_png(width, height)
    return make_zip(entries)
