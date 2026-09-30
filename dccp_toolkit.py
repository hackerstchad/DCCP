#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 DCCP - Datagram Congestion Control Protocol
 Advanced Python Implementation / Simulator / Analyzer / Lab
 Créé par Hackers Tchad — Interface Rouge & Green
 Version : 1.0.0
================================================================================

Ce script fournit une implémentation avancée, éducative et expérimentale du
protocole DCCP (RFC 4340, RFC 4341, RFC 4342, RFC 5622), avec :
- Stack DCCP complète (states, handshakes, feature negotiation, CCIDs)
- Parseur de paquets DCCP binaires
- Client/Serveur DCCP via UDP socket underlay
- Outils d'analyse Wireshark-like
- Générateur de trames DCCP
- Laboratoire de congestion control (CCID-2, CCID-3)
- CLI colorée (rouge/vert) style hacker
- Mode MITM / proxy DCCP pour inspection
- Statistiques temps réel
- Export pcap-like JSON

USAGE:
    python dccp_protocol.py --mode server --host 0.0.0.0 --port 5001
    python dccp_protocol.py --mode client --host 127.0.0.1 --port 5001
    python dccp_protocol.py --mode analyze --pcap capture.json
    python dccp_protocol.py --mode generate --count 100

ATTENTION : Ce logiciel est fourni à des fins éducatives et de recherche.
Respectez les lois locales et n'utilisez ces outils que sur vos propres réseaux.
================================================================================
"""

import argparse
import array
import base64
import binascii
import collections
import colorsys
import copy
import datetime
import enum
import errno
import fcntl
import hashlib
import heapq
import inspect
import io
import ipaddress
import itertools
import json
import logging
import math
import os
import pickle
import platform
import queue
import random
import re
import select
import socket
import statistics
import string
import struct
import sys
import textwrap
import threading
import time
import traceback
import types
import uuid
import zlib
from dataclasses import dataclass, field, asdict
from typing import (
    Any, Callable, Dict, List, Optional, Tuple, Union, Set, Iterable,
    NamedTuple, BinaryIO
)

# ---------------------------------------------------------------------------
# Couleurs & UI
# ---------------------------------------------------------------------------

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"

    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    @staticmethod
    def hex_color(hexcode: str) -> str:
        h = hexcode.lstrip("#")
        r, g, b = tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
        return f"\033[38;2;{r};{g};{b}m"

    @staticmethod
    def rgb(r: int, g: int, b: int) -> str:
        return f"\033[38;2;{r};{g};{b}m"

    @staticmethod
    def bg_rgb(r: int, g: int, b: int) -> str:
        return f"\033[48;2;{r};{g};{b}m"

    @classmethod
    def disable(cls):
        for k in dir(cls):
            if not k.startswith("_") and isinstance(getattr(cls, k), str):
                setattr(cls, k, "")


class UI:
    WIDTH = 78

    @classmethod
    def banner(cls, title: str = "DCCP PROTOCOL LAB") -> str:
        date_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"{Colors.BG_BLACK}{Colors.BRIGHT_RED}╔{'═' * cls.WIDTH}╗{Colors.RESET}",
            f"{Colors.BG_BLACK}{Colors.BRIGHT_RED}║{Colors.BRIGHT_GREEN} {title.center(cls.WIDTH - 1)}{Colors.BRIGHT_RED}║{Colors.RESET}",
            f"{Colors.BG_BLACK}{Colors.BRIGHT_RED}╠{'═' * cls.WIDTH}╣{Colors.RESET}",
            f"{Colors.BG_BLACK}{Colors.BRIGHT_RED}║{Colors.RED} Hackers Tchad {Colors.GREEN}• Advanced DCCP Stack & Analyzer".ljust(cls.WIDTH + 20) + f"{Colors.BRIGHT_RED}║{Colors.RESET}",
            f"{Colors.BG_BLACK}{Colors.BRIGHT_RED}║{Colors.GREEN} {date_now.ljust(cls.WIDTH - 2)}{Colors.BRIGHT_RED}║{Colors.RESET}",
            f"{Colors.BG_BLACK}{Colors.BRIGHT_RED}╚{'═' * cls.WIDTH}╝{Colors.RESET}",
        ]
        return "\n".join(lines)

    @classmethod
    def box(cls, text: str, color: str = Colors.BRIGHT_GREEN) -> str:
        wrapped = textwrap.fill(text, width=cls.WIDTH - 4)
        result = [f"{Colors.RED}┌{'─' * (cls.WIDTH - 2)}┐{Colors.RESET}"]
        for line in wrapped.split("\n"):
            result.append(f"{Colors.RED}│{color} {line.ljust(cls.WIDTH - 4)} {Colors.RED}│{Colors.RESET}")
        result.append(f"{Colors.RED}└{'─' * (cls.WIDTH - 2)}┘{Colors.RESET}")
        return "\n".join(result)

    @classmethod
    def info(cls, msg: str):
        print(f"{Colors.BRIGHT_GREEN}[+] {Colors.RESET}{msg}")

    @classmethod
    def warn(cls, msg: str):
        print(f"{Colors.BRIGHT_YELLOW}[!] {Colors.RESET}{msg}")

    @classmethod
    def error(cls, msg: str):
        print(f"{Colors.BRIGHT_RED}[-] {Colors.RESET}{msg}")

    @classmethod
    def debug(cls, msg: str):
        print(f"{Colors.CYAN}[*] {Colors.RESET}{msg}")

    @classmethod
    def table(cls, headers: List[str], rows: List[List[Any]]) -> str:
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        sep = "+".join(["-" * (w + 2) for w in widths])
        sep = f"{Colors.RED}+{sep}+{Colors.RESET}"
        header = "|".join([f" {Colors.BRIGHT_GREEN}{headers[i].ljust(widths[i])}{Colors.RESET} " for i in range(len(headers))])
        header = f"{Colors.RED}|{header}|{Colors.RESET}"
        out = [sep, header, sep]
        for row in rows:
            line = "|".join([f" {Colors.WHITE}{str(row[i]).ljust(widths[i])}{Colors.RESET} " for i in range(len(row))])
            out.append(f"{Colors.RED}|{line}|{Colors.RESET}")
        out.append(sep)
        return "\n".join(out)


# ---------------------------------------------------------------------------
# Constantes DCCP (RFC 4340)
# ---------------------------------------------------------------------------

DCCP_PORT_DEFAULT = 5001
DCCP_HEADER_MIN_LEN = 12
DCCP_MAX_SEQNO = 2 ** 48 - 1
DCCP_MAX_ACKNO = 2 ** 48 - 1


class DCCPType(enum.IntEnum):
    REQUEST = 0
    RESPONSE = 1
    DATA = 2
    ACK = 3
    DATAACK = 4
    CLOSEREQ = 5
    CLOSE = 6
    RESET = 7
    SYNC = 8
    SYNCACK = 9


DCCP_TYPE_NAMES = {t.value: t.name for t in DCCPType}


class DCCPAckVectorState(enum.IntEnum):
    RECEIVED = 0
    RECEIVED_ECNECHOED = 1
    NOT_RECEIVED = 2
    NOT_REPORTABLE = 3


class DCCPResetCode(enum.IntEnum):
    UNSPECIFIED = 0
    CLOSED = 1
    ABORTED = 2
    NO_CONNECTION = 3
    PACKET_ERROR = 4
    OPTION_ERROR = 5
    MANDATORY_ERROR = 6
    CONNECTION_REFUSED = 7
    BAD_SERVICE_CODE = 8
    TOO_BUSY = 9
    BAD_INIT_COOKIE = 10
    AGGRESSION_PENALTY = 11


RESET_CODE_NAMES = {r.value: r.name for r in DCCPResetCode}


class DCCPFeature(enum.IntEnum):
    CCID = 1
    SHORT_SEQNOS = 2
    SEQUENCE_WINDOW = 3
    ECN_INCAPABLE = 4
    ACK_RATIO = 5
    ENABLE_ACK_VECTOR = 6
    TX_DEQUEUE_RATE = 7
    SEND_LEV_RATE = 8


FEATURE_NAMES = {f.value: f.name for f in DCCPFeature}


class DCCPOption(enum.IntEnum):
    PAD = 0
    MANDATORY = 1
    SLOW_RECEIVER = 2
    CHANGE_L = 32
    CONFIRM_L = 33
    CHANGE_R = 34
    CONFIRM_R = 35
    INIT_COOKIE = 36
    NDP_COUNT = 37
    ACK_VECTOR_0 = 38
    ACK_VECTOR_1 = 39
    TIMESTAMP = 41
    TIMESTAMP_ECHO = 42
    ELAPSED_TIME = 43
    DATA_DROPS = 44
    TIMESTAMP_ECHO_SIZE = 45
    ELAPSED_TIME_SIZE = 46


OPTION_NAMES = {o.value: o.name for o in DCCPOption}
OPTION_NAMES.update({
    40: "DATA_CHECKSUM",
    46: "ELAPSED_TIME_SIZE",
    47: "SEND_LEV_RATE",
    48: "RECV_LEV_RATE",
    49: "DROP_CODE",
    50: "FEATURE_NN",
    51: "MPS_PENDING",
    52: "MPS_DECOMMIT",
    53: "MPS_CLOSE",
    54: "MPS_JOIN",
    55: "MPS_LEAVE",
})


class CCID(enum.IntEnum):
    CCID_2 = 2
    CCID_3 = 3


class DCCPState(enum.IntEnum):
    CLOSED = 1
    REQUEST = 2
    RESPOND = 3
    PARTOPEN = 4
    OPEN = 5
    CLOSING = 6
    TIME_WAIT = 7


STATE_NAMES = {s.value: s.name for s in DCCPState}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_ms() -> int:
    return int(time.time() * 1000)


def seqno_add(a: int, b: int, max_val: int = DCCP_MAX_SEQNO + 1) -> int:
    return (a + b) % max_val


def seqno_diff(a: int, b: int, max_val: int = DCCP_MAX_SEQNO + 1) -> int:
    d = (a - b) % max_val
    if d > max_val // 2:
        d -= max_val
    return d


def seqno_gt(a: int, b: int) -> bool:
    return 0 < seqno_diff(a, b) <= (DCCP_MAX_SEQNO // 2)


def seqno_lt(a: int, b: int) -> bool:
    return seqno_gt(b, a)


def crc16(data: bytes, poly: int = 0x8005, init: int = 0x0000) -> int:
    """CRC-16-IBM implémenté en pur Python pour l'intégrité des paquets."""
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
        crc &= 0xFFFF
    return crc


def checksum_ipv4_pseudo(src: str, dst: str, protocol: int, length: int) -> bytes:
    """Pseudo-header IPv4 pour checksum DCCP (RFC 4340 Section 9)."""
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)
    return src_bytes + dst_bytes + struct.pack("!BBH", 0, protocol, length)


def green_gradient(text: str, start: Tuple[int, int, int] = (0, 50, 0),
                   end: Tuple[int, int, int] = (0, 255, 0)) -> str:
    out = []
    length = max(1, len(text))
    for i, ch in enumerate(text):
        ratio = i / length
        r = int(start[0] + (end[0] - start[0]) * ratio)
        g = int(start[1] + (end[1] - start[1]) * ratio)
        b = int(start[2] + (end[2] - start[2]) * ratio)
        out.append(f"{Colors.rgb(r, g, b)}{ch}{Colors.RESET}")
    return "".join(out)


def red_gradient(text: str, start: Tuple[int, int, int] = (50, 0, 0),
                 end: Tuple[int, int, int] = (255, 0, 0)) -> str:
    out = []
    length = max(1, len(text))
    for i, ch in enumerate(text):
        ratio = i / length
        r = int(start[0] + (end[0] - start[0]) * ratio)
        g = int(start[1] + (end[1] - start[1]) * ratio)
        b = int(start[2] + (end[2] - start[2]) * ratio)
        out.append(f"{Colors.rgb(r, g, b)}{ch}{Colors.RESET}")
    return "".join(out)


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{Colors.RED}{i:08x}{Colors.RESET}  {Colors.GREEN}{hex_part:<{width*3}}{Colors.RESET} {Colors.YELLOW}|{ascii_part}|{Colors.RESET}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Structures DCCP
# ---------------------------------------------------------------------------

@dataclass
class DCCPPacket:
    source_port: int
    destination_port: int
    data_offset: int
    ccval: int
    cscov: int
    type: int
    extended_seqno: bool
    sequence_number: int
    ack_number_present: bool
    ack_number: int = 0
    data: bytes = b""
    options: List[Tuple[int, bytes]] = field(default_factory=list)
    service_code: int = 0
    timestamp: float = field(default_factory=time.time)

    def type_name(self) -> str:
        return DCCP_TYPE_NAMES.get(self.type, f"UNKNOWN({self.type})")

    def summary(self) -> str:
        ack = f" ack={self.ack_number}" if self.ack_number_present else ""
        opts = f" options={len(self.options)}" if self.options else ""
        return (f"DCCP {self.source_port}->{self.destination_port} "
                f"[{self.type_name()}] seq={self.sequence_number}{ack}{opts} "
                f"len={len(self.data)}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "data_offset": self.data_offset,
            "ccval": self.ccval,
            "cscov": self.cscov,
            "type": self.type,
            "type_name": self.type_name(),
            "extended_seqno": self.extended_seqno,
            "sequence_number": self.sequence_number,
            "ack_number_present": self.ack_number_present,
            "ack_number": self.ack_number,
            "data_length": len(self.data),
            "data_hex": binascii.hexlify(self.data).decode(),
            "options": [{"type": opt, "type_name": OPTION_NAMES.get(opt, f"UNKNOWN({opt})"),
                         "value": binascii.hexlify(val).decode()} for opt, val in self.options],
            "service_code": self.service_code,
            "timestamp": self.timestamp,
        }


@dataclass
class DCCPConnection:
    local_addr: Tuple[str, int]
    remote_addr: Tuple[str, int]
    state: DCCPState = DCCPState.CLOSED
    sequence_number: int = 0
    ack_number: int = 0
    ccid_local: int = CCID.CCID_2
    ccid_remote: int = CCID.CCID_2
    service_code: int = 0
    sequence_window: int = 100
    ack_ratio: int = 1
    cookies: List[bytes] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    stats: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.stats:
            self.stats = {
                "packets_sent": 0,
                "packets_received": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "retransmissions": 0,
                "drops": 0,
            }


# ---------------------------------------------------------------------------
# Parseur & Builder de paquets DCCP
# ---------------------------------------------------------------------------

class DCCPCodec:
    """Encode et décode les paquets DCCP selon RFC 4340."""

    @staticmethod
    def encode(packet: DCCPPacket) -> bytes:
        """Sérialise un DCCPPacket en octets bruts."""
        ext = 1 if packet.extended_seqno else 0
        type_n_ccval = (packet.type << 4) | (packet.ccval & 0x0F)
        first_word = (packet.source_port << 16) | packet.destination_port
        third_word = ((packet.data_offset // 4) << 28) | (packet.cscov << 8) | type_n_ccval
        if packet.extended_seqno:
            seq_bytes = struct.pack("!Q", packet.sequence_number)[2:]
        else:
            seq_bytes = struct.pack("!I", packet.sequence_number & 0xFFFFFFFF)
        if packet.ack_number_present:
            if packet.extended_seqno:
                ack_bytes = struct.pack("!Q", packet.ack_number)[2:]
            else:
                ack_bytes = struct.pack("!I", packet.ack_number & 0xFFFFFFFF)
        else:
            ack_bytes = b""

        options_bytes = DCCPCodec.encode_options(packet.options)
        if packet.type in (DCCPType.REQUEST, DCCPType.RESPONSE):
            service_bytes = struct.pack("!I", packet.service_code)
        else:
            service_bytes = b""

        header_without_checksum = (
            struct.pack("!I", first_word) +
            struct.pack("!I", third_word) +
            seq_bytes + ack_bytes + service_bytes + options_bytes
        )
        actual_offset = len(header_without_checksum) // 4
        third_word = (actual_offset << 28) | (packet.cscov << 8) | type_n_ccval
        header_without_checksum = (
            struct.pack("!I", first_word) +
            struct.pack("!I", third_word) +
            seq_bytes + ack_bytes + service_bytes + options_bytes
        )

        # Checksum sur header + data + pseudo header (dummy 0.0.0.0)
        checksum = DCCPCodec.compute_checksum(header_without_checksum + packet.data, "0.0.0.0", "0.0.0.0")
        final_header = header_without_checksum[:6] + struct.pack("!H", checksum) + header_without_checksum[8:]
        return final_header + packet.data

    @staticmethod
    def encode_options(options: List[Tuple[int, bytes]]) -> bytes:
        buf = b""
        for opt_type, opt_val in options:
            length = len(opt_val) + 2
            if length > 255:
                continue
            buf += struct.pack("!BB", opt_type, length) + opt_val
        return buf

    @staticmethod
    def decode(data: bytes) -> Optional[DCCPPacket]:
        if len(data) < DCCP_HEADER_MIN_LEN:
            return None
        first_word = struct.unpack("!I", data[0:4])[0]
        source_port = (first_word >> 16) & 0xFFFF
        dest_port = first_word & 0xFFFF
        second_word = struct.unpack("!I", data[4:8])[0]
        data_offset = (second_word >> 28) * 4
        ccval = (second_word >> 24) & 0x0F
        cscov = (second_word >> 8) & 0xFF
        type_n_ccval = second_word & 0xFF
        pkt_type = (type_n_ccval >> 4) & 0x0F
        ccval = type_n_ccval & 0x0F
        ext = (second_word >> 16) & 0x01
        extended = bool(ext)

        offset = 8
        if extended:
            if len(data) < offset + 6:
                return None
            seq_high = struct.unpack("!H", data[offset:offset+2])[0]
            seq_low = struct.unpack("!I", data[offset+2:offset+6])[0]
            sequence_number = (seq_high << 32) | seq_low
            offset += 6
        else:
            if len(data) < offset + 4:
                return None
            sequence_number = struct.unpack("!I", data[offset:offset+4])[0]
            offset += 4

        ack_present = False
        ack_number = 0
        if pkt_type in (DCCPType.ACK, DCCPType.DATAACK, DCCPType.SYNCACK, DCCPType.RESPONSE,
                        DCCPType.CLOSEREQ, DCCPType.CLOSE, DCCPType.RESET):
            ack_present = True
            if extended:
                if len(data) < offset + 6:
                    return None
                ack_high = struct.unpack("!H", data[offset:offset+2])[0]
                ack_low = struct.unpack("!I", data[offset+2:offset+6])[0]
                ack_number = (ack_high << 32) | ack_low
                offset += 6
            else:
                if len(data) < offset + 4:
                    return None
                ack_number = struct.unpack("!I", data[offset:offset+4])[0]
                offset += 4

        service_code = 0
        if pkt_type in (DCCPType.REQUEST, DCCPType.RESPONSE):
            if len(data) < offset + 4:
                return None
            service_code = struct.unpack("!I", data[offset:offset+4])[0]
            offset += 4

        options = []
        if data_offset > offset:
            options = DCCPCodec.decode_options(data[offset:data_offset])

        payload = data[data_offset:]
        return DCCPPacket(
            source_port=source_port,
            destination_port=dest_port,
            data_offset=data_offset,
            ccval=ccval,
            cscov=cscov,
            type=pkt_type,
            extended_seqno=extended,
            sequence_number=sequence_number,
            ack_number_present=ack_present,
            ack_number=ack_number,
            data=payload,
            options=options,
            service_code=service_code,
        )

    @staticmethod
    def decode_options(data: bytes) -> List[Tuple[int, bytes]]:
        options = []
        i = 0
        while i < len(data):
            opt_type = data[i]
            if opt_type in (0, 1):
                options.append((opt_type, b""))
                i += 1
                continue
            if i + 1 >= len(data):
                break
            length = data[i + 1]
            if length < 2 or i + length > len(data):
                break
            options.append((opt_type, data[i+2:i+length]))
            i += length
        return options

    @staticmethod
    def compute_checksum(data: bytes, src: str, dst: str) -> int:
        pseudo = checksum_ipv4_pseudo(src, dst, socket.IPPROTO_DCCP, len(data))
        full = pseudo + data
        if len(full) % 2:
            full += b"\x00"
        s = 0
        for i in range(0, len(full), 2):
            w = (full[i] << 8) + full[i + 1]
            s += w
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF


# ---------------------------------------------------------------------------
# Congestion Control (CCID-2, CCID-3)
# ---------------------------------------------------------------------------

class CongestionController(abc := __import__("abc").ABC):
    @abc.abstractmethod
    def on_ack(self, ackno: int, now: float):
        pass

    @abc.abstractmethod
    def on_loss(self, seqno: int, now: float):
        pass

    @abc.abstractmethod
    def cwnd(self) -> int:
        pass


class CCID2Controller(CongestionController):
    """CCID-2 : TCP-like congestion control (RFC 4341)."""

    def __init__(self, mss: int = 1400):
        self.mss = mss
        self._cwnd = mss
        self.ssthresh = 64 * mss
        self.dupacks = 0
        self.last_ack = -1
        self.sent_packets: Dict[int, float] = {}

    def on_ack(self, ackno: int, now: float):
        if ackno == self.last_ack:
            self.dupacks += 1
            if self.dupacks == 3:
                self.ssthresh = max(self._cwnd // 2, self.mss)
                self._cwnd = self.ssthresh + 3 * self.mss
        else:
            self.dupacks = 0
            self.last_ack = ackno
            if self._cwnd < self.ssthresh:
                self._cwnd += self.mss
            else:
                self._cwnd += self.mss * self.mss // self._cwnd
        self.sent_packets.pop(ackno, None)

    def on_loss(self, seqno: int, now: float):
        self.ssthresh = max(self._cwnd // 2, self.mss)
        self._cwnd = self.mss
        self.dupacks = 0

    def cwnd(self) -> int:
        return max(int(self._cwnd), self.mss)

    def send_allowed(self, in_flight: int) -> bool:
        return in_flight < self.cwnd()


class CCID3Controller(CongestionController):
    """CCID-3 : TCP-Friendly Rate Control (TFRC) (RFC 4342)."""

    def __init__(self, mss: int = 1400):
        self.mss = mss
        self.rtt = 0.1
        self.loss_event_rate = 0.0
        self._cwnd = 4 * mss
        self.last_rate_update = time.time()

    def on_ack(self, ackno: int, now: float):
        # Simplified TFRC rate equation
        if self.loss_event_rate == 0:
            self._cwnd += self.mss
        else:
            rate = self.mss / (self.rtt * math.sqrt(self.loss_event_rate) * 1.22)
            self._cwnd = max(int(rate * self.rtt), self.mss)
        self.last_rate_update = now

    def on_loss(self, seqno: int, now: float):
        self.loss_event_rate = min(1.0, self.loss_event_rate + 0.05)
        self._cwnd = max(self._cwnd // 2, self.mss)

    def cwnd(self) -> int:
        return int(self._cwnd)


# ---------------------------------------------------------------------------
# Machine à états DCCP
# ---------------------------------------------------------------------------

class DCCPStateMachine:
    """Implémente la machine à états DCCP RFC 4340 Section 8."""

    VALID_TRANSITIONS = {
        DCCPState.CLOSED: {DCCPState.REQUEST},
        DCCPState.REQUEST: {DCCPState.CLOSED, DCCPState.RESPOND},
        DCCPState.RESPOND: {DCCPState.CLOSED, DCCPState.PARTOPEN},
        DCCPState.PARTOPEN: {DCCPState.CLOSED, DCCPState.OPEN, DCCPState.TIME_WAIT},
        DCCPState.OPEN: {DCCPState.CLOSING, DCCPState.CLOSED, DCCPState.TIME_WAIT},
        DCCPState.CLOSING: {DCCPState.TIME_WAIT, DCCPState.CLOSED},
        DCCPState.TIME_WAIT: {DCCPState.CLOSED},
    }

    def __init__(self, conn: DCCPConnection):
        self.conn = conn
        self.lock = threading.RLock()

    def transition(self, new_state: DCCPState) -> bool:
        with self.lock:
            if new_state in self.VALID_TRANSITIONS.get(self.conn.state, set()):
                old = self.conn.state
                self.conn.state = new_state
                UI.debug(f"State transition: {STATE_NAMES[old.value]} -> {STATE_NAMES[new_state.value]}")
                return True
            UI.error(f"Invalid transition from {STATE_NAMES[self.conn.state.value]} to {STATE_NAMES[new_state.value]}")
            return False

    def handle_packet(self, pkt: DCCPPacket) -> Optional[DCCPPacket]:
        with self.lock:
            state = self.conn.state
            t = pkt.type
            if state == DCCPState.CLOSED:
                if t == DCCPType.REQUEST:
                    self.transition(DCCPState.RESPOND)
                    return self._build_response(pkt)
                return None
            elif state == DCCPState.REQUEST:
                if t == DCCPType.RESPONSE:
                    self.transition(DCCPState.PARTOPEN)
                    return self._build_ack(pkt)
                elif t == DCCPType.RESET:
                    self.transition(DCCPState.CLOSED)
                    return None
            elif state == DCCPState.RESPOND:
                if t == DCCPType.ACK:
                    self.transition(DCCPState.OPEN)
                    return None
                elif t == DCCPType.DATA:
                    self.transition(DCCPState.OPEN)
                    return self._build_dataack(pkt)
            elif state == DCCPState.PARTOPEN:
                if t in (DCCPType.DATA, DCCPType.DATAACK):
                    self.transition(DCCPState.OPEN)
                    return self._build_ack(pkt)
                elif t == DCCPType.RESET:
                    self.transition(DCCPState.TIME_WAIT)
                    return None
            elif state == DCCPState.OPEN:
                if t == DCCPType.DATA:
                    return self._build_ack(pkt)
                elif t == DCCPType.DATAACK:
                    return self._build_data(pkt)
                elif t == DCCPType.CLOSEREQ:
                    self.transition(DCCPState.CLOSING)
                    return self._build_close(pkt)
                elif t == DCCPType.CLOSE:
                    self.transition(DCCPState.TIME_WAIT)
                    return self._build_reset(pkt, DCCPResetCode.CLOSED)
            elif state == DCCPState.CLOSING:
                if t == DCCPType.RESET:
                    self.transition(DCCPState.TIME_WAIT)
                    return None
            return None

    def _build_response(self, pkt: DCCPPacket) -> DCCPPacket:
        self.conn.sequence_number = random.randint(1, 0xFFFFFF)
        self.conn.ack_number = pkt.sequence_number
        return DCCPPacket(
            source_port=self.conn.local_addr[1],
            destination_port=self.conn.remote_addr[1],
            data_offset=0,
            ccval=0,
            cscov=0,
            type=DCCPType.RESPONSE,
            extended_seqno=False,
            sequence_number=self.conn.sequence_number,
            ack_number_present=True,
            ack_number=pkt.sequence_number,
            service_code=self.conn.service_code,
            options=[(DCCPOption.CONFIRM_L, struct.pack("!BB", DCCPFeature.CCID, self.conn.ccid_local)),
                     (DCCPOption.CONFIRM_R, struct.pack("!BB", DCCPFeature.CCID, self.conn.ccid_remote))],
        )

    def _build_ack(self, pkt: DCCPPacket) -> DCCPPacket:
        self.conn.sequence_number = seqno_add(self.conn.sequence_number, 1)
        self.conn.ack_number = pkt.sequence_number
        return DCCPPacket(
            source_port=self.conn.local_addr[1],
            destination_port=self.conn.remote_addr[1],
            data_offset=0,
            ccval=0,
            cscov=0,
            type=DCCPType.ACK,
            extended_seqno=False,
            sequence_number=self.conn.sequence_number,
            ack_number_present=True,
            ack_number=pkt.sequence_number,
            options=[(DCCPOption.TIMESTAMP, struct.pack("!I", int(time.time()) & 0xFFFFFFFF))],
        )

    def _build_dataack(self, pkt: DCCPPacket) -> DCCPPacket:
        self.conn.sequence_number = seqno_add(self.conn.sequence_number, 1)
        self.conn.ack_number = pkt.sequence_number
        return DCCPPacket(
            source_port=self.conn.local_addr[1],
            destination_port=self.conn.remote_addr[1],
            data_offset=0,
            ccval=0,
            cscov=0,
            type=DCCPType.DATAACK,
            extended_seqno=False,
            sequence_number=self.conn.sequence_number,
            ack_number_present=True,
            ack_number=pkt.sequence_number,
            data=b"ACKDATA",
        )

    def _build_data(self, pkt: DCCPPacket) -> DCCPPacket:
        self.conn.sequence_number = seqno_add(self.conn.sequence_number, 1)
        return DCCPPacket(
            source_port=self.conn.local_addr[1],
            destination_port=self.conn.remote_addr[1],
            data_offset=0,
            ccval=0,
            cscov=0,
            type=DCCPType.DATA,
            extended_seqno=False,
            sequence_number=self.conn.sequence_number,
            ack_number_present=False,
            data=b"PAYLOAD",
        )

    def _build_close(self, pkt: DCCPPacket) -> DCCPPacket:
        self.conn.sequence_number = seqno_add(self.conn.sequence_number, 1)
        return DCCPPacket(
            source_port=self.conn.local_addr[1],
            destination_port=self.conn.remote_addr[1],
            data_offset=0,
            ccval=0,
            cscov=0,
            type=DCCPType.CLOSE,
            extended_seqno=False,
            sequence_number=self.conn.sequence_number,
            ack_number_present=True,
            ack_number=pkt.sequence_number,
        )

    def _build_reset(self, pkt: DCCPPacket, code: DCCPResetCode) -> DCCPPacket:
        self.conn.sequence_number = seqno_add(self.conn.sequence_number, 1)
        return DCCPPacket(
            source_port=self.conn.local_addr[1],
            destination_port=self.conn.remote_addr[1],
            data_offset=0,
            ccval=0,
            cscov=0,
            type=DCCPType.RESET,
            extended_seqno=False,
            sequence_number=self.conn.sequence_number,
            ack_number_present=True,
            ack_number=pkt.sequence_number,
            data=struct.pack("!B", code.value) + b"\x00\x00\x00",
        )


# ---------------------------------------------------------------------------
# Transport DCCP over UDP
# ---------------------------------------------------------------------------

class DCCPTransport:
    """Transport DCCP expérimental utilisant UDP comme underlay."""

    def __init__(self, host: str, port: int, is_server: bool = False):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self.connections: Dict[Tuple[str, int], DCCPConnection] = {}
        self.machines: Dict[Tuple[str, int], DCCPStateMachine] = {}
        self.codec = DCCPCodec()
        self.callbacks: List[Callable[[DCCPPacket, Tuple[str, int]], None]] = []
        self.lock = threading.RLock()

    def start(self):
        if self.is_server:
            self.sock.bind((self.host, self.port))
            UI.info(f"DCCP server listening on {Colors.BRIGHT_RED}{self.host}:{self.port}{Colors.RESET}")
        else:
            UI.info(f"DCCP client ready on {Colors.BRIGHT_GREEN}{self.host}:{self.port}{Colors.RESET}")
        self.running = True
        self.recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.recv_thread.start()

    def stop(self):
        self.running = False
        self.sock.close()
        UI.warn("DCCP transport stopped.")

    def register_callback(self, cb: Callable[[DCCPPacket, Tuple[str, int]], None]):
        self.callbacks.append(cb)

    def _receive_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                pkt = self.codec.decode(data)
                if pkt is None:
                    continue
                with self.lock:
                    conn = self.connections.get(addr)
                    if conn is None and self.is_server:
                        conn = DCCPConnection(
                            local_addr=(self.host, self.port),
                            remote_addr=addr,
                            service_code=pkt.service_code,
                        )
                        self.connections[addr] = conn
                        self.machines[addr] = DCCPStateMachine(conn)
                    machine = self.machines.get(addr)
                for cb in self.callbacks:
                    cb(pkt, addr)
                if machine:
                    response = machine.handle_packet(pkt)
                    if response:
                        self.send_packet(response, addr)
                if conn:
                    conn.stats["packets_received"] += 1
                    conn.stats["bytes_received"] += len(data)
            except OSError:
                break
            except Exception as e:
                UI.error(f"Receive loop error: {e}")

    def send_packet(self, pkt: DCCPPacket, addr: Tuple[str, int]):
        raw = self.codec.encode(pkt)
        try:
            self.sock.sendto(raw, addr)
            conn = self.connections.get(addr)
            if conn:
                conn.stats["packets_sent"] += 1
                conn.stats["bytes_sent"] += len(raw)
        except Exception as e:
            UI.error(f"Send error: {e}")

    def connect(self, remote_host: str, remote_port: int, service_code: int = 0):
        addr = (remote_host, remote_port)
        conn = DCCPConnection(
            local_addr=(self.host, self.port),
            remote_addr=addr,
            state=DCCPState.REQUEST,
            service_code=service_code,
        )
        machine = DCCPStateMachine(conn)
        with self.lock:
            self.connections[addr] = conn
            self.machines[addr] = machine
        conn.sequence_number = random.randint(1, 0xFFFFFF)
        req = DCCPPacket(
            source_port=self.port,
            destination_port=remote_port,
            data_offset=0,
            ccval=0,
            cscov=0,
            type=DCCPType.REQUEST,
            extended_seqno=False,
            sequence_number=conn.sequence_number,
            ack_number_present=False,
            service_code=service_code,
            options=[(DCCPOption.CHANGE_L, struct.pack("!BB", DCCPFeature.CCID, CCID.CCID_2)),
                     (DCCPOption.CHANGE_R, struct.pack("!BB", DCCPFeature.CCID, CCID.CCID_2))],
        )
        self.send_packet(req, addr)


# ---------------------------------------------------------------------------
# Analyseur / Wireshark-like
# ---------------------------------------------------------------------------

class DCCPAnalyzer:
    """Analyseur de paquets DCCP avec statistiques et inspection."""

    def __init__(self):
        self.packets: List[DCCPPacket] = []
        self.capture_start: Optional[float] = None
        self.capture_end: Optional[float] = None

    def add(self, pkt: DCCPPacket):
        self.packets.append(pkt)
        if self.capture_start is None:
            self.capture_start = pkt.timestamp
        self.capture_end = pkt.timestamp

    def summary(self) -> str:
        counts: Dict[str, int] = collections.Counter()
        srcs = set()
        dsts = set()
        total_bytes = 0
        for pkt in self.packets:
            counts[pkt.type_name()] += 1
            srcs.add(pkt.source_port)
            dsts.add(pkt.destination_port)
            total_bytes += len(pkt.data) + DCCP_HEADER_MIN_LEN
        duration = (self.capture_end or time.time()) - (self.capture_start or time.time())
        rows = [["Total packets", len(self.packets)],
                ["Duration (s)", f"{duration:.3f}"],
                ["Total bytes", total_bytes],
                ["Source ports", len(srcs)],
                ["Dest ports", len(dsts)]]
        for tname, c in sorted(counts.items()):
            rows.append([tname, c])
        return UI.table(["Métrique", "Valeur"], rows)

    def export_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump([p.to_dict() for p in self.packets], f, indent=2)
        UI.info(f"Capture exported to {path}")


# ---------------------------------------------------------------------------
# Générateur de trafic / fuzzer
# ---------------------------------------------------------------------------

class DCCPTrafficGenerator:
    """Génère des paquets DCCP aléatoires pour tests et fuzzing."""

    def __init__(self, codec: DCCPCodec = DCCPCodec()):
        self.codec = codec

    def generate(self, count: int = 100) -> List[bytes]:
        packets = []
        for _ in range(count):
            pkt_type = random.choice(list(DCCPType))
            seq = random.randint(0, 0xFFFFFFFF)
            ack = random.randint(0, 0xFFFFFFFF) if random.random() > 0.3 else 0
            options = []
            if random.random() > 0.5:
                options.append((DCCPOption.TIMESTAMP, struct.pack("!I", random.randint(0, 0xFFFFFFFF))))
            pkt = DCCPPacket(
                source_port=random.randint(1024, 65535),
                destination_port=random.randint(1024, 65535),
                data_offset=0,
                ccval=random.randint(0, 15),
                cscov=random.randint(0, 15),
                type=pkt_type.value,
                extended_seqno=random.choice([True, False]),
                sequence_number=seq,
                ack_number_present=random.choice([True, False]),
                ack_number=ack,
                data=os.urandom(random.randint(0, 256)),
                options=options,
                service_code=random.randint(0, 0xFFFFFFFF) if pkt_type in (DCCPType.REQUEST, DCCPType.RESPONSE) else 0,
            )
            try:
                packets.append(self.codec.encode(pkt))
            except Exception as e:
                UI.warn(f"Generated invalid packet skipped: {e}")
        return packets


# ---------------------------------------------------------------------------
# Proxy / MITM
# ---------------------------------------------------------------------------

class DCCPProxy:
    """Proxy DCCP qui relaie et inspecte le trafic entre deux endpoints."""

    def __init__(self, listen_host: str, listen_port: int, target_host: str, target_port: int):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((listen_host, listen_port))
        self.target = (target_host, target_port)
        self.clients: Set[Tuple[str, int]] = set()
        self.codec = DCCPCodec()
        self.analyzer = DCCPAnalyzer()
        self.running = False

    def start(self):
        self.running = True
        UI.info(f"DCCP proxy listening on {self.listen_host}:{self.listen_port} -> {self.target_host}:{self.target_port}")
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                pkt = self.codec.decode(data)
                if pkt:
                    self.analyzer.add(pkt)
                    UI.debug(f"[PROXY] {pkt.summary()}")
                if addr == self.target:
                    for client in self.clients:
                        self.sock.sendto(data, client)
                else:
                    self.clients.add(addr)
                    self.sock.sendto(data, self.target)
            except OSError:
                break
            except Exception as e:
                UI.error(f"Proxy error: {e}")

    def stop(self):
        self.running = False
        self.sock.close()


# ---------------------------------------------------------------------------
# CLI / Main
# ---------------------------------------------------------------------------

def run_server(args):
    transport = DCCPTransport(args.host, args.port, is_server=True)
    analyzer = DCCPAnalyzer()
    transport.register_callback(lambda pkt, addr: analyzer.add(pkt))
    transport.start()
    try:
        while True:
            time.sleep(1)
            os.system("clear" if os.name == "posix" else "cls")
            print(UI.banner("DCCP SERVER"))
            print(analyzer.summary())
    except KeyboardInterrupt:
        if args.export:
            analyzer.export_json(args.export)
        transport.stop()


def run_client(args):
    transport = DCCPTransport(args.host, args.port, is_server=False)
    transport.start()
    transport.connect(args.remote_host, args.remote_port, args.service_code)
    UI.info("Sent DCCP REQUEST. Waiting for handshake...")
    try:
        for i in range(args.count):
            time.sleep(1)
            conn = transport.connections.get((args.remote_host, args.remote_port))
            if conn and conn.state == DCCPState.OPEN:
                pkt = DCCPPacket(
                    source_port=args.port,
                    destination_port=args.remote_port,
                    data_offset=0,
                    ccval=0,
                    cscov=0,
                    type=DCCPType.DATA,
                    extended_seqno=False,
                    sequence_number=seqno_add(conn.sequence_number, i + 1),
                    ack_number_present=False,
                    data=f"Hello DCCP {i}".encode(),
                )
                transport.send_packet(pkt, (args.remote_host, args.remote_port))
                UI.info(f"Sent DATA seq={pkt.sequence_number}")
    except KeyboardInterrupt:
        transport.stop()


def run_analyze(args):
    codec = DCCPCodec()
    analyzer = DCCPAnalyzer()
    with open(args.pcap, "rb") as f:
        if args.pcap.endswith(".json"):
            for item in json.load(f):
                raw = binascii.unhexlify(item.get("raw", ""))
                pkt = codec.decode(raw)
                if pkt:
                    analyzer.add(pkt)
        else:
            data = f.read()
            # Assume concatenated DCCP packets for demo
            offset = 0
            while offset < len(data):
                if offset + DCCP_HEADER_MIN_LEN > len(data):
                    break
                second_word = struct.unpack("!I", data[offset+4:offset+8])[0]
                pkt_len = (second_word >> 28) * 4
                if pkt_len < DCCP_HEADER_MIN_LEN or offset + pkt_len > len(data):
                    pkt_len = len(data) - offset
                pkt = codec.decode(data[offset:offset+pkt_len])
                if pkt:
                    analyzer.add(pkt)
                offset += pkt_len
    print(UI.banner("DCCP ANALYZER"))
    print(analyzer.summary())
    for pkt in analyzer.packets[:args.max_display]:
        print(UI.box(pkt.summary(), Colors.BRIGHT_GREEN))
        if args.hexdump:
            print(hexdump(DCCPCodec().encode(pkt)))


def run_generate(args):
    gen = DCCPTrafficGenerator()
    packets = gen.generate(args.count)
    out_path = args.output or "dccp_generated.bin"
    with open(out_path, "wb") as f:
        for p in packets:
            f.write(struct.pack("!H", len(p)) + p)
    UI.info(f"Generated {len(packets)} DCCP packets into {out_path}")


def run_proxy(args):
    proxy = DCCPProxy(args.host, args.port, args.remote_host, args.remote_port)
    try:
        proxy.start()
    except KeyboardInterrupt:
        proxy.stop()


def parse_args():
    parser = argparse.ArgumentParser(
        prog="dccp_protocol.py",
        description="DCCP Protocol Advanced Lab — Hackers Tchad",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Modes:
              server    Lance un serveur DCCP
              client    Lance un client DCCP
              analyze   Analyse une capture binaire ou JSON
              generate  Génère des paquets DCCP aléatoires
              proxy     Proxy MITM/inspecteur DCCP
        """)
    )
    parser.add_argument("--mode", choices=["server", "client", "analyze", "generate", "proxy"], required=True)
    parser.add_argument("--host", default="0.0.0.0", help="Adresse locale (défaut: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=DCCP_PORT_DEFAULT, help="Port local")
    parser.add_argument("--remote-host", default="127.0.0.1", help="Adresse distante (client/proxy)")
    parser.add_argument("--remote-port", type=int, default=DCCP_PORT_DEFAULT, help="Port distant")
    parser.add_argument("--service-code", type=int, default=0, help="Service code")
    parser.add_argument("--count", type=int, default=10, help="Nombre de paquets/data à envoyer/générer")
    parser.add_argument("--pcap", default="capture.json", help="Fichier de capture à analyser")
    parser.add_argument("--output", default=None, help="Fichier de sortie (generate)")
    parser.add_argument("--export", default=None, help="Exporter la capture au format JSON")
    parser.add_argument("--max-display", type=int, default=20, help="Nombre max de paquets à afficher")
    parser.add_argument("--hexdump", action="store_true", help="Afficher le hexdump des paquets")
    parser.add_argument("--no-color", action="store_true", help="Désactiver les couleurs")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.no_color:
        Colors.disable()
    print(UI.banner("DCCP PROTOCOL LAB"))
    print(UI.box(
        "Outil avancé d'apprentissage et de laboratoire pour le protocole DCCP. "
        "Utilisez-le uniquement sur vos propres réseaux. Créé par Hackers Tchad.",
        Colors.BRIGHT_GREEN,
    ))
    if args.mode == "server":
        run_server(args)
    elif args.mode == "client":
        run_client(args)
    elif args.mode == "analyze":
        run_analyze(args)
    elif args.mode == "generate":
        run_generate(args)
    elif args.mode == "proxy":
        run_proxy(args)


if __name__ == "__main__":
    main()
