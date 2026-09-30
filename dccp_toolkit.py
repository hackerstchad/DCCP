#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
DCCP ADVANCED TOOLKIT v2.0.0
A single-file, feature-rich Python GUI application for exploring, crafting,
capturing and fuzzing the Datagram Congestion Control Protocol (DCCP).

Authors  : Hackers Tchad
License  : Educational use only
================================================================================
"""

import os
import sys
import time
import json
import csv
import struct
import socket
import random
import threading
import ipaddress
import hashlib
import base64
import subprocess
import binascii
import re
import tempfile
import string
import math
from datetime import datetime, timedelta
from collections import deque, defaultdict, OrderedDict
from enum import IntEnum
from functools import wraps
from tkinter import (
    Tk, ttk, Frame, Label, Button, Entry, Text, Listbox, Scrollbar,
    Checkbutton, IntVar, StringVar, DoubleVar, OptionMenu, Menu,
    filedialog, messagebox, Canvas, Scale, Radiobutton
)

# Third-party imports
try:
    from scapy.all import (
        sniff, conf, wrpcap, rdpcap, Raw, IP, get_if_list, get_if_addr,
        get_if_hwaddr, Ether, send, srp1
    )
    from scapy.layers.inet import DCCP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = str(e)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

# =============================================================================
# CONSTANTS & ENUMERATIONS
# =============================================================================
APP_NAME = "DCCP Advanced Toolkit"
VERSION = "2.0.0"
AUTHORS = "Hackers Tchad"

class DCCPState(IntEnum):
    CLOSED = 0
    REQUEST = 1
    RESPOND = 2
    PARTOPEN = 3
    OPEN = 4
    CLOSING = 5
    TIMEWAIT = 6
    RESET = 7

DCCP_STATES = {k.name: k.value for k in DCCPState}

class DCCPPacketType(IntEnum):
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

DCCP_PACKET_TYPES = {k.name.title().replace("T", "t").replace("Req", "Req").replace("Ack", "Ack"): k.value
                     for k in DCCPPacketType}
# Normalize keys
DCCP_PACKET_TYPES = {
    "Request": 0, "Response": 1, "Data": 2, "Ack": 3,
    "DataAck": 4, "CloseReq": 5, "Close": 6, "Reset": 7,
    "Sync": 8, "SyncAck": 9
}

CCID_PROFILES = OrderedDict([
    ("CCID2 (TCP-like)", 2),
    ("CCID3 (TFRC)", 3),
    ("CCID4 (TFRC SP)", 4),
    ("CCID5 (Experimental)", 5),
    ("CCID6 (Experimental)", 6),
    ("Custom", 999),
])

DCCP_OPTION_TYPES = {
    "Padding": 0,
    "Mandatory": 1,
    "Slow Receiver": 2,
    "Change L": 32,
    "Confirm L": 33,
    "Change R": 34,
    "Confirm R": 35,
    "Init Cookie": 36,
    "NDP Count": 37,
    "Ack Vector 0": 38,
    "Ack Vector 1": 39,
    "Data Dropped": 40,
    "Timestamp": 41,
    "Timestamp Echo": 42,
    "Elapsed Time": 43,
    "Data Checksum": 44,
    "Receive Buffer": 45,
    "CCID Option 0": 46,
    "CCID Option 1": 47,
    "CCID Option 2": 48,
    "CCID Option 3": 49,
    "CCID Option 4": 50,
    "CCID Option 5": 51,
    "CCID Option 6": 52,
}

DCCP_RESET_CODES = {
    0: "Unspecified",
    1: "Closed",
    2: "Aborted",
    3: "No Connection",
    4: "Packet Error",
    5: "Option Error",
    6: "Connection Refused",
    7: "Bad Service Code",
    8: "Too Busy",
    9: "Bad Init Cookie",
    10: "Aggression Penalty",
    11: "No Feature",
}

THEMES = {
    "matrix": {
        "bg": "#050505",
        "fg": "#00ff41",
        "accent": "#008f11",
        "red": "#ff003c",
        "text_bg": "#0a0a0a",
        "text_fg": "#00ff41",
        "panel": "#111111",
        "font": ("Consolas", 10),
        "title_font": ("Consolas", 12, "bold"),
    },
    "red": {
        "bg": "#1a0000",
        "fg": "#ff1a1a",
        "accent": "#8b0000",
        "red": "#ff003c",
        "text_bg": "#0d0000",
        "text_fg": "#ff4d4d",
        "panel": "#220000",
        "font": ("Consolas", 10),
        "title_font": ("Consolas", 12, "bold"),
    },
}


class DCCPConnection:
    """Represents a single DCCP connection flow."""

    def __init__(self, conn_id, src_ip, dst_ip, src_port, dst_port, ccid=2):
        self.conn_id = conn_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.ccid = ccid
        self.state = "CLOSED"
        self.seq = random.randint(1000, 999999)
        self.ack = 0
        self.created_at = datetime.now()
        self.last_activity = time.time()
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.history = deque(maxlen=200)
        self.lock = threading.Lock()

    def to_dict(self):
        return {
            "conn_id": self.conn_id,
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "ccid": self.ccid,
            "state": self.state,
            "seq": self.seq,
            "ack": self.ack,
            "sent": self.packets_sent,
            "received": self.packets_received,
            "age": int(time.time() - self.last_activity),
        }

    def log_event(self, event):
        self.history.append({"time": datetime.now().isoformat(), "event": event})


class PacketDatabase:
    """Thread-safe in-memory packet database with optional PCAP persistence."""

    def __init__(self, max_size=5000):
        self.packets = deque(maxlen=max_size)
        self.lock = threading.Lock()
        self.stats = defaultdict(int)

    def add(self, packet_info):
        with self.lock:
            self.packets.append(packet_info)
            self.stats[packet_info.get("type", "UNKNOWN")] += 1
            self.stats["total"] += 1

    def get_all(self):
        with self.lock:
            return list(self.packets)

    def clear(self):
        with self.lock:
            self.packets.clear()
            self.stats.clear()

    def export_pcap(self, path):
        if not SCAPY_AVAILABLE:
            return False
        try:
            pkts = [p.get("raw") for p in self.packets if p.get("raw")]
            wrpcap(path, pkts)
            return True
        except Exception as e:
            print(f"PCAP export error: {e}")
            return False

    def import_pcap(self, path):
        if not SCAPY_AVAILABLE:
            return []
        try:
            return rdpcap(path)
        except Exception as e:
            print(f"PCAP import error: {e}")
            return []


class DCCPEngine:
    """Core DCCP state machine, packet builder and sender."""

    def __init__(self, db, logger_callback=None):
        self.db = db
        self.logger_callback = logger_callback
        self.connections = {}
        self.conn_counter = 0
        self.lock = threading.Lock()
        self.running = True
        self.capture_thread = None

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        line = f"[{ts}] {msg}"
        if self.logger_callback:
            self.logger_callback(line)

    def create_connection(self, src_ip, dst_ip, src_port, dst_port, ccid=2):
        with self.lock:
            self.conn_counter += 1
            conn = DCCPConnection(
                self.conn_counter, src_ip, dst_ip, src_port, dst_port, ccid
            )
            self.connections[self.conn_counter] = conn
            conn.log_event("Connection created")
            self.log(f"[CONN] Created #{self.conn_counter} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            return conn

    def get_connection(self, conn_id):
        with self.lock:
            return self.connections.get(conn_id)

    def transition(self, conn, new_state):
        old_state = conn.state
        conn.state = new_state
        conn.last_activity = time.time()
        conn.log_event(f"State {old_state} -> {new_state}")
        self.log(f"[STATE] #{conn.conn_id} {old_state} -> {new_state}")

    def build_dccp_packet(
        self,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ptype="Data",
        seq=None,
        ack=None,
        ccid=2,
        payload=b"",
        dport_in_dccp=False,
    ):
        if not SCAPY_AVAILABLE:
            return None
        type_val = DCCP_PACKET_TYPES.get(ptype, 2)
        if seq is None:
            seq = random.randint(100000, 999999999)
        if ack is None:
            ack = 0
        pkt = IP(src=src_ip, dst=dst_ip, proto=33) / DCCP(
            sport=src_port,
            dport=dst_port,
            type=type_val,
            seq=seq,
            ack=ack,
            reserved=0,
            service_code=0,
            options=[],
        ) / Raw(load=payload)
        return pkt

    def send_packet(self, conn, ptype="Data", payload=b""):
        if not SCAPY_AVAILABLE:
            self.log("[ERROR] Scapy not available, cannot send")
            return False
        try:
            pkt = self.build_dccp_packet(
                conn.src_ip, conn.dst_ip, conn.src_port, conn.dst_port,
                ptype=ptype, seq=conn.seq, ack=conn.ack, ccid=conn.ccid,
                payload=payload,
            )
            if pkt is None:
                return False
            pkt = pkt.__class__(bytes(pkt))
            send(pkt, verbose=0)
            conn.seq += 1
            conn.packets_sent += 1
            conn.bytes_sent += len(payload)
            conn.last_activity = time.time()
            self.db.add({
                "time": datetime.now().isoformat(),
                "type": ptype,
                "dir": "TX",
                "src": f"{conn.src_ip}:{conn.src_port}",
                "dst": f"{conn.dst_ip}:{conn.dst_port}",
                "seq": conn.seq,
                "ack": conn.ack,
                "len": len(payload),
                "raw": pkt,
            })
            self.log(f"[TX] #{conn.conn_id} {ptype} seq={conn.seq} ack={conn.ack}")
            return True
        except Exception as e:
            self.log(f"[ERROR] Send failed: {e}")
            return False

    def open_connection(self, conn):
        self.transition(conn, "REQUEST")
        self.send_packet(conn, "Request")
        # Simulated handshake completion
        time.sleep(0.1)
        self.transition(conn, "PARTOPEN")
        self.send_packet(conn, "Ack")
        self.transition(conn, "OPEN")

    def close_connection(self, conn):
        if conn.state in ("CLOSED", "TIMEWAIT"):
            return
        self.transition(conn, "CLOSING")
        self.send_packet(conn, "Close")
        time.sleep(0.1)
        self.send_packet(conn, "Reset")
        self.transition(conn, "TIMEWAIT")
        time.sleep(0.2)
        self.transition(conn, "CLOSED")

    def start_capture(self, iface=None, bpf_filter="dccp"):
        if not SCAPY_AVAILABLE:
            self.log("[ERROR] Scapy not available, cannot capture")
            return
        self.capture_iface = iface
        self.capture_filter = bpf_filter
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        self.log(f"[CAPTURE] Started on {iface or 'default'} filter={bpf_filter}")

    def _capture_loop(self):
        def process(pkt):
            if not pkt.haslayer(DCCP):
                return
            dccp = pkt[DCCP]
            src = f"{pkt[IP].src}:{dccp.sport}"
            dst = f"{pkt[IP].dst}:{dccp.dport}"
            ptype_name = next(
                (k for k, v in DCCP_PACKET_TYPES.items() if v == dccp.type), "Unknown"
            )
            self.db.add({
                "time": datetime.now().isoformat(),
                "type": ptype_name,
                "dir": "RX",
                "src": src,
                "dst": dst,
                "seq": dccp.seq,
                "ack": dccp.ack,
                "len": len(bytes(dccp.payload)) if dccp.haslayer(Raw) else 0,
                "raw": pkt,
            })
            self.log(f"[RX] {ptype_name} {src} -> {dst} seq={dccp.seq} ack={dccp.ack}")
            with self.lock:
                for conn in self.connections.values():
                    if (
                        conn.src_ip == pkt[IP].dst and conn.dst_ip == pkt[IP].src
                        and conn.src_port == dccp.dport and conn.dst_port == dccp.sport
                    ):
                        conn.packets_received += 1
                        conn.bytes_received += len(bytes(dccp.payload)) if dccp.haslayer(Raw) else 0
                        conn.ack = dccp.seq
                        conn.last_activity = time.time()

        try:
            sniff(
                iface=self.capture_iface,
                filter=self.capture_filter,
                prn=process,
                store=False,
                stop_filter=lambda x: not self.running,
            )
        except Exception as e:
            self.log(f"[ERROR] Capture loop: {e}")

    def stop_capture(self):
        self.running = False
        self.log("[CAPTURE] Stopped")


class DCCPInterfaceScanner:
    """Scans local network interfaces and Wi-Fi details."""

    @staticmethod
    def list_interfaces():
        ifaces = []
        if SCAPY_AVAILABLE:
            for name in get_if_list():
                try:
                    ip = get_if_addr(name)
                    mac = get_if_hwaddr(name)
                except Exception:
                    ip = "N/A"
                    mac = "N/A"
                ifaces.append({"name": name, "ip": ip, "mac": mac})
        elif NETIFACES_AVAILABLE:
            for name in netifaces.interfaces():
                addrs = netifaces.ifaddresses(name)
                ip = addrs.get(netifaces.AF_INET, [{}])[0].get("addr", "N/A")
                mac = addrs.get(netifaces.AF_LINK, [{}])[0].get("addr", "N/A")
                ifaces.append({"name": name, "ip": ip, "mac": mac})
        elif PSUTIL_AVAILABLE:
            stats = psutil.net_if_addrs()
            for name, addrs in stats.items():
                ip = "N/A"
                mac = "N/A"
                for a in addrs:
                    if a.family == socket.AF_INET:
                        ip = a.address
                    elif a.family == socket.AF_LINK:
                        mac = a.address
                ifaces.append({"name": name, "ip": ip, "mac": mac})
        else:
            ifaces.append({"name": "lo", "ip": "127.0.0.1", "mac": "00:00:00:00:00:00"})
        return ifaces

    @staticmethod
    def get_wifi_network():
        try:
            if sys.platform == "linux":
                out = subprocess.check_output(
                    ["iwgetid", "-r"], stderr=subprocess.DEVNULL
                ).decode().strip()
                return out or "Unknown"
        except Exception:
            pass
        return "Unknown"


class DCCPChart(Frame):
    """Simple real-time line chart widget."""

    def __init__(self, parent, theme, width=300, height=120, **kwargs):
        super().__init__(parent, bg=theme["bg"], **kwargs)
        self.theme = theme
        self.width = width
        self.height = height
        self.canvas = Canvas(
            self, width=width, height=height, bg=theme["panel"],
            highlightthickness=1, highlightbackground=theme["accent"]
        )
        self.canvas.pack()
        self.data = deque([0] * 60, maxlen=60)
        self.red_data = deque([0] * 60, maxlen=60)

    def update_value(self, green_value, red_value=0):
        self.data.append(green_value)
        self.red_data.append(red_value)
        self.draw()

    def draw(self):
        self.canvas.delete("all")
        t = self.theme
        w, h = self.width, self.height
        self.canvas.create_line(0, h - 1, w, h - 1, fill=t["accent"])
        self.canvas.create_line(0, 0, 0, h, fill=t["accent"])

        def render_series(data, color):
            if not data:
                return
            max_val = max(max(data), 1)
            step = w / len(data)
            points = []
            for i, v in enumerate(data):
                x = i * step
                y = h - (v / max_val) * (h - 4) - 2
                points.append((x, y))
            for i in range(1, len(points)):
                self.canvas.create_line(
                    points[i - 1][0], points[i - 1][1],
                    points[i][0], points[i][1],
                    fill=color, width=2
                )

        render_series(self.data, t["fg"])
        render_series(self.red_data, t["red"])


class DCCPToolkitApp:
    """Main GUI application."""

    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{VERSION} - {AUTHORS}")
        self.root.geometry("1400x900")
        self.root.configure(bg="#050505")
        self.theme_name = "matrix"
        self.theme = THEMES[self.theme_name]
        self.db = PacketDatabase()
        self.engine = DCCPEngine(self.db, logger_callback=self.append_log)
        self.auto_scroll = True
        self.fuzz_running = False
        self.stats_thread = None
        self.build_ui()
        self.refresh_interfaces()
        self.start_stats_loop()

    def apply_theme_to_widget(self, widget):
        t = self.theme
        widget.configure(bg=t["bg"], fg=t["fg"], font=t["font"])

    def build_ui(self):
        t = self.theme
        root = self.root
        root.configure(bg=t["bg"])

        # Styles
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=t["bg"], tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background=t["panel"], foreground=t["fg"], font=t["font"])
        style.map("TNotebook.Tab", background=[("selected", t["accent"])])

        # Menu
        menubar = Menu(root, bg=t["panel"], fg=t["fg"], activebackground=t["accent"])
        file_menu = Menu(menubar, tearoff=0, bg=t["panel"], fg=t["fg"])
        file_menu.add_command(label="Export PCAP", command=self.export_pcap)
        file_menu.add_command(label="Import PCAP", command=self.import_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        theme_menu = Menu(menubar, tearoff=0, bg=t["panel"], fg=t["fg"])
        theme_menu.add_command(label="Matrix Green", command=lambda: self.set_theme("matrix"))
        theme_menu.add_command(label="Hacker Red", command=lambda: self.set_theme("red"))
        menubar.add_cascade(label="Theme", menu=theme_menu)
        root.config(menu=menubar)

        # Header
        header = Frame(root, bg=t["bg"], height=60)
        header.pack(fill="x", padx=10, pady=5)
        Label(
            header, text=APP_NAME, bg=t["bg"], fg=t["red"],
            font=("Consolas", 18, "bold")
        ).pack(side="left")
        Label(
            header, text=f"v{VERSION} | {AUTHORS}", bg=t["bg"], fg=t["fg"],
            font=t["font"]
        ).pack(side="left", padx=20)
        self.status_label = Label(header, text="READY", bg=t["panel"], fg=t["fg"], font=t["font"])
        self.status_label.pack(side="right", padx=10)

        # Notebook
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_dashboard = Frame(self.notebook, bg=t["bg"])
        self.tab_craft = Frame(self.notebook, bg=t["bg"])
        self.tab_connections = Frame(self.notebook, bg=t["bg"])
        self.tab_capture = Frame(self.notebook, bg=t["bg"])
        self.tab_fuzzer = Frame(self.notebook, bg=t["bg"])
        self.tab_logs = Frame(self.notebook, bg=t["bg"])
        self.tab_about = Frame(self.notebook, bg=t["bg"])

        self.notebook.add(self.tab_dashboard, text="Dashboard")
        self.notebook.add(self.tab_craft, text="Craft & Send")
        self.notebook.add(self.tab_connections, text="Connections")
        self.notebook.add(self.tab_capture, text="Capture")
        self.notebook.add(self.tab_fuzzer, text="Fuzzer / Stress")
        self.notebook.add(self.tab_logs, text="Logs")
        self.notebook.add(self.tab_about, text="About")

        self.build_dashboard()
        self.build_craft_tab()
        self.build_connections_tab()
        self.build_capture_tab()
        self.build_fuzzer_tab()
        self.build_logs_tab()
        self.build_about_tab()

    def build_dashboard(self):
        t = self.theme
        tab = self.tab_dashboard

        top = Frame(tab, bg=t["bg"])
        top.pack(fill="x", padx=10, pady=10)

        # Interface selector
        Label(top, text="Interface:", bg=t["bg"], fg=t["fg"], font=t["font"]).pack(side="left")
        self.iface_var = StringVar()
        self.iface_combo = ttk.Combobox(top, textvariable=self.iface_var, width=30, state="readonly")
        self.iface_combo.pack(side="left", padx=5)
        Button(top, text="Refresh", command=self.refresh_interfaces, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)

        self.wifi_label = Label(top, text="Wi-Fi: Unknown", bg=t["bg"], fg=t["fg"], font=t["font"])
        self.wifi_label.pack(side="left", padx=20)

        # Stats panels
        stats_frame = Frame(tab, bg=t["bg"])
        stats_frame.pack(fill="x", padx=10, pady=10)

        def stat_box(parent, title, var):
            f = Frame(parent, bg=t["panel"], width=200, height=80, highlightbackground=t["accent"], highlightthickness=1)
            f.pack_propagate(False)
            f.pack(side="left", padx=5, pady=5)
            Label(f, text=title, bg=t["panel"], fg=t["fg"], font=t["title_font"]).pack(pady=5)
            Label(f, textvariable=var, bg=t["panel"], fg=t["red"], font=("Consolas", 14, "bold")).pack()
            return f

        self.total_var = StringVar(value="0")
        self.tx_var = StringVar(value="0")
        self.rx_var = StringVar(value="0")
        self.conns_var = StringVar(value="0")

        stat_box(stats_frame, "Total Packets", self.total_var)
        stat_box(stats_frame, "Transmitted", self.tx_var)
        stat_box(stats_frame, "Received", self.rx_var)
        stat_box(stats_frame, "Active Connections", self.conns_var)

        # Chart
        chart_frame = Frame(tab, bg=t["bg"])
        chart_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.chart = DCCPChart(chart_frame, t, width=800, height=250)
        self.chart.pack(fill="both", expand=True)

    def build_craft_tab(self):
        t = self.theme
        tab = self.tab_craft

        left = Frame(tab, bg=t["bg"])
        left.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        fields = [
            ("Source IP", "src_ip", "127.0.0.1"),
            ("Destination IP", "dst_ip", "127.0.0.1"),
            ("Source Port", "src_port", "5000"),
            ("Destination Port", "dst_port", "5001"),
            ("Sequence", "seq", ""),
            ("Acknowledgement", "ack", ""),
        ]
        self.craft_vars = {}
        for label, key, default in fields:
            f = Frame(left, bg=t["bg"])
            f.pack(fill="x", pady=3)
            Label(f, text=label, bg=t["bg"], fg=t["fg"], font=t["font"], width=18, anchor="w").pack(side="left")
            var = StringVar(value=default)
            self.craft_vars[key] = var
            Entry(f, textvariable=var, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"]).pack(side="left", fill="x", expand=True)

        f = Frame(left, bg=t["bg"])
        f.pack(fill="x", pady=3)
        Label(f, text="Packet Type", bg=t["bg"], fg=t["fg"], font=t["font"], width=18, anchor="w").pack(side="left")
        self.craft_type_var = StringVar(value="Data")
        OptionMenu(f, self.craft_type_var, *DCCP_PACKET_TYPES.keys()).pack(side="left")

        f = Frame(left, bg=t["bg"])
        f.pack(fill="x", pady=3)
        Label(f, text="CCID Profile", bg=t["bg"], fg=t["fg"], font=t["font"], width=18, anchor="w").pack(side="left")
        self.craft_ccid_var = StringVar(value="CCID2 (TCP-like)")
        OptionMenu(f, self.craft_ccid_var, *CCID_PROFILES.keys()).pack(side="left")

        f = Frame(left, bg=t["bg"])
        f.pack(fill="x", pady=3)
        Label(f, text="Payload", bg=t["bg"], fg=t["fg"], font=t["font"], width=18, anchor="w").pack(side="left")
        self.payload_var = StringVar(value="PAYLOAD")
        Entry(f, textvariable=self.payload_var, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"]).pack(side="left", fill="x", expand=True)

        btn_frame = Frame(left, bg=t["bg"])
        btn_frame.pack(fill="x", pady=10)
        Button(btn_frame, text="Send Packet", command=self.send_crafted_packet, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)
        Button(btn_frame, text="Create Connection", command=self.create_connection_from_craft, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)

        right = Frame(tab, bg=t["bg"])
        right.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        Label(right, text="Packet Preview", bg=t["bg"], fg=t["fg"], font=t["title_font"]).pack(anchor="w")
        self.preview_text = Text(right, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"], height=20)
        self.preview_text.pack(fill="both", expand=True)
        Button(right, text="Preview", command=self.preview_packet, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(pady=5)

    def build_connections_tab(self):
        t = self.theme
        tab = self.tab_connections

        ctrl = Frame(tab, bg=t["bg"])
        ctrl.pack(fill="x", padx=10, pady=5)
        Button(ctrl, text="Open", command=self.open_selected_connection, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)
        Button(ctrl, text="Close", command=self.close_selected_connection, bg=t["red"], fg="white", font=t["font"]).pack(side="left", padx=5)
        Button(ctrl, text="Send Data", command=self.send_data_selected, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)
        Button(ctrl, text="Refresh", command=self.refresh_connections, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)

        cols = ("ID", "Source", "Destination", "CCID", "State", "Seq", "Ack", "Sent", "Recv", "Age")
        self.conn_tree = ttk.Treeview(tab, columns=cols, show="headings", height=20)
        for c in cols:
            self.conn_tree.heading(c, text=c)
            self.conn_tree.column(c, width=100)
        self.conn_tree.pack(fill="both", expand=True, padx=10, pady=5)

    def build_capture_tab(self):
        t = self.theme
        tab = self.tab_capture

        ctrl = Frame(tab, bg=t["bg"])
        ctrl.pack(fill="x", padx=10, pady=5)
        Button(ctrl, text="Start Capture", command=self.start_capture, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)
        Button(ctrl, text="Stop Capture", command=self.stop_capture, bg=t["red"], fg="white", font=t["font"]).pack(side="left", padx=5)
        Button(ctrl, text="Clear", command=self.clear_capture, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)

        self.capture_text = Text(tab, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"])
        self.capture_text.pack(fill="both", expand=True, padx=10, pady=5)

    def build_fuzzer_tab(self):
        t = self.theme
        tab = self.tab_fuzzer

        left = Frame(tab, bg=t["bg"])
        left.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        Label(left, text="Fuzzer Target", bg=t["bg"], fg=t["fg"], font=t["title_font"]).pack(anchor="w")
        f = Frame(left, bg=t["bg"])
        f.pack(fill="x", pady=3)
        Label(f, text="Target IP", bg=t["bg"], fg=t["fg"], font=t["font"], width=12, anchor="w").pack(side="left")
        self.fuzz_ip_var = StringVar(value="127.0.0.1")
        Entry(f, textvariable=self.fuzz_ip_var, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"]).pack(side="left", fill="x", expand=True)

        f = Frame(left, bg=t["bg"])
        f.pack(fill="x", pady=3)
        Label(f, text="Port Range", bg=t["bg"], fg=t["fg"], font=t["font"], width=12, anchor="w").pack(side="left")
        self.fuzz_port_min = StringVar(value="5000")
        self.fuzz_port_max = StringVar(value="5050")
        Entry(f, textvariable=self.fuzz_port_min, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"], width=8).pack(side="left")
        Label(f, text="-", bg=t["bg"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)
        Entry(f, textvariable=self.fuzz_port_max, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"], width=8).pack(side="left")

        f = Frame(left, bg=t["bg"])
        f.pack(fill="x", pady=3)
        Label(f, text="Packet Count", bg=t["bg"], fg=t["fg"], font=t["font"], width=12, anchor="w").pack(side="left")
        self.fuzz_count_var = StringVar(value="1000")
        Entry(f, textvariable=self.fuzz_count_var, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"]).pack(side="left")

        f = Frame(left, bg=t["bg"])
        f.pack(fill="x", pady=3)
        Label(f, text="Delay (ms)", bg=t["bg"], fg=t["fg"], font=t["font"], width=12, anchor="w").pack(side="left")
        self.fuzz_delay_var = StringVar(value="1")
        Entry(f, textvariable=self.fuzz_delay_var, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"]).pack(side="left")

        self.fuzz_random_payload = IntVar(value=1)
        Checkbutton(left, text="Random payload sizes", variable=self.fuzz_random_payload, bg=t["bg"], fg=t["fg"], selectcolor=t["panel"], font=t["font"]).pack(anchor="w", pady=3)
        self.fuzz_random_type = IntVar(value=1)
        Checkbutton(left, text="Random DCCP packet types", variable=self.fuzz_random_type, bg=t["bg"], fg=t["fg"], selectcolor=t["panel"], font=t["font"]).pack(anchor="w", pady=3)

        btn_frame = Frame(left, bg=t["bg"])
        btn_frame.pack(fill="x", pady=10)
        self.fuzz_btn = Button(btn_frame, text="Start Fuzzer", command=self.toggle_fuzzer, bg=t["red"], fg="white", font=t["font"])
        self.fuzz_btn.pack(side="left", padx=5)

        right = Frame(tab, bg=t["bg"])
        right.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        Label(right, text="Fuzzer Log", bg=t["bg"], fg=t["fg"], font=t["title_font"]).pack(anchor="w")
        self.fuzz_text = Text(right, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"])
        self.fuzz_text.pack(fill="both", expand=True)

    def build_logs_tab(self):
        t = self.theme
        tab = self.tab_logs

        ctrl = Frame(tab, bg=t["bg"])
        ctrl.pack(fill="x", padx=10, pady=5)
        self.scroll_var = IntVar(value=1)
        Checkbutton(ctrl, text="Auto-scroll", variable=self.scroll_var, bg=t["bg"], fg=t["fg"], selectcolor=t["panel"], font=t["font"]).pack(side="left", padx=5)
        Button(ctrl, text="Clear", command=self.clear_logs, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)
        Button(ctrl, text="Save Logs", command=self.save_logs, bg=t["accent"], fg=t["fg"], font=t["font"]).pack(side="left", padx=5)

        self.log_text = Text(tab, bg=t["text_bg"], fg=t["text_fg"], insertbackground=t["fg"], font=t["font"])
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)

    def build_about_tab(self):
        t = self.theme
        tab = self.tab_about
        text = (
            f"{APP_NAME}\n"
            f"Version {VERSION}\n"
            f"Created by {AUTHORS}\n\n"
            "Educational DCCP exploration toolkit.\n"
            "Use responsibly on networks you own or have permission to test.\n\n"
            "Features:\n"
            "- Full DCCP state machine simulation\n"
            "- Packet crafting, capture and injection\n"
            "- Connection manager with live statistics\n"
            "- Fuzzer and stress generator\n"
            "- PCAP import/export\n"
            "- Red/green hacker-style interface\n"
        )
        Label(tab, text=text, bg=t["bg"], fg=t["fg"], font=t["font"], justify="left").pack(anchor="nw", padx=20, pady=20)

    # Actions
    def set_theme(self, name):
        self.theme_name = name
        self.theme = THEMES[name]
        messagebox.showinfo("Theme", f"Theme changed to {name}. Restart to apply fully.")

    def refresh_interfaces(self):
        ifaces = DCCPInterfaceScanner.list_interfaces()
        names = [i["name"] for i in ifaces]
        self.iface_combo["values"] = names
        if names and not self.iface_var.get():
            self.iface_var.set(names[0])
        wifi = DCCPInterfaceScanner.get_wifi_network()
        self.wifi_label.config(text=f"Wi-Fi: {wifi}")

    def start_stats_loop(self):
        def loop():
            while True:
                time.sleep(1)
                try:
                    stats = self.db.stats
                    total = stats.get("total", 0)
                    tx = sum(1 for p in self.db.get_all() if p.get("dir") == "TX")
                    rx = sum(1 for p in self.db.get_all() if p.get("dir") == "RX")
                    conns = len(self.engine.connections)
                    self.total_var.set(str(total))
                    self.tx_var.set(str(tx))
                    self.rx_var.set(str(rx))
                    self.conns_var.set(str(conns))
                    self.chart.update_value(tx, rx)
                    self.refresh_connections()
                except Exception as e:
                    print(f"Stats loop error: {e}")

        self.stats_thread = threading.Thread(target=loop, daemon=True)
        self.stats_thread.start()

    def append_log(self, line):
        def update():
            self.log_text.insert("end", line + "\n")
            if self.scroll_var.get():
                self.log_text.see("end")
        self.root.after(0, update)

    def clear_logs(self):
        self.log_text.delete("1.0", "end")

    def save_logs(self):
        path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log files", "*.log")])
        if path:
            with open(path, "w") as f:
                f.write(self.log_text.get("1.0", "end"))

    def create_connection_from_craft(self):
        try:
            src_ip = self.craft_vars["src_ip"].get()
            dst_ip = self.craft_vars["dst_ip"].get()
            src_port = int(self.craft_vars["src_port"].get())
            dst_port = int(self.craft_vars["dst_port"].get())
            ccid_name = self.craft_ccid_var.get()
            ccid = CCID_PROFILES.get(ccid_name, 2)
            conn = self.engine.create_connection(src_ip, dst_ip, src_port, dst_port, ccid)
            messagebox.showinfo("Connection", f"Connection #{conn.conn_id} created")
            self.refresh_connections()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_crafted_packet(self):
        try:
            src_ip = self.craft_vars["src_ip"].get()
            dst_ip = self.craft_vars["dst_ip"].get()
            src_port = int(self.craft_vars["src_port"].get())
            dst_port = int(self.craft_vars["dst_port"].get())
            ptype = self.craft_type_var.get()
            payload = self.payload_var.get().encode()
            seq_txt = self.craft_vars["seq"].get()
            ack_txt = self.craft_vars["ack"].get()
            seq = int(seq_txt) if seq_txt else None
            ack = int(ack_txt) if ack_txt else None
            ccid = CCID_PROFILES.get(self.craft_ccid_var.get(), 2)
            pkt = self.engine.build_dccp_packet(
                src_ip, dst_ip, src_port, dst_port, ptype, seq, ack, ccid, payload
            )
            if pkt is None:
                messagebox.showerror("Error", "Scapy unavailable")
                return
            send(pkt, verbose=0)
            self.db.add({
                "time": datetime.now().isoformat(),
                "type": ptype,
                "dir": "TX",
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "seq": seq or 0,
                "ack": ack or 0,
                "len": len(payload),
                "raw": pkt,
            })
            self.append_log(f"[TX] Crafted {ptype} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def preview_packet(self):
        try:
            src_ip = self.craft_vars["src_ip"].get()
            dst_ip = self.craft_vars["dst_ip"].get()
            src_port = int(self.craft_vars["src_port"].get())
            dst_port = int(self.craft_vars["dst_port"].get())
            ptype = self.craft_type_var.get()
            payload = self.payload_var.get().encode()
            seq_txt = self.craft_vars["seq"].get()
            ack_txt = self.craft_vars["ack"].get()
            seq = int(seq_txt) if seq_txt else None
            ack = int(ack_txt) if ack_txt else None
            ccid = CCID_PROFILES.get(self.craft_ccid_var.get(), 2)
            pkt = self.engine.build_dccp_packet(
                src_ip, dst_ip, src_port, dst_port, ptype, seq, ack, ccid, payload
            )
            self.preview_text.delete("1.0", "end")
            if pkt is None:
                self.preview_text.insert("end", "Scapy not available\n")
                return
            self.preview_text.insert("end", pkt.show(dump=True))
            self.preview_text.insert("end", "\n\nHexdump:\n")
            self.preview_text.insert("end", binascii.hexlify(bytes(pkt)).decode())
        except Exception as e:
            self.preview_text.delete("1.0", "end")
            self.preview_text.insert("end", f"Error: {e}")

    def refresh_connections(self):
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
        for conn in self.engine.connections.values():
            d = conn.to_dict()
            self.conn_tree.insert(
                "", "end",
                values=(
                    d["conn_id"], d["src"], d["dst"], d["ccid"],
                    d["state"], d["seq"], d["ack"], d["sent"],
                    d["received"], d["age"]
                )
            )

    def selected_conn_id(self):
        sel = self.conn_tree.selection()
        if not sel:
            messagebox.showwarning("Selection", "No connection selected")
            return None
        item = self.conn_tree.item(sel[0])
        return int(item["values"][0])

    def open_selected_connection(self):
        cid = self.selected_conn_id()
        if cid:
            conn = self.engine.get_connection(cid)
            threading.Thread(target=self.engine.open_connection, args=(conn,), daemon=True).start()

    def close_selected_connection(self):
        cid = self.selected_conn_id()
        if cid:
            conn = self.engine.get_connection(cid)
            threading.Thread(target=self.engine.close_connection, args=(conn,), daemon=True).start()

    def send_data_selected(self):
        cid = self.selected_conn_id()
        if cid:
            conn = self.engine.get_connection(cid)
            payload = self.payload_var.get().encode() or b"DATA"
            threading.Thread(target=self.engine.send_packet, args=(conn, "Data", payload), daemon=True).start()

    def start_capture(self):
        iface = self.iface_var.get()
        self.engine.start_capture(iface=iface or None, bpf_filter="dccp")
        self.status_label.config(text="CAPTURING", fg=self.theme["red"])
        threading.Thread(target=self._capture_refresh, daemon=True).start()

    def stop_capture(self):
        self.engine.stop_capture()
        self.status_label.config(text="READY", fg=self.theme["fg"])

    def clear_capture(self):
        self.capture_text.delete("1.0", "end")
        self.db.clear()

    def _capture_refresh(self):
        last_len = 0
        while self.engine.running:
            time.sleep(0.5)
            packets = self.db.get_all()
            if len(packets) != last_len:
                last_len = len(packets)
                self.root.after(0, self._update_capture_text, packets[-100:])

    def _update_capture_text(self, packets):
        self.capture_text.delete("1.0", "end")
        for p in packets:
            line = f"[{p.get('time','')}] {p.get('dir')} {p.get('type')} {p.get('src')} -> {p.get('dst')} seq={p.get('seq')} ack={p.get('ack')} len={p.get('len')}\n"
            self.capture_text.insert("end", line)
        self.capture_text.see("end")

    def toggle_fuzzer(self):
        if self.fuzz_running:
            self.fuzz_running = False
            self.fuzz_btn.config(text="Start Fuzzer", bg=self.theme["red"])
        else:
            self.fuzz_running = True
            self.fuzz_btn.config(text="Stop Fuzzer", bg=self.theme["accent"])
            threading.Thread(target=self._fuzzer_loop, daemon=True).start()

    def _fuzzer_loop(self):
        try:
            target_ip = self.fuzz_ip_var.get()
            port_min = int(self.fuzz_port_min.get())
            port_max = int(self.fuzz_port_max.get())
            count = int(self.fuzz_count_var.get())
            delay = float(self.fuzz_delay_var.get()) / 1000.0
            types = list(DCCP_PACKET_TYPES.keys())
            for i in range(count):
                if not self.fuzz_running:
                    break
                dst_port = random.randint(port_min, port_max)
                src_port = random.randint(10000, 65000)
                ptype = random.choice(types) if self.fuzz_random_type.get() else "Data"
                size = random.randint(0, 1400) if self.fuzz_random_payload.get() else 64
                payload = os.urandom(size)
                pkt = self.engine.build_dccp_packet(
                    "127.0.0.1", target_ip, src_port, dst_port, ptype, payload=payload
                )
                if pkt is None:
                    continue
                try:
                    send(pkt, verbose=0)
                    self.db.add({
                        "time": datetime.now().isoformat(),
                        "type": ptype,
                        "dir": "TX",
                        "src": f"127.0.0.1:{src_port}",
                        "dst": f"{target_ip}:{dst_port}",
                        "seq": 0,
                        "ack": 0,
                        "len": len(payload),
                        "raw": pkt,
                    })
                except Exception as e:
                    self._append_fuzz_log(f"Send error: {e}")
                if i % 100 == 0:
                    self._append_fuzz_log(f"Fuzzed {i}/{count} packets")
                time.sleep(delay)
            self._append_fuzz_log("Fuzzer finished")
        except Exception as e:
            self._append_fuzz_log(f"Fuzzer error: {e}")
        finally:
            self.fuzz_running = False
            self.root.after(0, lambda: self.fuzz_btn.config(text="Start Fuzzer", bg=self.theme["red"]))

    def _append_fuzz_log(self, line):
        self.root.after(0, lambda: (self.fuzz_text.insert("end", line + "\n"), self.fuzz_text.see("end")))

    def export_pcap(self):
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if path:
            if self.db.export_pcap(path):
                messagebox.showinfo("Export", f"Saved {path}")
            else:
                messagebox.showerror("Export", "PCAP export failed")

    def import_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if path:
            pkts = self.db.import_pcap(path)
            messagebox.showinfo("Import", f"Loaded {len(pkts)} packets from {path}")


def main():
    if not SCAPY_AVAILABLE:
        print("WARNING: Scapy not installed. Packet crafting/capture disabled.")
        print(f"Install error: {SCAPY_ERROR}")
    root = Tk()
    app = DCCPToolkitApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
