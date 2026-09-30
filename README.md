# DCCP Advanced Toolkit

A sophisticated, single-file Python GUI application for exploring and interacting with the DCCP (Datagram Congestion Control Protocol) stack over Wi-Fi and Ethernet interfaces.

## Features

- Full DCCP state machine (CLOSED, REQUEST, RESPOND, PARTOPEN, OPEN, CLOSING, TIMEWAIT, CLOSED)
- Packet crafting, capture, injection and parsing via Scapy
- Congestion control profiles (CCID2, CCID3, custom)
- Connection manager with multiple simultaneous DCCP flows
- Real-time packet logger, hexdump, statistics and charts
- Wi-Fi / interface scanner and selector
- Red/green hacker-style tkinter interface
- Built-in fuzzer and stress generator
- PCAP export / import

## Usage

```bash
pip install -r requirements.txt
sudo python3 dccp_toolkit.py
```

Root / sudo privileges are required for raw socket packet crafting and capture.

## Authors

Hackers Tchad

## License

Educational use only.
