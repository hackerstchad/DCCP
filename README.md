DCCP

<img width="1450" height="935" alt="arch_full" src="https://github.com/user-attachments/assets/91647b3a-ea6f-4d8c-9dfa-6ebcda2362e3" />


# GRAND DCCP — Suite Avancée DCCP

l'analyse et la sécurisation du protocole DCCP (Datagram Congestion Control Protocol).

## Contenu

- `grand_dccp.py` : script principal (10000+ lignes) avec stack complète, sniffer, fuzzer, proxy, attaques, benchmark, chiffrement, interface terminal stylisée rouge/verte.
- `requirements_grand_dccp.txt` : dépendances.
- `README_GRAND_DCCP.md` : documentation.

## Modes principaux

- `server` : serveur DCCP multi-clients avec state machine complète.
- `client` : client DCCP avec handshake, envoi de données, CCID.
- `sniff` : capture et analyse de paquets DCCP sur une interface.
- `fuzz` : fuzzing de paquets DCCP pour tests de robustesse.
- `proxy` : proxy MITM/inspecteur DCCP.
- `attack` : simulations d'attaques (SYN flood, Reset injection, option abuse, seqno fuzz).
- `benchmark` : tests de performance et de congestion.
- `learn` : mode interactif pédagogique.

## Installation

```bash
pip install -r requirements_grand_dccp.txt
```

Sous Linux, activez le module DCCP du noyau :
```bash
sudo modprobe dccp
sudo modprobe dccp_ccid2
sudo modprobe dccp_ccid3
```

## Utilisation

```bash
# Serveur
python grand_dccp.py server --host 0.0.0.0 --port 5001

# Client
python grand_dccp.py client --remote-host 127.0.0.1 --remote-port 5001

# Sniffer
python grand_dccp.py sniff --iface eth0

# Fuzzer
python grand_dccp.py fuzz --target 127.0.0.1 --target-port 5001 --count 1000

# Proxy MITM
python grand_dccp.py proxy --host 0.0.0.0 --port 5050 --remote-host 127.0.0.1 --remote-port 5001

# Benchmark
python grand_dccp.py benchmark --host 127.0.0.1 --port 5001 --duration 60
```

## Ressources

- RFC 4340 : https://tools.ietf.org/html/rfc4340
- RFC 4341 : https://tools.ietf.org/html/rfc4341
- RFC 4342 : https://tools.ietf.org/html/rfc4342
- RFC 5595 : https://tools.ietf.org/html/rfc5595
- RFC 5596 : https://tools.ietf.org/html/rfc5596
- RFC 5762 : https://tools.ietf.org/html/rfc5762
- RFC 6773 : https://tools.ietf.org/html/rfc6773

## Livres

- TCP/IP Illustrated, Volume 1 — W. Richard Stevens
- The Linux Networking Architecture — Klaus Wehrle et al.
- Network Protocols: Architecture, Security and Standardization — Thorsten Braun

 Hackers Tchad.
