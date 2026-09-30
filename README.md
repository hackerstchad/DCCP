DCCP

<img width="1450" height="935" alt="arch_full" src="https://github.com/user-attachments/assets/91647b3a-ea6f-4d8c-9dfa-6ebcda2362e3" />

# Datagram Congestion Control Protocol

Outil de protocole DCCP (Datagram Congestion Control Protocol, RFC 4340, RFC 5595, RFC 5596, RFC 5762, RFC 6773). Créé par la communauté Hackers Tchad.

## Qu'est-ce que DCCP ?

DCCP est un protocole de transport unicast, fiable en connexion, orienté datagramme, avec contrôle de congestion. Il se situe entre UDP (sans connexion) et TCP (flux fiable).

## Ressources officielles

- RFC 4340 : https://tools.ietf.org/html/rfc4340
- RFC 5595 : https://tools.ietf.org/html/rfc5595
- RFC 5596 : https://tools.ietf.org/html/rfc5596
- RFC 5762 : https://tools.ietf.org/html/rfc5762
- RFC 6773 : https://tools.ietf.org/html/rfc/rfc6773
- Wikipedia : https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol
- IETF DCCP Working Group : https://datatracker.ietf.org/wg/dccp/about/

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

### Mode serveur
```bash
python dccp_protocol.py server --host 0.0.0.0 --port 5001
```

### Mode client
```bash
python dccp_protocol.py client --host 192.168.1.10 --port 5001 --file data.bin
```

### Mode sniffer/analyse
```bash
python dccp_protocol.py sniff --iface wlan0
```

### Envoi de paquet DCCP brut
```bash
python dccp_protocol.py craft --src 192.168.1.5 --dst 192.168.1.10 --sport 1234 --dport 5001 --type Request
```

## Fonctionnalités

- Implémentation des types de paquets DCCP : Request, Response, Data, Ack, DataAck, CloseReq, Close, Reset, Sync, SyncAck.
- Gestion des options : Change L/R, Confirm L/R, Init Cookie, NDP, Ack Vector, Timestamp, Timestamp Echo, Elapsed Time, Data Dropped, Slow Receiver, etc.
- Sniffing et parsing de paquets DCCP réels via Scapy.
- Simulations client/serveur locale sur Wi-Fi.
- Chiffrement optionnel des payloads avec AES-256-GCM.
- Interface terminal stylisée rouge et verte.
- Logs détaillés, statistiques temps réel, mode debug.

## Commandes utiles Linux

```bash
# Vérifier le support DCCP du noyau
lsmod | grep dccp

# Charger le module DCCP
sudo modprobe dccp

# Voir les sockets DCCP actifs
ss -dccp

# Capturer du trafic DCCP avec tcpdump
sudo tcpdump -i any -n proto 33
```

## Livres recommandés

- TCP/IP Illustrated, Volume 1 — W. Richard Stevens
- The Linux Networking Architecture — Klaus Wehrle et al.
- Network Protocols: Architecture, Security and Standardization — Thorsten

  Auter
  
  Hackers Tchad 
