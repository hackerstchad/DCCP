DCCP

<img width="1450" height="935" alt="arch_full" src="https://github.com/user-attachments/assets/91647b3a-ea6f-4d8c-9dfa-6ebcda2362e3" />


# DCCP — Le Protocole Datagram Congestion Control Protocol

## Guide Ultime, Complet et Avancé

---

## 1. Introduction

Le **Datagram Congestion Control Protocol (DCCP)** est un protocole de transport de la couche 4 du modèle OSI, défini principalement par la RFC 4340. Il a été conçu par l'IETF (Internet Engineering Task Force) pour combler le fossé entre **UDP** et **TCP**. DCCP offre un service **non fiable** comme UDP, mais avec une **gestion de la congestion** comme TCP, et avec un **handshake en trois temps** pour établir et fermer les connexions proprement.

Contrairement à TCP, DCCP ne garantit pas la livraison des données, ne les délivre pas en ordre, et n'effectue pas de retransmission automatique. En revanche, il fournit un mécanisme de **contrôle de congestion fiable**, des **négociations de fonctionnalités**, un **contrôle d'erreur sur les en-têtes**, et supporte plusieurs **CCIDs (Congestion Control IDs)** pour adapter le comportement de congestion à l'application.

DCCP est particulièrement adapté aux applications multimédias en temps réel (VoIP, streaming vidéo, jeux en ligne) qui tolèrent une perte de paquets mais nécessitent un contrôle de congestion pour ne pas saturer le réseau.

---

## 2. Histoire et Contexte

### 2.1 Pourquoi DCCP ?

Avant DCCP, les développeurs d'applications temps réel devaient choisir entre :

- **TCP** : fiable, ordonné, avec contrôle de congestion, mais avec des latences dues aux retransmissions et à la remise en ordre.
- **UDP** : rapide, sans connexion, sans contrôle de congestion, mais pouvant causer des congestions réseau et être bloqué par les pare-feu.

DCCP a été proposé pour offrir le meilleur des deux mondes : la rapidité et la tolérance aux pertes d'UDP, avec le contrôle de congestion et la connexion fiable de TCP.

### 2.2 Chronologie

- **2002** : Première proposition de DCCP par Eddie Kohler, Mark Handley et Sally Floyd.
- **2006** : Publication de la RFC 4340, la spécification principale de DCCP.
- **2006** : RFC 4341 et RFC 4342 définissant CCID-2 (TCP-like) et CCID-3 (TFRC).
- **2009** : RFC 5595 et RFC 5596 sur l'utilisation de DCCP avec RTP et les extensions de service.
- **2010** : RFC 5762 sur DCCP-UDP encapsulation pour la traversée de NAT.
- **2012** : RFC 6773 sur les extensions de DCCP pour les services mobiles.
- **Années 2020** : DCCP reste un protocole de niche, utilisé principalement dans la recherche, le streaming et certaines applications temps réel.

### 2.3 Auteurs principaux

- **Eddie Kohler** (UCLA)
- **Mark Handley** (UCL)
- **Sally Floyd** (ICIR)
- **Joerg Widmer** (Eurecom)
- **Lars Eggert** (Nokia)

---

## 3. Modèle de Service DCCP

### 3.1 Caractéristiques du service

DCCP fournit un service de transport avec les propriétés suivantes :

| Propriété | DCCP | TCP | UDP |
|-----------|------|-----|-----|
| Connexion | Oui | Oui | Non |
| Livraison fiable | Non | Oui | Non |
| Ordre de livraison | Non garanti | Oui | Non |
| Contrôle de congestion | Oui | Oui | Non |
| Datagrammes | Oui | Non (flux) | Oui |
| Handshake | 3-way | 3-way | Aucun |
| Multiplexage par port | Oui | Oui | Oui |

### 3.2 Types d'applications adaptées

- **Streaming vidéo/audio** : tolérance aux pertes, mais besoin de contrôle de congestion.
- **VoIP et visioconférence** : faible latence prioritaire sur la fiabilité.
- **Jeux en ligne** : envoi rapide d'états de jeu, avec adaptation à la congestion.
- **Téléchargements en temps réel** : flux de données continus sans retransmission.

---

## 4. Architecture DCCP

### 4.1 Position dans la pile TCP/IP

DCCP réside au niveau de la couche transport, au même niveau que TCP et UDP. Il utilise IP comme protocole de couche réseau. Le numéro de protocole IP assigné à DCCP est **33**.

```
+---------------------+
|    Application      |
+---------------------+
|    DCCP / TCP / UDP |
+---------------------+
|    IPv4 / IPv6      |
+---------------------+
|    Liaison          |
+---------------------+
```

### 4.2 Composants principaux

- **En-tête DCCP** : contient ports, numéros de séquence, accusés de réception, type de paquet, options.
- **State Machine** : gère les états de connexion (CLOSED, REQUEST, RESPOND, PARTOPEN, OPEN, CLOSING, TIME_WAIT).
- **CCIDs** : modules de contrôle de congestion (CCID-2, CCID-3, etc.).
- **Options** : mécanismes de négociation et de métadonnées.
- **Service Codes** : identifient l'application utilisant DCCP.

---

## 5. Format du Paquet DCCP

### 5.1 En-tête DCCP (RFC 4340)

L'en-tête DCCP a une longueur minimale de **12 octets** et peut atteindre jusqu'à **1020 octets** avec les options.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |           Dest Port           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Data Offset   | CCVal | CsCov |           Checksum          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     |           |          Sequence Number (48 bits)          |
| Res |  Type     |                                             |
|     |           |                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Ack Number Present        |          Ack Number           |
|     |                         |          (48 bits)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Options (variable)                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Application Data (variable)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 5.2 Description des champs

- **Source Port** (16 bits) : port source.
- **Destination Port** (16 bits) : port destination.
- **Data Offset** (8 bits) : taille de l'en-tête DCCP en mots de 32 bits.
- **CCVal** (4 bits) : valeur utilisée par le CCID actif.
- **CsCov** (4 bits) : couverture du checksum (0 = tout le paquet).
- **Checksum** (16 bits) : somme de contrôle sur l'en-tête, options, données et pseudo-header IP.
- **Reserved** (3 bits) : réservé, doit être zéro.
- **Type** (4 bits) : type de paquet DCCP.
- **Extended Sequence Number** (1 bit) : étend le numéro de séquence à 48 bits.
- **Sequence Number** (48 bits) : numéro de séquence du paquet.
- **Ack Number Present** (1 bit) : indique la présence d'un numéro d'accusé de réception.
- **Ack Number** (48 bits) : numéro d'accusé de réception.
- **Options** : liste d'options DCCP.
- **Data** : données applicatives.

### 5.3 Types de paquets

| Valeur | Type | Description |
|--------|------|-------------|
| 0 | Request | Demande d'ouverture de connexion |
| 1 | Response | Réponse à une demande |
| 2 | Data | Données applicatives |
| 3 | Ack | Accusé de réception |
| 4 | DataAck | Données + accusé de réception |
| 5 | CloseReq | Demande de fermeture |
| 6 | Close | Fermeture |
| 7 | Reset | Réinitialisation brutale |
| 8 | Sync | Synchronisation |
| 9 | SyncAck | Accusé de synchronisation |

### 5.4 Codes de Reset

| Valeur | Code | Signification |
|--------|------|---------------|
| 0 | Unspecified | Erreur non spécifiée |
| 1 | Closed | Connexion fermée |
| 2 | Aborted | Abortée |
| 3 | No Connection | Pas de connexion |
| 4 | Packet Error | Erreur de paquet |
| 5 | Option Error | Erreur d'option |
| 6 | Mandatory Error | Erreur d'option Mandatory |
| 7 | Connection Refused | Connexion refusée |
| 8 | Bad Service Code | Mauvais service code |
| 9 | Too Busy | Trop occupé |
| 10 | Bad Init Cookie | Cookie invalide |
| 11 | Aggression Penalty | Pénalité d'agressivité |

---

## 6. Machine à États DCCP

### 6.1 États de connexion

```
        +--------+  app passive open   +---------+
        | CLOSED |-------------------->| LISTEN  | (non standard)
        +--------+                     +---------+
          | active open                     |
          v                                 |
       +---------+  Request            +---------+
       | REQUEST |-------------------->| RESPOND |
       +---------+                     +---------+
          | <Response|                      | <Ack|
          |         |                      v
          |       +---------+          +----------+
          +------>| PARTOPEN|--------->|   OPEN   |
                  +---------+ Ack      +----------+
                                        | |
                                        | | CloseReq/Close
                                        v v
                                   +----------+
                                   | CLOSING  |
                                   +----------+
                                        |
                                        v
                                   +----------+
                                   |TIME_WAIT |
                                   +----------+
```

### 6.2 Transitions principales

- **CLOSED → REQUEST** : l'application demande une connexion active.
- **REQUEST → RESPOND** : le serveur reçoit un Request et répond.
- **RESPOND → PARTOPEN** : le client reçoit le Response.
- **PARTOPEN → OPEN** : le client envoie un Ack/DataAck confirmant l'établissement.
- **OPEN → CLOSING** : une des parties envoie CloseReq/Close.
- **CLOSING → TIME_WAIT** : réception de l'accusé de fermeture.
- **TIME_WAIT → CLOSED** : expiration du timer (2 MSL).

### 6.3 Gestion du Handshake

Le handshake DCCP est en **trois temps** :

1. **Client → Serveur : REQUEST** (avec Service Code et options CCID).
2. **Serveur → Client : RESPONSE** (avec Init Cookie et options confirmées).
3. **Client → Serveur : ACK ou DATAACK** (validation et ouverture).

---

## 7. Options DCCP

### 7.1 Liste des options principales

| Numéro | Option | Description |
|--------|--------|-------------|
| 0 | Pad | Remplissage |
| 1 | Mandatory | Option obligatoire |
| 2 | Slow Receiver | Récepteur lent |
| 32 | Change L | Changer une feature locale |
| 33 | Confirm L | Confirmer une feature locale |
| 34 | Change R | Changer une feature distante |
| 35 | Confirm R | Confirmer une feature distante |
| 36 | Init Cookie | Cookie d'initiation anti-SYN flood |
| 37 | NDP Count | Nombre de Non-Data Packets |
| 38 | Ack Vector [Nonce=0] | Vecteur d'accusés de réception |
| 39 | Ack Vector [Nonce=1] | Vecteur d'accusés de réception |
| 41 | Timestamp | Horodatage |
| 42 | Timestamp Echo | Écho d'horodatage |
| 43 | Elapsed Time | Temps écoulé |
| 44 | Data Dropped | Données perdues signalées |
| 45 | Timestamp Echo Size | Taille de l'écho |
| 46 | Elapsed Time Size | Taille du temps écoulé |

### 7.2 Négociation de features

Les features DCCP permettent de négocier les paramètres de connexion :

| Numéro | Feature | Description |
|--------|---------|-------------|
| 1 | CCID | Congestion Control ID |
| 2 | Short Seqnos | Séquences courtes |
| 3 | Sequence Window | Fenêtre de séquence |
| 4 | ECN Incapable | Incapacité ECN |
| 5 | Ack Ratio | Ratio d'accusés |
| 6 | Enable Ack Vector | Activer Ack Vector |
| 7 | TX Dequeue Rate | Taux de défilement TX |
| 8 | Send Lev Rate | Taux d'envoi |

---

## 8. Congestion Control IDs (CCIDs)

### 8.1 CCID-2 — TCP-like Congestion Control (RFC 4341)

- Comportement similaire à TCP Reno.
- Augmente la fenêtre de congestion additivement.
- Réduction de moitié en cas de perte.
- Adapté aux applications tolérantes aux pertes mais voulant maximiser le débit.

### 8.2 CCID-3 — TFRC (TCP-Friendly Rate Control) (RFC 4342)

- Contrôle de congestion basé sur un modèle de taux.
- Réduit les variations de débit.
- Adapté au streaming multimédia.

### 8.3 Autres CCIDs

- **CCID-4** : TFRC avec SP (Small Packets).
- **CCID-5 à CCID-255** : réservés ou expérimentaux.

---

## 9. Checksum DCCP

Le checksum DCCP couvre :
- L'en-tête DCCP.
- Les options.
- Les données (selon CsCov).
- Le pseudo-header IPv4 ou IPv6.

Le pseudo-header IPv4 est structuré comme suit :
```
+-------------------------------+
|          Source IP            |
+-------------------------------+
|        Destination IP         |
+-------------------------------+
|  Zero  | Protocol |  Length   |
+-------------------------------+
```

---

## 10. Numéros de Séquence et Accusés de Réception

### 10.1 Numéro de séquence

- Identifie chaque paquet DCCP de manière unique sur une connexion.
- Par défaut sur 24 bits, extensible à 48 bits avec le bit Extended Sequence Number.
- Incrémenté à chaque paquet envoyé.

### 10.2 Ack Number

- Indique le prochain numéro de séquence attendu.
- Présent dans les paquets d'accusé de réception.
- Permet au récepteur de signaler quels paquets ont été reçus.

### 10.3 Ack Vector

L'option Ack Vector fournit une bitmap de réception des paquets :
- **0** : paquet reçu.
- **1** : paquet reçu et ECN Echoed.
- **2** : paquet non reçu.
- **3** : non reportable.

---

## 11. Service Codes

Le Service Code est un entier de 32 bits inclus dans les paquets Request et Response. Il identifie l'application ou le service utilisant DCCP.

Exemples :
- `0x00000000` : service non spécifié.
- `0x43433032` : ASCII "CC02" pour CCID-2.
- Les applications peuvent définir leurs propres codes.

---

## 12. Encapsulation DCCP dans UDP

La RFC 5762 définit une encapsulation de DCCP dans UDP pour traverser les NAT et pare-feu. Le paquet UDP transporte un paquet DCCP complet dans son payload.

```
+-------------------+
|   UDP Header      |
+-------------------+
|   DCCP Packet     |
+-------------------+
```

---

## 13. Sécurité et Attaques sur DCCP

### 13.1 Vulnérabilités connues

- **SYN flood** : exploitation du handshake avec des paquets Request.
- **Reset injection** : envoi de paquets Reset forgés.
- **Option abuse** : options Mandatory malformées.
- **Seqno spoofing** : usurpation de numéros de séquence.
- **MITM** : interception et modification des paquets DCCP.

### 13.2 Bonnes pratiques

- Utiliser Init Cookie pour limiter les SYN floods.
- Valider toutes les options reçues.
- Utiliser des pare-feu stateful DCCP.
- Surveiller les anomalies de séquence.
- Encapsuler DCCP dans UDP/TLS pour la traversée NAT et la confidentialité.

---

## 14. Commandes Pratiques

### 14.1 Sous Linux

```bash
# Vérifier le support DCCP dans le noyau
lsmod | grep dccp

# Charger les modules DCCP
sudo modprobe dccp
sudo modprobe dccp_ccid2
sudo modprobe dccp_ccid3

# Voir les sockets DCCP actifs
ss -dccp

# Capturer du trafic DCCP avec tcpdump
sudo tcpdump -i any -n proto 33

# Capturer DCCP sur un port spécifique
sudo tcpdump -i any -n 'udp port 5001 or proto 33'

# Activer le routage DCCP dans le noyau
sudo sysctl -w net.dccp.default.seq_window=100

# Désactiver DCCP (sécurité)
echo "install dccp /bin/true" | sudo tee /etc/modprobe.d/dccp.conf
```

### 14.2 Sous Windows

```powershell
# Vérifier les ports DCCP en écoute
Get-NetTCPConnection -LocalPort 5001

# Activer/désactiver le protocole DCCP (via le registre ou pare-feu)
# Note : le support natif DCCP est limité sous Windows.
```

### 14.3 Avec Scapy

```python
from scapy.all import *
# Envoyer un paquet DCCP
pkt = IP(dst="192.168.1.10", proto=33)/b'\x13\x88\x13\x88...'
send(pkt)
```

---

## 15. Implémentations et Outils

### 15.1 Implémentations du noyau Linux

- Module `dccp` dans le noyau Linux.
- CCID-2 et CCID-3 disponibles via `dccp_ccid2` et `dccp_ccid3`.
- API socket : `socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP)`.

### 15.2 Outils d'analyse

- **Wireshark** : décode les paquets DCCP.
- **tcpdump** : capture les paquets IP proto 33.
- **Scapy** : forge et envoie des paquets DCCP.
- **GRAND DCCP** : suite avancée Python créée par Hackers Tchad.

### 15.3 Bibliothèques

- `scapy` : manipulation de paquets réseau.
- `dpkt` : parsing de paquets.
- `impacket` : protocoles réseau en Python.

---

## 16. Liens et Ressources

### 16.1 RFCs officielles

- RFC 4340 : https://tools.ietf.org/html/rfc4340
- RFC 4341 : https://tools.ietf.org/html/rfc4341
- RFC 4342 : https://tools.ietf.org/html/rfc4342
- RFC 5595 : https://tools.ietf.org/html/rfc5595
- RFC 5596 : https://tools.ietf.org/html/rfc5596
- RFC 5762 : https://tools.ietf.org/html/rfc5762
- RFC 6773 : https://tools.ietf.org/html/rfc6773

### 16.2 Documentation et tutoriels

- https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol
- https://datatracker.ietf.org/wg/dccp/about/
- https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml
- https://wiki.wireshark.org/DCCP

### 16.3 Articles de recherche

- Kohler, Handley, Floyd. "Datagram Congestion Control Protocol". SIGCOMM 2006.
- Floyd, S., et al. "Equation-Based Congestion Control for Unicast Applications." ACM SIGCOMM 2000.

### 16.4 Livres recommandés

- **TCP/IP Illustrated, Volume 1** — W. Richard Stevens
- **The Linux Networking Architecture** — Klaus Wehrle, Frank Pahlke, Hartmut Ritter, Daniel Müller, Marc Bechler
- **Network Protocols: Architecture, Security and Standardization** — Thorsten Braun
- **Computer Networking: A Top-Down Approach** — James F. Kurose, Keith W. Ross
- **Unix Network Programming, Volume 1** — W. Richard Stevens, Bill Fenner, Andrew M. Rudoff

---

## 17. Glossaire DCCP

| Terme | Définition |
|-------|------------|
| CCID | Congestion Control ID, identifie l'algorithme de congestion |
| CsCov | Checksum Coverage, définit la couverture du checksum |
| DCCP | Datagram Congestion Control Protocol |
| ECN | Explicit Congestion Notification |
| Feature | Paramètre négociable de la connexion DCCP |
| Init Cookie | Cookie anti-SYN-flood envoyé par le serveur |
| MSL | Maximum Segment Lifetime |
| NDP | Non-Data Packet |
| Option | Extension d'en-tête DCCP |
| Reset | Paquet de réinitialisation de connexion |
| Seqno | Numéro de séquence |
| Service Code | Identifiant de service applicatif |
| State Machine | Machine à états de la connexion DCCP |
| TFRC | TCP-Friendly Rate Control |

---

## 18. Comparaison avec d'autres protocoles

### 18.1 DCCP vs TCP

- DCCP ne garantit pas la livraison ni l'ordre.
- DCCP envoie des datagrammes, TCP envoie un flux.
- DCCP supporte plusieurs CCIDs, TCP a un seul algorithme de congestion.
- DCCP est mieux adapté au multimédia temps réel.

### 18.2 DCCP vs UDP

- DCCP a un handshake et une machine à états.
- DCCP a un contrôle de congestion intégré.
- UDP est plus simple et plus rapide.
- DCCP est plus robuste face à la congestion réseau.

### 18.3 DCCP vs SCTP

- SCTP supporte le multihoming et le multistreaming.
- DCCP est orienté datagramme simple.
- SCTP est fiable, DCCP ne l'est pas.

### 18.4 DCCP vs QUIC

- QUIC est un protocole moderne sur UDP avec multiplexage et chiffrement intégré.
- DCCP est un protocole IP de couche transport.
- QUIC est plus utilisé dans le web moderne.
- DCCP est plus léger et spécialisé pour le média temps réel.

---

## 19. Cas d'Usage Réels

### 19.1 Streaming vidéo

DCCP permet d'envoyer des flux vidéo sans retransmission, en adaptant le débit à la congestion. Les pertes de paquets se traduisent par une légère dégradation qualité mais pas par du buffering.

### 19.2 VoIP

La faible latence est prioritaire. DCCP évite la saturation du réseau tout en limitant les retards.

### 19.3 Jeux en ligne

Les mises à jour d'état de jeu sont envoyées rapidement. DCCP contrôle la congestion sans bloquer les envois par des retransmissions.

### 19.4 Téléphonie mobile

DCCP est utilisé dans certaines architectures 4G/5G pour le transport de médias temps réel.

---

## 20. Configuration Réseau

### 20.1 Pare-feu et DCCP

```bash
# iptables : autoriser DCCP sur un port
sudo iptables -A INPUT -p dccp --dport 5001 -j ACCEPT

# nftables
sudo nft add rule inet filter input dccp dport 5001 accept

# pf (FreeBSD/OpenBSD)
pass in proto dccp to any port 5001
```

### 20.2 NAT et DCCP

Le NAT de DCCP est complexe car il nécessite de suivre les numéros de séquence et la state machine. L'encapsulation UDP (RFC 5762) simplifie la traversée NAT.

### 20.3 QoS et DCCP

DCCP peut être marqué avec DSCP pour la qualité de service :
- **EF (Expedited Forwarding)** : VoIP.
- **AF (Assured Forwarding)** : streaming vidéo.
- **BE (Best Effort)** : données classiques.

---

## 21. Dépannage

### 21.1 Problèmes courants

| Symptôme | Cause possible | Solution |
|----------|----------------|----------|
| Impossible d'établir la connexion | Module DCCP non chargé | `sudo modprobe dccp` |
| Paquets rejetés | Pare-feu bloquant DCCP | Ouvrir le port et le proto 33 |
| Latence élevée | Mauvais CCID | Utiliser CCID-3 pour les médias |
| Perte massive | Fenêtre de séquence trop petite | Augmenter Sequence Window |
| Handshake échoue | Service code mismatch | Vérifier les Service Codes |

### 21.2 Outils de debug

```bash
# Logs noyau DCCP
dmesg | grep -i dccp

# Statistiques sockets
cat /proc/net/dccp

# Capture Wireshark
wireshark -k -i eth0 -f "proto 33"
```

---

## 22. Développement avec DCCP

### 22.1 En C

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/dccp.h>

int sock = socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP);
struct sockaddr_in addr = {0};
addr.sin_family = AF_INET;
addr.sin_port = htons(5001);
addr.sin_addr.s_addr = INADDR_ANY;
bind(sock, (struct sockaddr *)&addr, sizeof(addr));
listen(sock, 5);
```

### 22.2 En Python (socket natif Linux)

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DCCP, socket.IPPROTO_DCCP)
sock.bind(("0.0.0.0", 5001))
sock.listen(5)
```

### 22.3 Avec Scapy

```python
from scapy.all import IP, Raw
pkt = IP(dst="192.168.1.10", proto=33)/Raw(load=b"...")
send(pkt)
```

---

## 23. Futur de DCCP

- Intégration possible avec QUIC/MPQUIC.
- Utilisation dans les réseaux 5G/6G.
- Amélioration des CCIDs pour les hauts débits et faibles latences.
- Adoption dans les CDN et plateformes de streaming.
- Recherche sur DCCP sécurisé (DCCP-TLS, DCCP over QUIC).

---


**FIN DU GUIDE DCCP**
