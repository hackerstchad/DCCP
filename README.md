
DCCP

Une application graphique Python sophistiquée à fichier unique pour explorer et interagir avec la pile DCCP (Datagram Congestion Control Protocol) via des interfaces Wi-Fi et Ethernet.

## Caractéristiques

- Machine d'état DCCP complète (FERMÉE, DEMANDE, RÉPONSE, PARTOPEN, OUVERTE, FERMETURE, TIMEWAIT, FERMÉE)
- Création, capture, injection et analyse de paquets via Scapy
- Profils de contrôle de congestion (CCID2, CCID3, coutume) 
- Gestionnaire de connexions avec plusieurs flux DCCP 
- Enregistreur de paquets en temps réel, hexdump, statistiques et graphiques
-Scanner et sélecteur Wi-Fi / interface
- Fuzzer intégré et générateur de stress
- Exportation / importation PCAP

## Utilisation

"'coup
exigences d'installation de pip -r.txt
python sudo 3 dccp_toolkit.py
```

Les privilèges Root / sudo sont requis pour la création et la capture de paquets de socket bruts.

## Auteurs

Hackers Tchad
