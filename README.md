# ASN Block

Blocca automaticamente il traffico da interi ASN (Autonomous System Numbers) usando **ipset** + **iptables** + **MaxMind GeoLite2-ASN** in locale.

## Requisiti

- Ubuntu 20.04+ / Debian 11+
- Root access
- MaxMind `GeoLite2-ASN.mmdb` installato in `/usr/share/GeoIP/`

## Installazione (one-liner)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/perfido19/AsnBlock/main/install.sh)
```

> ⚠️ Sostituisci `TUOREPO` con il tuo username GitHub.

## Come funziona

1. Legge la lista ASN da `/etc/asn-blocklist.txt`
2. Scansiona il database MaxMind locale (zero query esterne)
3. Carica tutti i prefissi IPv4 in un ipset via bulk restore
4. La regola iptables in **posizione 1** droppa tutto il traffico sorgente che matcha il set
5. Il cron aggiorna automaticamente ogni 6 ore con priorità minima

## File installati

| File | Descrizione |
|------|-------------|
| `/etc/asn-blocklist.txt` | Lista ASN da bloccare (modificabile) |
| `/usr/local/bin/asn-to-ipset.py` | Script Python che scansiona il mmdb |
| `/usr/local/bin/update-asn-block.sh` | Script di aggiornamento |
| `/etc/ipset.conf` | Snapshot ipset (auto-generato) |
| `/etc/iptables/rules.v4` | Regole iptables persistenti |
| `/etc/systemd/system/ipset-restore.service` | Ripristino ipset al boot |

## Comandi utili

```bash
# Aggiornamento manuale
/usr/local/bin/update-asn-block.sh

# Quanti prefissi sono bloccati
ipset list blocked_asn | grep -c '/'

# Testa se un IP è bloccato
ipset test blocked_asn 1.2.3.4

# Aggiungi un ASN
nano /etc/asn-blocklist.txt
/usr/local/bin/update-asn-block.sh

# Log aggiornamenti automatici
tail -f /var/log/update-asn-block.log
```

## Struttura repo

```
asn-block/
├── install.sh              ← one-liner installer
├── asn-blocklist.txt       ← lista ASN (1200+ entries)
├── update-asn-block.sh     ← script aggiornamento
├── asn-to-ipset.py         ← scanner MaxMind Python
└── ipset-restore.service   ← systemd unit
```
