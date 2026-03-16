# AsnBlock

Blocco automatico di ASN tramite **ipset + iptables** usando il database **MaxMind GeoLite2-ASN** locale.

## Caratteristiche

- ✅ Zero query esterne — usa il database MaxMind già installato
- ✅ Whitelist per prefissi CIDR e domini (risolti automaticamente)
- ✅ Watcher automatico — il set si aggiorna appena modifichi la whitelist
- ✅ Swap atomico — nessuna finestra con set vuoto durante l'aggiornamento
- ✅ Regola LOG in pos.1 + DROP in pos.2 di iptables INPUT
- ✅ Ripristino automatico al boot via systemd
- ✅ Aggiornamento automatico ogni 6 ore (cron con priorità minima)
- ✅ Modalità update — se già installato aggiorna tutto senza reinstallare
- ✅ Script per aggiornare le liste da GitHub sui VPS già installati
- ✅ ~1200 ASN preconfigurati

## Prerequisiti

- Ubuntu 20.04+ / Debian 11+
- Accesso `root`
- `/usr/share/GeoIP/GeoLite2-ASN.mmdb` già installato

## Installazione / Aggiornamento (one-liner)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/perfido19/AsnBlock/master/install.sh)
```

Se già installato, lo stesso comando aggiorna tutto automaticamente.

## Aggiornare le liste da GitHub (su VPS già installati)

```bash
/usr/local/bin/update-lists.sh
```

Scarica `asn-blocklist.txt` e `asn-whitelist-nets.txt` da GitHub, fa backup dei file esistenti e aggiorna il set ipset.

## File nella repo

| File | Descrizione |
|------|-------------|
| `install.sh` | Installer/Updater self-contained — contiene tutto |
| `update-lists.sh` | Aggiorna le liste ASN e whitelist da GitHub |
| `asn-to-ipset.py` | Script Python — scansiona MaxMind, gestisce whitelist + domini |
| `update-asn-block.sh` | Script aggiornamento set ipset |
| `asn-log-stats.py` | Statistiche pacchetti droppati per ASN |
| `whitelist-watcher.sh` | Watcher inotify — aggiorna il set al salvataggio della whitelist |
| `whitelist-watcher.service` | Servizio systemd per il watcher |
| `ipset-restore.service` | Servizio systemd — ripristina ipset al boot |
| `asn-blocklist.txt` | Lista ASN da bloccare (~1200 ASN) |
| `asn-whitelist-nets.txt` | Whitelist prefissi e domini da non bloccare |

## File installati sul VPS

| Percorso | Descrizione |
|----------|-------------|
| `/etc/asn-blocklist.txt` | Lista ASN — modificabile, preservata negli update |
| `/etc/asn-whitelist-nets.txt` | Whitelist — modificabile, preservata negli update |
| `/usr/local/bin/asn-to-ipset.py` | Script Python MaxMind |
| `/usr/local/bin/update-asn-block.sh` | Script aggiornamento set |
| `/usr/local/bin/update-lists.sh` | Aggiorna liste da GitHub |
| `/usr/local/bin/asn-log-stats.py` | Statistiche |
| `/usr/local/bin/whitelist-watcher.sh` | Watcher whitelist |
| `/etc/ipset.conf` | Snapshot ipset (auto-generato) |
| `/etc/iptables/rules.v4` | Regole iptables persistenti |
| `/etc/systemd/system/ipset-restore.service` | Ripristino al boot |
| `/etc/systemd/system/whitelist-watcher.service` | Watcher whitelist |
| `/var/log/update-asn-block.log` | Log aggiornamenti cron |

## Comandi utili

```bash
# Aggiorna liste da GitHub (ASN + whitelist)
/usr/local/bin/update-lists.sh

# Aggiornamento manuale del set ipset
/usr/local/bin/update-asn-block.sh

# Verifica regole iptables (LOG pos.1 + DROP pos.2)
iptables -L INPUT -n --line-numbers | head -5

# Prefissi bloccati
ipset list blocked_asn | grep -c '/'

# Testa se un IP è bloccato
ipset test blocked_asn 1.2.3.4

# Statistiche per ASN
python3 /usr/local/bin/asn-log-stats.py
python3 /usr/local/bin/asn-log-stats.py --top 50
python3 /usr/local/bin/asn-log-stats.py --since "Mar 15"

# Stato servizi
systemctl status whitelist-watcher.service
systemctl status ipset-restore.service

# Log aggiornamenti
tail -30 /var/log/update-asn-block.log
```

## Gestione whitelist

```bash
# Aggiungi un dominio (risolto automaticamente)
echo 'domain:mioserver.com  # server personale' >> /etc/asn-whitelist-nets.txt

# Aggiungi un prefisso CIDR
echo '1.2.3.0/24  # range cliente' >> /etc/asn-whitelist-nets.txt

# Il set si aggiorna automaticamente entro pochi secondi (watcher)
# Oppure forza manualmente:
/usr/local/bin/update-asn-block.sh
```

## Flush manuale del set

```bash
iptables -D INPUT -m set --match-set blocked_asn src -j DROP 2>/dev/null || true
iptables -D INPUT -m set --match-set blocked_asn src -j LOG  2>/dev/null || true
ipset flush blocked_asn
/usr/local/bin/update-asn-block.sh
```

## Rimozione completa

```bash
iptables -D INPUT -m set --match-set blocked_asn src -j DROP 2>/dev/null || true
iptables -D INPUT -m set --match-set blocked_asn src -j LOG  2>/dev/null || true
iptables-save > /etc/iptables/rules.v4
ipset destroy blocked_asn
systemctl disable --now ipset-restore.service whitelist-watcher.service
rm /etc/systemd/system/ipset-restore.service
rm /etc/systemd/system/whitelist-watcher.service
systemctl daemon-reload
crontab -l | grep -v update-asn-block | crontab -
rm /usr/local/bin/update-asn-block.sh
rm /usr/local/bin/asn-to-ipset.py
rm /usr/local/bin/asn-log-stats.py
rm /usr/local/bin/whitelist-watcher.sh
rm /usr/local/bin/update-lists.sh
rm /etc/asn-blocklist.txt
rm /etc/asn-whitelist-nets.txt
rm /etc/ipset.conf
```
