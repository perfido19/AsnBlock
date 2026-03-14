#!/usr/bin/env bash
set -euo pipefail

SET="blocked_asn"
TMPSET="${SET}_new"
ASN_FILE="/etc/asn-blocklist.txt"
IPSET_SAVE_FILE="/etc/ipset.conf"
MMDB="/usr/share/GeoIP/GeoLite2-ASN.mmdb"
LOG_TAG="[update-asn-block]"

if [[ ! -f "$ASN_FILE" ]]; then
    echo "$LOG_TAG File ASN non trovato: $ASN_FILE" >&2
    exit 1
fi

if [[ ! -f "$MMDB" ]]; then
    echo "$LOG_TAG Database MaxMind non trovato: $MMDB" >&2
    exit 1
fi

ASNS=()
while IFS= read -r LINE || [[ -n "$LINE" ]]; do
    LINE="$(echo "$LINE" | tr -d '\r' | xargs)"
    [[ -z "$LINE" ]] && continue
    [[ "$LINE" =~ ^# ]] && continue
    ASN="$(echo "$LINE" | sed 's/#.*//' | xargs)"
    [[ -z "$ASN" ]] && continue
    ASN="${ASN^^}"
    ASN="${ASN#AS}"
    ASNS+=("$ASN")
done < "$ASN_FILE"

if [[ ${#ASNS[@]} -eq 0 ]]; then
    echo "$LOG_TAG Nessun ASN trovato in $ASN_FILE" >&2
    exit 1
fi

echo "$LOG_TAG ASN da bloccare: ${ASNS[*]}"

# Crea il set principale se non esiste
ipset create "$SET" hash:net family inet maxelem 1048576 -exist

# Se esiste già ma con maxelem insufficiente, ricrealo
# (ipset -exist non aggiorna maxelem su set già esistenti)
CURRENT_MAXELEM=$(ipset list "$SET" | awk '/maxelem/ {for(i=1;i<=NF;i++) if($i=="maxelem") print $(i+1)}')
if [[ -n "$CURRENT_MAXELEM" ]] && [[ "$CURRENT_MAXELEM" -lt 1048576 ]]; then
    echo "$LOG_TAG maxelem attuale ($CURRENT_MAXELEM) insufficiente, ricreo il set..."
    iptables -D INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null || true
    ipset destroy "$SET"
    ipset create "$SET" hash:net family inet maxelem 1048576
    iptables -I INPUT 1 -m set --match-set "$SET" src -j DROP
    iptables-save > /etc/iptables/rules.v4
    echo "$LOG_TAG Set ricreato con maxelem 1048576."
fi

# Set temporaneo: distruggi e ricrea sempre pulito
ipset destroy "$TMPSET" 2>/dev/null || true
ipset create "$TMPSET" hash:net family inet maxelem 1048576

COUNT=$(python3 /usr/local/bin/asn-to-ipset.py "$TMPSET" "$MMDB" "${ASNS[@]}")

echo "$LOG_TAG Prefissi trovati: $COUNT"

if [[ -z "$COUNT" ]] || [[ "$COUNT" -eq 0 ]]; then
    echo "$LOG_TAG ATTENZIONE: nessun prefisso trovato, aggiornamento annullato" >&2
    ipset destroy "$TMPSET"
    exit 1
fi

ipset swap "$TMPSET" "$SET"
ipset destroy "$TMPSET"
ipset save > "$IPSET_SAVE_FILE"

echo "$LOG_TAG Aggiornamento completato"
