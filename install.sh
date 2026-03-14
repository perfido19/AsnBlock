#!/usr/bin/env bash
# =============================================================
# install.sh — ASN Block Installer
# One-liner:
#   bash <(curl -fsSL https://raw.githubusercontent.com/perfido19/AsnBlock/master/install.sh)
# =============================================================
set -euo pipefail

REPO_URL="https://raw.githubusercontent.com/perfido19/AsnBlock/master"
MMDB="/usr/share/GeoIP/GeoLite2-ASN.mmdb"
INSTALL_DIR="/usr/local/bin"
ASN_FILE="/etc/asn-blocklist.txt"
IPSET_SAVE="/etc/ipset.conf"
IPSET_SET="blocked_asn"
IPSET_MAXELEM=1048576

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo ""
echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       ASN Block Installer            ║${NC}"
echo -e "${BLUE}║  ipset + iptables + MaxMind GeoIP    ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

# Root check
[[ $EUID -ne 0 ]] && error "Eseguire come root"

# MaxMind check
[[ ! -f "$MMDB" ]] && error "Database MaxMind non trovato: $MMDB\nInstalla GeoLite2-ASN.mmdb prima di procedere."
ok "Database MaxMind trovato: $MMDB"

# Pacchetti
info "Installazione pacchetti..."
apt-get update -qq
apt-get install -y ipset iptables-persistent python3-pip curl
ok "Pacchetti installati"

# Python maxminddb
if ! python3 -c "import maxminddb" 2>/dev/null; then
    info "Installo libreria Python maxminddb..."
    pip3 install maxminddb
fi
ok "Libreria maxminddb disponibile"

# Download file dal repo
info "Download file dal repository..."
curl -fsSL "$REPO_URL/asn-to-ipset.py"        -o "$INSTALL_DIR/asn-to-ipset.py"
curl -fsSL "$REPO_URL/update-asn-block.sh"     -o "$INSTALL_DIR/update-asn-block.sh"
curl -fsSL "$REPO_URL/ipset-restore.service"   -o "/etc/systemd/system/ipset-restore.service"
chmod +x "$INSTALL_DIR/asn-to-ipset.py"
chmod +x "$INSTALL_DIR/update-asn-block.sh"
ok "Script installati in $INSTALL_DIR"

# ASN list: scarica solo se non esiste già (preserva personalizzazioni)
if [[ ! -f "$ASN_FILE" ]]; then
    info "Download lista ASN..."
    curl -fsSL "$REPO_URL/asn-blocklist.txt" -o "$ASN_FILE"
    ok "Lista ASN scaricata: $ASN_FILE"
else
    warn "Lista ASN già presente ($ASN_FILE) — mantenuta senza sovrascrivere"
fi

# ipset
info "Creo set ipset $IPSET_SET..."
ipset create "$IPSET_SET" hash:net family inet maxelem "$IPSET_MAXELEM" -exist
CURRENT_MAXELEM=$(ipset list "$IPSET_SET" | awk '/maxelem/ {for(i=1;i<=NF;i++) if($i=="maxelem") print $(i+1)}')
if [[ -n "$CURRENT_MAXELEM" ]] && [[ "$CURRENT_MAXELEM" -lt "$IPSET_MAXELEM" ]]; then
    warn "maxelem insufficiente ($CURRENT_MAXELEM), ricreo il set..."
    iptables -D INPUT -m set --match-set "$IPSET_SET" src -j DROP 2>/dev/null || true
    ipset destroy "$IPSET_SET"
    ipset create "$IPSET_SET" hash:net family inet maxelem "$IPSET_MAXELEM"
fi
ok "Set ipset pronto (maxelem=$IPSET_MAXELEM)"

# iptables
info "Configuro regola iptables in posizione 1..."
iptables -D INPUT -m set --match-set "$IPSET_SET" src -j DROP 2>/dev/null || true
iptables -I INPUT 1 -m set --match-set "$IPSET_SET" src -j DROP
iptables-save > /etc/iptables/rules.v4
ok "Regola iptables configurata in posizione 1"

# systemd
info "Abilito ipset-restore.service..."
systemctl daemon-reload
systemctl enable ipset-restore.service
systemctl start ipset-restore.service
ok "Servizio ipset-restore abilitato"

# Primo aggiornamento
info "Primo aggiornamento (può richiedere ~10 secondi)..."
"$INSTALL_DIR/update-asn-block.sh"

# Cron
info "Configuro cron ogni 6 ore..."
( crontab -l 2>/dev/null | grep -v 'update-asn-block'; \
  echo "0 */6 * * * nice -n 19 ionice -c 3 $INSTALL_DIR/update-asn-block.sh >> /var/log/update-asn-block.log 2>&1" \
) | crontab -
ok "Cron configurato (ogni 6 ore, priorità minima)"

# Verifica finale
echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLAZIONE COMPLETATA ✅      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
PREFISSI=$(ipset list "$IPSET_SET" | grep -c '/' || true)
echo -e "  Prefissi bloccati:  ${GREEN}$PREFISSI${NC}"
echo -e "  Regola iptables:"
iptables -L INPUT -n --line-numbers | head -4 | sed 's/^/    /'
echo ""
echo -e "  ${BLUE}Comandi utili:${NC}"
echo "    Aggiornamento manuale:  $INSTALL_DIR/update-asn-block.sh"
echo "    Testa un IP:            ipset test $IPSET_SET 1.2.3.4"
echo "    Aggiungi ASN:           nano $ASN_FILE"
echo "    Log cron:               tail -f /var/log/update-asn-block.log"
echo ""
