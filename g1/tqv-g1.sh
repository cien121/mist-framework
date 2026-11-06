#!/bin/bash
# TQV G1: real H3 baseline collection (independent track, parallel with the lab
# matrix allowed, but MUST land before any SIZE fine-grained analysis).
# Basis: nextround/stage-a/h3-baseline-recollect-plan.md + design §2.
# Usage: bash tqv-g1.sh /path/to/frozen-site-list.txt
# The site list is FROZEN at dispatch (one full URL per line, no comments);
# this script carries NO default list and refuses to run without one.
# Frozen 2026-11-06 (chan nod, homepage + 2 inner pages per family):
#   cloudflare.com: www.cloudflare.com/ (+ /learning/, /products/)
#   github.com: github.com/ (+ /about, /features)
#   google.com: www.google.com/ (+ /advanced_search, /imghp)
# Inner pages were verified 200 and staying on-host before dispatch.
# Never touches Mist traffic or production domains; browser goes direct to the
# internet, no proxy. Never prints secrets, URLs with paths, cookies, or payload
# (log lines show hosts only; the frozen list file itself carries the URLs).
set -u
LOGD=/root/pilot/logs
G1D=/root/pilot/g1
SITE_LIST="${1:-}"
[ -n "$SITE_LIST" ] && [ -f "$SITE_LIST" ] || { echo "G1_NO_SITE_LIST (pass the frozen site-list file as \$1)"; exit 1; }
DATE=$(date +%Y%m%d)
OUTD="$G1D/h3-baseline-$DATE"
mkdir -p "$OUTD"
echo "=== g1: site list ==="
SITE_SHA=$(sha256sum "$SITE_LIST" | cut -d' ' -f1)
wc -l "$SITE_LIST"
while read -r url; do
  [ -z "$url" ] && continue
  host=${url#https://}; host=${host#http://}; host=${host%%/*}
  echo "site_host=$host"
done < "$SITE_LIST"
echo "site_list_sha=$SITE_SHA"
echo "=== g1: browser ==="
CHROME=$(which chromium chromium-browser google-chrome google-chrome-stable 2>/dev/null | head -1)
[ -n "$CHROME" ] || { echo "G1_NO_CHROME (no chromium binary on this host; G1 cannot run here)"; exit 1; }
"$CHROME" --version 2>&1
echo "=== g1: egress interface ==="
IFACE=$(ip route get 8.8.8.8 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
[ -n "$IFACE" ] || IFACE="any"
echo "iface=$IFACE"
echo "=== g1: resolve site IPs (filter set, recorded in manifest) ==="
IPS=""
while read -r url; do
  [ -z "$url" ] && continue
  host=${url#https://}; host=${host#http://}; host=${host%%/*}
  for ip in $(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u); do
    IPS="$IPS $ip"
  done
done < "$SITE_LIST"
IPS=$(echo "$IPS" | tr ' ' '\n' | sort -u | tr '\n' ' ')
echo "resolved_ips:$IPS"
[ -n "$(echo "$IPS" | tr -d ' ')" ] || { echo "G1_NO_IPS_RESOLVED"; exit 1; }
FILTER=""
for ip in $IPS; do
  [ -z "$FILTER" ] && FILTER="host $ip" || FILTER="$FILTER or host $ip"
done
echo "filter=$FILTER"
echo "=== g1: production / mist exclusion check ==="
echo "$FILTER" | grep -qE "148\.135|198112|8443" && { echo "G1_FILTER_TOUCHES_PROD"; exit 1; } || echo "FILTER_CLEAN"
START_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "start_utc=$START_TS"
echo "=== g1: capture A-type (50 visits, 35s window each) ==="
tcpdump -i "$IFACE" -s 160 -w "$OUTD/g1-a.pcap" "($FILTER) and not port 22" > "$LOGD/g1-tcpdump-a.log" 2>&1 &
TCPD_A=$!
sleep 1
kill -0 "$TCPD_A" 2>/dev/null || { echo "G1_TCPDUMP_A_DEAD"; exit 1; }
i=0
while read -r url; do
  [ -z "$url" ] && continue
  host=${url#https://}; host=${host#http://}; host=${host%%/*}
  i=$((i + 1))
  [ $i -gt 50 ] && break
  UD=$(mktemp -d /tmp/g1-ud-XXXXXX)
  timeout 40 "$CHROME" --headless=new --no-sandbox --disable-gpu --no-first-run --disable-extensions --no-default-browser-check --user-data-dir="$UD" "$url" > "$LOGD/g1-a-$i.log" 2>&1 &
  CPID=$!
  sleep 35
  kill -TERM "$CPID" 2>/dev/null
  sleep 1
  kill -KILL "$CPID" 2>/dev/null
  rm -rf "$UD"
  SZ=$(stat -c%s "$OUTD/g1-a.pcap" 2>/dev/null || echo 0)
  [ "$SZ" -gt 500000000 ] && { echo "G1_STOP_VOLUME a-pcap=$SZ"; kill -TERM "$TCPD_A" 2>/dev/null; exit 1; }
  echo "A visit $i done site=$host pcap_bytes=$SZ"
done < "$SITE_LIST"
# A-type needs 50 visits: cycle the list until 50 are done.
while [ $i -lt 50 ]; do
  while read -r url; do
    [ $i -ge 50 ] && break
    [ -z "$url" ] && continue
    host=${url#https://}; host=${host#http://}; host=${host%%/*}
    i=$((i + 1))
    UD=$(mktemp -d /tmp/g1-ud-XXXXXX)
    timeout 40 "$CHROME" --headless=new --no-sandbox --disable-gpu --no-first-run --disable-extensions --no-default-browser-check --user-data-dir="$UD" "$url" > "$LOGD/g1-a-$i.log" 2>&1 &
    CPID=$!
    sleep 35
    kill -TERM "$CPID" 2>/dev/null
    sleep 1
    kill -KILL "$CPID" 2>/dev/null
    rm -rf "$UD"
    SZ=$(stat -c%s "$OUTD/g1-a.pcap" 2>/dev/null || echo 0)
    [ "$SZ" -gt 500000000 ] && { echo "G1_STOP_VOLUME a-pcap=$SZ"; kill -TERM "$TCPD_A" 2>/dev/null; exit 1; }
    echo "A visit $i done site=$host pcap_bytes=$SZ"
  done < "$SITE_LIST"
done
kill -TERM "$TCPD_A" 2>/dev/null
sleep 2
echo "=== g1: capture B-type (50 visits, 120s window each) ==="
tcpdump -i "$IFACE" -s 160 -w "$OUTD/g1-b.pcap" "($FILTER) and not port 22" > "$LOGD/g1-tcpdump-b.log" 2>&1 &
TCPD_B=$!
sleep 1
kill -0 "$TCPD_B" 2>/dev/null || { echo "G1_TCPDUMP_B_DEAD"; exit 1; }
i=0
while [ $i -lt 50 ]; do
  while read -r url; do
    [ $i -ge 50 ] && break
    [ -z "$url" ] && continue
    host=${url#https://}; host=${host#http://}; host=${host%%/*}
    i=$((i + 1))
    UD=$(mktemp -d /tmp/g1-ud-XXXXXX)
    timeout 130 "$CHROME" --headless=new --no-sandbox --disable-gpu --no-first-run --disable-extensions --no-default-browser-check --user-data-dir="$UD" "$url" > "$LOGD/g1-b-$i.log" 2>&1 &
    CPID=$!
    sleep 120
    kill -TERM "$CPID" 2>/dev/null
    sleep 1
    kill -KILL "$CPID" 2>/dev/null
    rm -rf "$UD"
    SZ=$(stat -c%s "$OUTD/g1-b.pcap" 2>/dev/null || echo 0)
    [ "$SZ" -gt 500000000 ] && { echo "G1_STOP_VOLUME b-pcap=$SZ"; kill -TERM "$TCPD_B" 2>/dev/null; exit 1; }
    echo "B visit $i done site=$host pcap_bytes=$SZ"
  done < "$SITE_LIST"
done
kill -TERM "$TCPD_B" 2>/dev/null
sleep 2
END_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "end_utc=$END_TS"
echo "=== g1: manifest ==="
{
  echo "baseline_version=h3-baseline-$DATE"
  echo "start_utc=$START_TS"
  echo "end_utc=$END_TS"
  echo "site_list_sha=$SITE_SHA"
  echo "list_note=homepage + 2 inner pages per family, frozen 2026-11-06"
  echo "browser=$CHROME"
  echo "browser_version=$("$CHROME" --version 2>&1)"
  echo "browser_args=--headless=new --no-sandbox --disable-gpu --no-first-run --disable-extensions --no-default-browser-check"
  echo "filter=$FILTER"
  echo "snaplen=160"
  echo "scale_note=VPS egress, RTT 1.5-10ms machine-room scale; do NOT extrapolate to residential/mobile networks"
  echo "headless_note=headless Chrome; QUIC behavior may differ from headed, declared here"
  sha256sum "$OUTD/g1-a.pcap" "$OUTD/g1-b.pcap"
  ls -la "$OUTD"
} > "$OUTD/manifest.txt"
cat "$OUTD/manifest.txt"
echo "G1_DONE"
