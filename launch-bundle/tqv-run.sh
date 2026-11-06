#!/bin/bash
# TQV inner runner. Sessions are sequential; every session appends
# START/rc/END/summary/BUMP lines to tqv-result.txt. Arm failures are
# recorded, never abort the matrix (only setup/stop conditions stop it).
# Env (set by tqv-launch.sh): BIN LOGD MIST_KEY TQV_SRV_PID TQV_OBJ_PID
#   TQV_SRV6_PID TQV_OBJ6_PID (v6 services, started lazily by this runner)
#   TAG (build tag, recorded in the result header)
BIN=/root/pilot/bin
LOGD=/root/pilot/logs
PCAPD=/root/pilot/pcaps
RES=$LOGD/tqv-result.txt
ATT=$LOGD/tqv-attempts.txt
[ -f "$ATT" ] || echo 0 > "$ATT"
: > $RES
echo "TQV_RUN_TAG=$TAG" >> $RES
echo "VPAGE0_DEFERRED (page first-byte hook missing in this tree; F proxy p99=2.05s used as L_tail input; see PRECHECK 3)" >> $RES
echo "BH_V3_DEFERRED (no wiring1/clear-DF variant binary in this tree; see PRECHECK)" >> $RES
echo "MECH_DEFERRED (decoy/D11/rot: no labserver/labclient entry points in this tree; see PRECHECK)" >> $RES
echo "SPL_DEFERRED (SplitClient not wired into labclient; see PRECHECK)" >> $RES

stop_matrix() { # $1=reason: stop starting new sessions, finalize, exit 0
  echo "STOP_$1 $(date +%s)" >> $RES
  finalize
  exit 0
}
finalize() {
  echo "--- stop tcpdump ---" >> $RES
  [ -n "$TCPD_PID" ] && kill -TERM "$TCPD_PID" 2>/dev/null
  for i in $(seq 1 5); do sleep 1; [ -n "$TCPD_PID" ] && kill -0 "$TCPD_PID" 2>/dev/null || break; done
  echo "--- shutdown services by recorded PID ---" >> $RES
  [ -n "$TQV_SRV_PID" ] && kill -TERM "$TQV_SRV_PID" 2>/dev/null
  [ -n "$TQV_OBJ_PID" ] && kill -TERM "$TQV_OBJ_PID" 2>/dev/null
  [ -n "$TQV_SRV6_PID" ] && kill -TERM "$TQV_SRV6_PID" 2>/dev/null
  [ -n "$TQV_OBJ6_PID" ] && kill -TERM "$TQV_OBJ6_PID" 2>/dev/null
  for i in $(seq 1 10); do sleep 1; kill -0 "$TQV_SRV_PID" 2>/dev/null || kill -0 "$TQV_OBJ_PID" 2>/dev/null || break; done
  echo "--- cleanup ---" >> $RES
  ip netns exec client-ns tc qdisc del dev veth-c root 2>/dev/null; ip netns exec server-ns tc qdisc del dev veth-s root 2>/dev/null
  ip netns exec client-ns6 tc qdisc del dev veth-c6 root 2>/dev/null; ip netns exec server-ns6 tc qdisc del dev veth-s6 root 2>/dev/null
  ip netns del client-ns 2>/dev/null; ip netns del server-ns 2>/dev/null
  ip netns del client-ns6 2>/dev/null; ip netns del server-ns6 2>/dev/null
  ip netns list >> $RES 2>&1
  [ -z "$(pgrep -x labserver; pgrep -x labclient; pgrep -x labobject)" ] && echo "NO_LAB_PROCS_AFTER" >> $RES || echo "LAB_PROCS_REMAIN" >> $RES
  ps -eo pid,args | grep -E 'mist-server|xray|hysteria|nginx|tcpdump' | grep -v grep | awk '{print $1}' | sort -n > $LOGD/tqv-prod-after.txt
  diff $LOGD/tqv-prod-before.txt $LOGD/tqv-prod-after.txt >> $RES 2>&1 && echo "PROD_UNCHANGED" >> $RES || echo "PROD_DIFF_ABOVE" >> $RES
  python3 $LOGD/tqv-bundle/tqv-analyze.py --final >> $RES 2>&1
  echo "TQV_DONE" >> $RES
}
bump_attempts() {
  local n
  n=$(cat "$ATT")
  n=$((n + 1))
  echo "$n" > "$ATT"
  [ "$n" -gt 280 ] && stop_matrix ATTEMPTS_EXCEEDED
  echo "$n"
}
prod_check() { # $1=label: fail-stop on production PID drift
  ps -eo pid,args | grep -E 'mist-server|xray|hysteria|nginx|tcpdump' | grep -v grep | awk '{print $1}' | sort -n > /tmp/tqv-prod-now.txt
  diff -q $LOGD/tqv-prod-before.txt /tmp/tqv-prod-now.txt > /dev/null 2>&1 || stop_matrix PROD_DIFF_$1
}
ceiling_check() { # before each SIZE session: total SIZE pcap bytes vs soft/hard stops
  local tot=0
  tot=$(stat -c%s $LOGD/tqv-size-*.pcap 2>/dev/null | awk 'BEGIN{s=0}{s+=$1}END{print s}')
  [ "$tot" -gt 800000000 ] && stop_matrix CEILING_HARD
  [ "$tot" -gt 700000000 ] && stop_matrix CEILING_SOFT
}
parse_out() { # $1=outfile: print summary json or PARSE_FAIL
  python3 - "$1" 2>&1 <<'PYEOF'
import sys, json
txt = open(sys.argv[1], errors='replace').read()
data = None
try:
    data = json.loads(txt)
except Exception:
    for line in reversed(txt.splitlines()):
        line = line.strip()
        if line.startswith('{'):
            try:
                data = json.loads(line); break
            except Exception:
                continue
if data is None:
    print('PARSE_FAIL tail=' + txt[-300:])
else:
    print('summary=' + json.dumps(data, sort_keys=True))
PYEOF
}
set_netem() { # $1=delay_ms $2=loss_pct: BOTH ends (V7 convention; RTT ~= 2x delay,
  local dly="$1" loss="$2"
  ip netns exec client-ns tc qdisc del dev veth-c root 2>/dev/null
  ip netns exec server-ns tc qdisc del dev veth-s root 2>/dev/null
  ip netns exec client-ns tc qdisc add dev veth-c root netem delay ${dly}ms 5ms distribution normal loss ${loss}%
  ip netns exec server-ns tc qdisc add dev veth-s root netem delay ${dly}ms 5ms distribution normal loss ${loss}%
  echo "NETEM delay=${dly}ms loss=${loss}%" >> $RES
}
set_netem6() { # $1=delay_ms $2=loss_pct: v6 pair, same convention
  local dly="$1" loss="$2"
  ip netns exec client-ns6 tc qdisc del dev veth-c6 root 2>/dev/null
  ip netns exec server-ns6 tc qdisc del dev veth-s6 root 2>/dev/null
  ip netns exec client-ns6 tc qdisc add dev veth-c6 root netem delay ${dly}ms 5ms distribution normal loss ${loss}%
  ip netns exec server-ns6 tc qdisc add dev veth-s6 root netem delay ${dly}ms 5ms distribution normal loss ${loss}%
  echo "NETEM6 delay=${dly}ms loss=${loss}%" >> $RES
}
run_a() { # $1=name $2=page $3=class $4=T $5=maxr $6=stall(on/off) $7=fb(on/off) $8=page_timeout(0=follow)
  local name="$1" page="$2" class="$3" T="$4" maxr="$5" stall="$6" fb="$7" pt="$8"
  local out=$LOGD/tqv-$name.out
  bump_attempts > /dev/null
  echo "START $name page=$page class=$class T=$T stall=$stall page_timeout=$pt $(date +%s)" >> $RES
  local args="-server 10.200.1.2:24443 -object 10.200.1.2:18080 -class $class -page $page -id tqv-$name -qlog $LOGD/tqv-$name.sqlog -events-out $LOGD/tqv-$name-events.json"
  [ "$stall" = "on" ] && args="$args -stall-recover -stall-timeout ${T}s -stall-max-reconnects $maxr"
  [ "$stall" = "on" ] && [ "$pt" != "0" ] && args="$args -stall-page-timeout ${pt}s"
  [ "$fb" = "on" ] && args="$args -firstbyte-out $LOGD/tqv-$name-firstbyte.json"
  timeout 300 ip netns exec client-ns env MIST_KEY="$MIST_KEY" $BIN/labclient-tqv $args > "$out" 2>&1
  local rc=$?
  echo "$name rc=$rc END $(date +%s)" >> $RES
  parse_out "$out" >> $RES
  grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true
  if [ "$fb" = "on" ] && [ -f $LOGD/tqv-$name-firstbyte.json ]; then
    python3 -c "import json; print('FIRSTBYTE $name n=' + str(len(json.load(open('$LOGD/tqv-$name-firstbyte.json')))))" >> $RES 2>&1 || echo "FIRSTBYTE $name PARSE_FAIL" >> $RES
  fi
  return $rc
}
run_direct() { # $1=name $2=page $3=class: direct arm (6s silence between sessions is the caller's job)
  local name="$1" page="$2" class="$3"
  local out=$LOGD/tqv-$name.out
  bump_attempts > /dev/null
  echo "START $name page=$page class=$class direct $(date +%s)" >> $RES
  timeout 300 ip netns exec client-ns $BIN/labclient-tqv -direct -object 10.200.1.2:18080 -class $class -page $page -id tqv-$name > "$out" 2>&1
  local rc=$?
  echo "$name rc=$rc END $(date +%s)" >> $RES
  parse_out "$out" >> $RES
  return $rc
}
wait_traffic() { # $1=sqlog $2=session_pid $3=min_bytes $4=max_wait_s
  local sqlog="$1" pid="$2" minb="$3" maxw="$4" waited=0
  while [ $waited -lt $((maxw * 2)) ]; do
    kill -0 "$pid" 2>/dev/null || return 2
    local sz=0
    [ -f "$sqlog" ] && sz=$(stat -c%s "$sqlog" 2>/dev/null || echo 0)
    [ "$sz" -ge "$minb" ] && { echo "TRAFFIC_TRIGGER size=$sz waited=${waited}"; return 0; }
    sleep 0.5
    waited=$((waited + 1))
  done
  return 1
}
wait_bump() { # $1=outfile $2=want_count $3=timeout_s: poll for object-phase bump lines
  local out="$1" want="$2" tmo="$3" waited=0
  while [ $waited -lt $((tmo * 2)) ]; do
    local n=$(grep -c 'objects in flight restart' "$out" 2>/dev/null || echo 0)
    [ "$n" -ge "$want" ] && return 0
    sleep 0.5
    waited=$((waited + 1))
  done
  return 1
}

run_a_contract() { # $1=name $2=page $3=T $4=maxr: dual-end 1500->1280 on traffic gate, restore after
  local name="$1" page="$2" T="$3" maxr="$4"
  local out=$LOGD/tqv-$name.out
  bump_attempts > /dev/null
  echo "START $name page=$page T=$T contract=1280 $(date +%s)" >> $RES
  timeout 300 ip netns exec client-ns env MIST_KEY="$MIST_KEY" $BIN/labclient-tqv -server 10.200.1.2:24443 -object 10.200.1.2:18080 -class A -page $page -id tqv-$name -qlog $LOGD/tqv-$name.sqlog -events-out $LOGD/tqv-$name-events.json -stall-recover -stall-timeout ${T}s -stall-max-reconnects $maxr -firstbyte-out $LOGD/tqv-$name-firstbyte.json > "$out" 2>&1 &
  local pid=$!
  local trig
  trig=$(wait_traffic $LOGD/tqv-$name.sqlog $pid 20000 25) && echo "TRAFFIC $name $trig $(date +%s)" >> $RES || echo "TRAFFIC_WAIT $name rc=$? (contracting anyway unless session exited)" >> $RES
  kill -0 $pid 2>/dev/null || { echo "EARLY_EXIT $name (session ended before contraction)" >> $RES; wait $pid; echo "$name rc=$? END $(date +%s)" >> $RES; parse_out "$out" >> $RES; grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true; ip netns exec client-ns ip link set veth-c mtu 1500 2>/dev/null; ip netns exec server-ns ip link set veth-s mtu 1500 2>/dev/null; return; }
  ip netns exec client-ns ip link set veth-c mtu 1280
  ip netns exec server-ns ip link set veth-s mtu 1280
  echo "CONTRACT $name -> 1280 $(date +%s)" >> $RES
  wait $pid
  echo "$name rc=$? END $(date +%s)" >> $RES
  parse_out "$out" >> $RES
  grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true
  ip netns exec client-ns ip link set veth-c mtu 1500 2>/dev/null
  ip netns exec server-ns ip link set veth-s mtu 1500 2>/dev/null
  echo "RESTORED $name -> 1500" >> $RES
}
run_a_contract_single() { # $1=name $2=T $3=end(srv|cli): single-end 1500->1280
  local name="$1" T="$2" end="$3"
  local out=$LOGD/tqv-$name.out
  bump_attempts > /dev/null
  echo "START $name T=$T contract-single=$end $(date +%s)" >> $RES
  timeout 300 ip netns exec client-ns env MIST_KEY="$MIST_KEY" $BIN/labclient-tqv -server 10.200.1.2:24443 -object 10.200.1.2:18080 -class A -page a -id tqv-$name -qlog $LOGD/tqv-$name.sqlog -events-out $LOGD/tqv-$name-events.json -stall-recover -stall-timeout ${T}s -stall-max-reconnects 3 -firstbyte-out $LOGD/tqv-$name-firstbyte.json > "$out" 2>&1 &
  local pid=$!
  local trig
  trig=$(wait_traffic $LOGD/tqv-$name.sqlog $pid 20000 25) && echo "TRAFFIC $name $trig $(date +%s)" >> $RES || echo "TRAFFIC_WAIT $name rc=$?" >> $RES
  kill -0 $pid 2>/dev/null || { echo "EARLY_EXIT $name" >> $RES; wait $pid; echo "$name rc=$? END $(date +%s)" >> $RES; parse_out "$out" >> $RES; grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true; ip netns exec client-ns ip link set veth-c mtu 1500 2>/dev/null; ip netns exec server-ns ip link set veth-s mtu 1500 2>/dev/null; return; }
  if [ "$end" = "srv" ]; then ip netns exec server-ns ip link set veth-s mtu 1280; else ip netns exec client-ns ip link set veth-c mtu 1280; fi
  echo "CONTRACT $name single=$end -> 1280 $(date +%s)" >> $RES
  wait $pid
  echo "$name rc=$? END $(date +%s)" >> $RES
  parse_out "$out" >> $RES
  grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true
  ip netns exec client-ns ip link set veth-c mtu 1500 2>/dev/null
  ip netns exec server-ns ip link set veth-s mtu 1500 2>/dev/null
  echo "RESTORED $name -> 1500" >> $RES
}
run_a_shrink_at() { # $1=name $2=page-delay $3=T_page $4=wait_after_traffic_s (or FIXED:n)
  # V-page-2: traffic gate then sleep N (approx "page success + Ns": the sqlog
  # gate fires once object traffic flows, i.e. after page success).
  # V-page-7: FIXED:1 shrinks 1s after session start (inside the 2s page delay).
  local name="$1" delay="$2" tpage="$3" mode="$4"
  local out=$LOGD/tqv-$name.out
  bump_attempts > /dev/null
  echo "START $name page-delay=${delay}s T_page=${tpage}s shrink=$mode $(date +%s)" >> $RES
  timeout 300 ip netns exec client-ns env MIST_KEY="$MIST_KEY" $BIN/labclient-tqv -server 10.200.1.2:24443 -object 10.200.1.2:18080 -class A -page a -id tqv-$name -qlog $LOGD/tqv-$name.sqlog -events-out $LOGD/tqv-$name-events.json -stall-recover -stall-timeout 8s -stall-page-timeout ${tpage}s -stall-max-reconnects 3 -firstbyte-out $LOGD/tqv-$name-firstbyte.json > "$out" 2>&1 &
  local pid=$!
  case "$mode" in
    FIXED:*)
      sleep "${mode#FIXED:}"
      ;;
    *)
      local trig
      trig=$(wait_traffic $LOGD/tqv-$name.sqlog $pid 20000 25) && echo "TRAFFIC $name $trig $(date +%s)" >> $RES || echo "TRAFFIC_WAIT $name rc=$?" >> $RES
      kill -0 $pid 2>/dev/null || { echo "EARLY_EXIT $name" >> $RES; wait $pid; echo "$name rc=$? END $(date +%s)" >> $RES; parse_out "$out" >> $RES; grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true; return; }
      sleep "$mode"
      ;;
  esac
  kill -0 $pid 2>/dev/null || { echo "EARLY_EXIT $name (before shrink)" >> $RES; wait $pid; echo "$name rc=$? END $(date +%s)" >> $RES; parse_out "$out" >> $RES; grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true; ip netns exec client-ns ip link set veth-c mtu 1500 2>/dev/null; ip netns exec server-ns ip link set veth-s mtu 1500 2>/dev/null; return; }
  ip netns exec client-ns ip link set veth-c mtu 1280
  ip netns exec server-ns ip link set veth-s mtu 1280
  echo "CONTRACT $name -> 1280 $(date +%s)" >> $RES
  wait $pid
  echo "$name rc=$? END $(date +%s)" >> $RES
  parse_out "$out" >> $RES
  grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true
  ip netns exec client-ns ip link set veth-c mtu 1500 2>/dev/null
  ip netns exec server-ns ip link set veth-s mtu 1500 2>/dev/null
  echo "RESTORED $name -> 1500" >> $RES
}
run_a_c() { # $1=name $2=T: C arm, restore 1500 during each backoff, re-contract after 6s
  local name="$1" T="$2"
  local out=$LOGD/tqv-$name.out
  bump_attempts > /dev/null
  echo "START $name page=a T=$T cap-arm $(date +%s)" >> $RES
  timeout 300 ip netns exec client-ns env MIST_KEY="$MIST_KEY" $BIN/labclient-tqv -server 10.200.1.2:24443 -object 10.200.1.2:18080 -class A -page a -id tqv-$name -qlog $LOGD/tqv-$name.sqlog -events-out $LOGD/tqv-$name-events.json -stall-recover -stall-timeout ${T}s -stall-max-reconnects 3 -firstbyte-out $LOGD/tqv-$name-firstbyte.json > "$out" 2>&1 &
  local pid=$!
  local trig
  trig=$(wait_traffic $LOGD/tqv-$name.sqlog $pid 20000 25) && echo "TRAFFIC $name $trig $(date +%s)" >> $RES || echo "TRAFFIC_WAIT $name rc=$? (contracting anyway unless session exited)" >> $RES
  kill -0 $pid 2>/dev/null || { echo "EARLY_EXIT $name" >> $RES; wait $pid; echo "$name rc=$? END $(date +%s)" >> $RES; parse_out "$out" >> $RES; grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true; ip netns exec client-ns ip link set veth-c mtu 1500 2>/dev/null; ip netns exec server-ns ip link set veth-s mtu 1500 2>/dev/null; return; }
  ip netns exec client-ns ip link set veth-c mtu 1280
  ip netns exec server-ns ip link set veth-s mtu 1280
  echo "CONTRACT $name gen0 -> 1280 $(date +%s)" >> $RES
  local gen=0
  while [ $gen -lt 3 ]; do
    if wait_bump "$out" $((gen + 1)) $((T + 15)); then
      echo "BUMP_SEEN $name bump=$((gen + 1)) $(date +%s)" >> $RES
      ip netns exec client-ns ip link set veth-c mtu 1500
      ip netns exec server-ns ip link set veth-s mtu 1500
      echo "RESTORED $name -> 1500 (during backoff) $(date +%s)" >> $RES
      sleep 6
      grep -q '"done":true' $LOGD/tqv-$name.sqlog.gen$((gen + 1)) 2>/dev/null && echo "CONVERGED $name gen=$((gen + 1))" >> $RES || echo "CONVERGE_UNCONFIRMED $name gen=$((gen + 1)) (contracting anyway)" >> $RES
      ip netns exec client-ns ip link set veth-c mtu 1280
      ip netns exec server-ns ip link set veth-s mtu 1280
      echo "CONTRACT $name gen=$((gen + 1)) -> 1280 $(date +%s)" >> $RES
      gen=$((gen + 1))
    else
      echo "C_ARM_ANOMALY $name: bump $((gen + 1)) did not arrive" >> $RES
      break
    fi
  done
  wait $pid
  echo "$name rc=$? END $(date +%s)" >> $RES
  parse_out "$out" >> $RES
  grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true
  ip netns exec client-ns ip link set veth-c mtu 1500 2>/dev/null
  ip netns exec server-ns ip link set veth-s mtu 1500 2>/dev/null
  echo "RESTORED $name -> 1500" >> $RES
}
restart_object() { # $1=page-delay seconds (0 = no delay): restart labobject only
  local delay="$1"
  kill -TERM "$TQV_OBJ_PID" 2>/dev/null
  for i in $(seq 1 10); do sleep 1; kill -0 "$TQV_OBJ_PID" 2>/dev/null || break; done
  kill -0 "$TQV_OBJ_PID" 2>/dev/null && { echo "OBJECT_RESTART_FAIL" >> $RES; return 1; }
  ip netns exec server-ns bash -c 'echo $$ > /root/pilot/logs/tqv-object.pid; exec /root/pilot/bin/labobject-tqv -listen "10.200.1.2:18080" -page-delay '"${delay}s" > $LOGD/tqv-object.log 2>&1 &
  sleep 1
  TQV_OBJ_PID=$(cat $LOGD/tqv-object.pid)
  kill -0 "$TQV_OBJ_PID" 2>/dev/null || { echo "OBJECT_DEAD_AFTER_RESTART delay=$delay" >> $RES; return 1; }
  timeout 3 ip netns exec server-ns bash -c 'cat < /dev/null > /dev/tcp/10.200.1.2/18080' 2>/dev/null && echo "OBJ_UP delay=${delay}s pid=$TQV_OBJ_PID" >> $RES || echo "OBJ_TCP_CHECK_FAIL delay=$delay" >> $RES
  return 0
}

start_v6() { # build v6 domain + start v6 labobject/labserver (only for BH-V6 / SIZE-v6)
  ip netns add client-ns6 2>/dev/null; ip netns add server-ns6 2>/dev/null
  ip link add veth-c6 type veth peer name veth-s6 2>/dev/null
  ip link set veth-c6 netns client-ns6 2>/dev/null
  ip link set veth-s6 netns server-ns6 2>/dev/null
  ip netns exec client-ns6 ip addr add fd00:200:1::1/64 dev veth-c6 2>/dev/null
  ip netns exec server-ns6 ip addr add fd00:200:1::2/64 dev veth-s6 2>/dev/null
  ip netns exec client-ns6 ip link set lo up
  ip netns exec server-ns6 ip link set lo up
  ip netns exec client-ns6 ip link set veth-c6 up
  ip netns exec server-ns6 ip link set veth-s6 up
  ip netns exec server-ns6 bash -c 'echo $$ > /root/pilot/logs/tqv-object6.pid; exec /root/pilot/bin/labobject-tqv -listen "[fd00:200:1::2]:18080"' > $LOGD/tqv-object6.log 2>&1 &
  sleep 1
  ip netns exec server-ns6 env MIST_KEY="$MIST_KEY" bash -c 'echo $$ > /root/pilot/logs/tqv-server6.pid; exec /root/pilot/bin/labserver-tqv -listen "[fd00:200:1::2]:24443" -qlog-dir /root/pilot/logs/tqv-qlog6 -events-out /root/pilot/logs/tqv-server6-events.json -pmtu-out /root/pilot/logs/tqv-server6-pmtu.json' > $LOGD/tqv-server6.log 2>&1 &
  sleep 2
  TQV_SRV6_PID=$(cat $LOGD/tqv-server6.pid); TQV_OBJ6_PID=$(cat $LOGD/tqv-object6.pid)
  kill -0 "$TQV_SRV6_PID" 2>/dev/null || { echo "V6_SERVER_DEAD"; return 1; }
  kill -0 "$TQV_OBJ6_PID" 2>/dev/null || { echo "V6_OBJECT_DEAD"; return 1; }
  echo "V6_UP server_pid=$TQV_SRV6_PID object_pid=$TQV_OBJ6_PID" >> $RES
  return 0
}
stop_v6() {
  [ -n "$TQV_SRV6_PID" ] && kill -TERM "$TQV_SRV6_PID" 2>/dev/null
  [ -n "$TQV_OBJ6_PID" ] && kill -TERM "$TQV_OBJ6_PID" 2>/dev/null
  sleep 1
  ip netns del client-ns6 2>/dev/null; ip netns del server-ns6 2>/dev/null
  echo "V6_DOWN" >> $RES
}
run_a6() { # $1=name $2=T $3=contract(off|on) $4=stall(on/off): v6 Mist class A session
  local name="$1" T="$2" contract="$3" stall="$4"
  local out=$LOGD/tqv-$name.out
  bump_attempts > /dev/null
  echo "START $name v6 T=$T contract=$contract stall=$stall $(date +%s)" >> $RES
  local args="-server [fd00:200:1::2]:24443 -object [fd00:200:1::2]:18080 -class A -page a -id tqv-$name -qlog $LOGD/tqv-$name.sqlog -events-out $LOGD/tqv-$name-events.json -firstbyte-out $LOGD/tqv-$name-firstbyte.json"
  [ "$stall" = "on" ] && args="$args -stall-recover -stall-timeout ${T}s -stall-max-reconnects 3"
  timeout 300 ip netns exec client-ns6 env MIST_KEY="$MIST_KEY" $BIN/labclient-tqv $args > "$out" 2>&1 &
  local pid=$!
  if [ "$contract" = "on" ]; then
    local trig
    trig=$(wait_traffic $LOGD/tqv-$name.sqlog $pid 20000 25) && echo "TRAFFIC $name $trig $(date +%s)" >> $RES || echo "TRAFFIC_WAIT $name rc=$?" >> $RES
    kill -0 $pid 2>/dev/null || { echo "EARLY_EXIT $name" >> $RES; wait $pid; echo "$name rc=$? END $(date +%s)" >> $RES; parse_out "$out" >> $RES; grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true; ip netns exec client-ns6 ip link set veth-c6 mtu 1500 2>/dev/null; ip netns exec server-ns6 ip link set veth-s6 mtu 1500 2>/dev/null; return; }
    ip netns exec client-ns6 ip link set veth-c6 mtu 1280
    ip netns exec server-ns6 ip link set veth-s6 mtu 1280
    echo "CONTRACT $name v6 -> 1280 $(date +%s)" >> $RES
  fi
  wait $pid
  echo "$name rc=$? END $(date +%s)" >> $RES
  parse_out "$out" >> $RES
  grep -E 'stall gen=' "$out" | sed "s/^/BUMP $name: /" >> $RES 2>&1 || true
  ip netns exec client-ns6 ip link set veth-c6 mtu 1500 2>/dev/null
  ip netns exec server-ns6 ip link set veth-s6 mtu 1500 2>/dev/null
  [ "$contract" = "on" ] && echo "RESTORED $name v6 -> 1500" >> $RES
}
run_direct6() { # $1=name: v6 direct class A session
  local name="$1"
  local out=$LOGD/tqv-$name.out
  bump_attempts > /dev/null
  echo "START $name v6 direct $(date +%s)" >> $RES
  timeout 300 ip netns exec client-ns6 $BIN/labclient-tqv -direct -object '[fd00:200:1::2]:18080' -class A -page a -id tqv-$name > "$out" 2>&1
  local rc=$?
  echo "$name rc=$rc END $(date +%s)" >> $RES
  parse_out "$out" >> $RES
  return $rc
}
cap_start() { # $1=pcap file $2=filter: start tcpdump on veth-c (or veth-c6 for v6)
  local pcap="$1" filt="$2" ns="${3:-client-ns}" dev="${4:-veth-c}"
  ip netns exec "$ns" bash -c 'echo $$ > /root/pilot/logs/tqv-tcpdump.pid; exec tcpdump -i '"$dev"' -s 160 -w '"$pcap"' "'"$filt"'"' > $LOGD/tqv-tcpdump.log 2>&1 &
  sleep 1
  TCPD_PID=$(cat $LOGD/tqv-tcpdump.pid)
  kill -0 "$TCPD_PID" 2>/dev/null && echo "CAP_START $pcap pid=$TCPD_PID" >> $RES || { echo "CAP_START_FAIL $pcap" >> $RES; TCPD_PID=""; }
}
cap_stop() { # stop tcpdump, record pcap size
  [ -n "$TCPD_PID" ] && kill -TERM "$TCPD_PID" 2>/dev/null
  for i in $(seq 1 5); do sleep 1; [ -n "$TCPD_PID" ] && kill -0 "$TCPD_PID" 2>/dev/null || break; done
  TCPD_PID=""
  echo "CAP_STOP" >> $RES
  ls -la $LOGD/tqv-size-*.pcap $LOGD/tqv-*.pcap 2>/dev/null | awk '{print "PCAP_SIZE", $5, $9}' >> $RES
}
complete() { # $1=arm(mist|direct) $2=id $3=ok|fail $4=completions-file
  echo "$1 $2 $3" >> "$4"
}
seg_done() { # $1=seg number: ceiling + prod check at segment boundary
  echo "TQV_SEG$1_DONE attempts=$(cat $ATT) $(date +%s)" >> $RES
  ls -la $LOGD/tqv-size-*.pcap 2>/dev/null | awk 'BEGIN{s=0}{s+=$5} END {print "SIZE_PCAP_TOTAL_BYTES=" s}' >> $RES
  prod_check "seg$1"
}

# ================= SEG 1: Q-M1M2 (gate, 6) + Q-TA (7) =================
echo "=== SEG1 Q-M1M2 (gate) ===" >> $RES
set_netem 200 1
for i in 1 2 3; do
  run_a m1-connect-$i a A 8 3 off off 0
done
# M1 gate: all three must pass (down exact, profile_version>=1, no failure).
M1FAIL=$(python3 - "$RES" <<'PYEOF'
import sys, json, re
txt = open(sys.argv[1], errors='replace').read()
ok = 0
for line in txt.splitlines():
    if line.startswith('summary='):
        try: d = json.loads(line[8:])
        except Exception: continue
        if str(d.get('session_id','')).startswith('tqv-m1-connect-'):
            if not d.get('failure') and d.get('down_bytes')==1032192 and d.get('objects')==15 and int(d.get('profile_version',0) or 0)>=1:
                ok += 1
print(3 - ok)
PYEOF
)
[ "$M1FAIL" != "0" ] && { echo "M1_GATE_FAIL missing=$M1FAIL" >> $RES; stop_matrix M1_GATE; }
echo "M1_GATE_PASS" >> $RES
WRONGKEY="0000000000000000000000000000000000000000000000000000000000000000"
for i in 1 2 3; do
  bump_attempts > /dev/null
  out=$LOGD/tqv-m2-authfail-$i.out
  echo "START m2-authfail-$i wrong-key $(date +%s)" >> $RES
  timeout 120 ip netns exec client-ns env MIST_KEY="$WRONGKEY" $BIN/labclient-tqv -server 10.200.1.2:24443 -object 10.200.1.2:18080 -class A -page a -id tqv-m2-authfail-$i > "$out" 2>&1
  echo "m2-authfail-$i rc=$? END $(date +%s)" >> $RES
  parse_out "$out" >> $RES
done
echo "=== SEG1 Q-TA (7) ===" >> $RES
set_netem 200 1
run_a ta-core-1 full A 8 3 on on 0
set_netem 200 5
run_a ta-core-2 full A 8 3 on on 0
set_netem 200 1
run_a ta-core-3 tail A 8 3 on on 0
set_netem 200 5
run_a ta-core-4 tail A 8 3 on on 0
for i in 1 2 3; do
  run_a ta-confirm-$i tail A 8 3 on on 0
done
seg_done 1
# ================= SEG 2: V-page (12) =================
echo "=== SEG2 V-page ===" >> $RES
set_netem 200 1
restart_object 2 || { echo "VPAGE_SKIP_D2 (object restart failed)" >> $RES; }
run_a vpage-1-d2 a A 8 3 on on 8
restart_object 4 || { echo "VPAGE_SKIP_D4 (object restart failed)" >> $RES; }
run_a vpage-1-d4 a A 8 3 on on 8
restart_object 8 || { echo "VPAGE2_SKIP (object restart failed)" >> $RES; }
run_a_shrink_at vpage-2 8 12 10
restart_object 4 || true
run_a vpage-3-t5 a A 8 3 on on 5
run_a vpage-3-t8 a A 8 3 on on 8
restart_object 12 || true
run_a vpage-4 a A 8 3 on on 8
restart_object 2 || true
for i in 1 2 3; do
  run_a vpage-5-n$i a A 8 3 on on 3
done
set_netem 200 5
run_a vpage-6-n1 tail A 8 3 on on 15
run_a vpage-6-n2 tail A 8 3 on on 15
set_netem 200 1
restart_object 2 || true
run_a_shrink_at vpage-7 2 8 FIXED:1
restart_object 0 || echo "VPAGE_RESTORE_FAIL" >> $RES
# V-page-2 key gate: page_bumps==0, obj bumps==1, reconnects==1, generations==2.
V2FAIL=$(python3 - "$RES" <<'PYEOF'
import sys, json
txt = open(sys.argv[1], errors='replace').read()
for line in txt.splitlines():
    if line.startswith('summary='):
        try: d = json.loads(line[8:])
        except Exception: continue
        if d.get('session_id') == 'tqv-vpage-2':
            ok = (int(d.get('stall_page_bumps', 0) or 0) == 0
                  and int(d.get('stall_reconnects', 0) or 0) == 1
                  and int(d.get('stall_generations', 0) or 0) == 2
                  and d.get('down_bytes') == 1032192 and not d.get('failure'))
            print(0 if ok else 1)
            sys.exit()
print(1)
PYEOF
)
[ "$V2FAIL" != "0" ] && { echo "VPAGE2_GATE_FAIL" >> $RES; stop_matrix VPAGE2_GATE; }
echo "VPAGE2_GATE_PASS" >> $RES
seg_done 2

# ================= SEG 3: BH (15) + SIZE-v6 (10) =================
echo "=== SEG3 BH ===" >> $RES
set_netem 20 0.1
for i in 1 2 3 4 5; do
  run_a_contract bh-d-main-$i a 8 3
done
for i in 1 2; do
  run_a_contract bh-d-lat-$i a 3 3
done
run_a_c bh-c-1 8
run_a_c bh-c-2 8
C1=$(python3 -c "
import json
txt = open('$RES', errors='replace').read()
ss = {}
for line in txt.splitlines():
    if line.startswith('summary='):
        try: d = json.loads(line[8:])
        except Exception: continue
        ss[d.get('session_id')] = d
a, b = ss.get('tqv-bh-c-1', {}), ss.get('tqv-bh-c-2', {})
ka = (a.get('stall_reconnects'), a.get('stall_generations'), bool(a.get('failure')))
kb = (b.get('stall_reconnects'), b.get('stall_generations'), bool(b.get('failure')))
print('SAME' if ka == kb else 'DIFF')
" 2>/dev/null)
echo "C_COMPARE_1_2=$C1" >> $RES
[ "$C1" = "DIFF" ] && run_a_c bh-c-3 8
run_a_contract bh-v1r a 8 3
run_a_contract_single bh-v5-srv 8 srv
run_a_contract_single bh-v5-cli 8 cli
start_v6 || { echo "V6_SETUP_FAIL (BH-V6 + SIZE-v6 skipped, recorded)" >> $RES; }
if kill -0 "$TQV_SRV6_PID" 2>/dev/null; then
  set_netem6 20 0.1
  run_a6 bh-v6 8 on on
  # --- SIZE-v6 (10): Mist A 5 + direct A 5, own pcaps ---
  cap_start $LOGD/tqv-size-mist-a-v6.pcap "(host fd00:200:1::1 and host fd00:200:1::2) and (udp port 24443 or tcp port 18080)" client-ns6 veth-c6
  : > $LOGD/tqv-completions-v6-mist.txt
  for i in 1 2 3 4 5; do
    run_a6 size-v6-mist-$i 8 off off
    complete mist size-v6-mist-$i ok $LOGD/tqv-completions-v6-mist.txt
  done
  cap_stop
  cap_start $LOGD/tqv-size-direct-a-v6.pcap "(host fd00:200:1::1 and host fd00:200:1::2) and (udp port 24443 or tcp port 18080)" client-ns6 veth-c6
  : > $LOGD/tqv-completions-v6-direct.txt
  for i in 1 2 3 4 5; do
    run_direct6 size-v6-direct-$i
    complete direct size-v6-direct-$i ok $LOGD/tqv-completions-v6-direct.txt
    sleep 6
  done
  cap_stop
  stop_v6
fi
seg_done 3
# ================= SEG 4: SIZE Mist A (50) =================
echo "=== SEG4 SIZE Mist A (50) ===" >> $RES
set_netem 200 1
: > $LOGD/tqv-completions-size-mist-a.txt
cap_start $LOGD/tqv-size-mist-a.pcap "(host 10.200.1.1 and host 10.200.1.2) and (udp port 24443 or tcp port 18080)"
for i in $(seq 1 50); do
  ceiling_check
  run_a size-mist-a-$i a A 8 3 off on 0
  complete mist size-mist-a-$i ok $LOGD/tqv-completions-size-mist-a.txt
done
cap_stop
python3 $LOGD/tqv-bundle/tqv-cluster-5s.py $LOGD/tqv-size-mist-a.pcap --class A --server 10.200.1.2 --client 10.200.1.1 --completions $LOGD/tqv-completions-size-mist-a.txt >> $RES 2>&1
echo "CLUSTER size-mist-a rc=$?" >> $RES
seg_done 4
# ================= SEG 5: SIZE Mist B (50) =================
echo "=== SEG5 SIZE Mist B (50) ===" >> $RES
: > $LOGD/tqv-completions-size-mist-b.txt
cap_start $LOGD/tqv-size-mist-b.pcap "(host 10.200.1.1 and host 10.200.1.2) and (udp port 24443 or tcp port 18080)"
for i in $(seq 1 50); do
  ceiling_check
  run_a size-mist-b-$i a B 8 3 off on 0
  complete mist size-mist-b-$i ok $LOGD/tqv-completions-size-mist-b.txt
done
cap_stop
python3 $LOGD/tqv-bundle/tqv-cluster-5s.py $LOGD/tqv-size-mist-b.pcap --class B --server 10.200.1.2 --client 10.200.1.1 --completions $LOGD/tqv-completions-size-mist-b.txt >> $RES 2>&1
echo "CLUSTER size-mist-b rc=$?" >> $RES
seg_done 5
# ================= SEG 6: SIZE direct A (50) =================
echo "=== SEG6 SIZE direct A (50) ===" >> $RES
: > $LOGD/tqv-completions-size-direct-a.txt
cap_start $LOGD/tqv-size-direct-a.pcap "(host 10.200.1.1 and host 10.200.1.2) and (udp port 24443 or tcp port 18080)"
for i in $(seq 1 50); do
  ceiling_check
  run_direct size-direct-a-$i a A
  complete direct size-direct-a-$i ok $LOGD/tqv-completions-size-direct-a.txt
  sleep 6
done
cap_stop
python3 $LOGD/tqv-bundle/tqv-cluster-5s.py $LOGD/tqv-size-direct-a.pcap --class A --server 10.200.1.2 --client 10.200.1.1 --completions $LOGD/tqv-completions-size-direct-a.txt >> $RES 2>&1
echo "CLUSTER size-direct-a rc=$?" >> $RES
seg_done 6
# ================= SEG 7: SIZE direct B (50) =================
echo "=== SEG7 SIZE direct B (50) ===" >> $RES
: > $LOGD/tqv-completions-size-direct-b.txt
cap_start $LOGD/tqv-size-direct-b.pcap "(host 10.200.1.1 and host 10.200.1.2) and (udp port 24443 or tcp port 18080)"
for i in $(seq 1 50); do
  ceiling_check
  run_direct size-direct-b-$i a B
  complete direct size-direct-b-$i ok $LOGD/tqv-completions-size-direct-b.txt
  sleep 6
done
cap_stop
python3 $LOGD/tqv-bundle/tqv-cluster-5s.py $LOGD/tqv-size-direct-b.pcap --class B --server 10.200.1.2 --client 10.200.1.1 --completions $LOGD/tqv-completions-size-direct-b.txt >> $RES 2>&1
echo "CLUSTER size-direct-b rc=$?" >> $RES
seg_done 7
# ================= finalize =================
# Merge per-arm completions for the record.
cat $LOGD/tqv-completions-size-*.txt $LOGD/tqv-completions-v6-*.txt 2>/dev/null > $LOGD/tqv-completions.txt
finalize
