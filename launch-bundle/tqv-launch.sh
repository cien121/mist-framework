#!/bin/bash
# TQV launch: true-QUIC validation matrix (design nextround/truequic-validation-design.md).
# Background runner; poll /root/pilot/logs/tqv-result.txt for TQV_DONE.
# Order: gate -> upload-verify -> build -> THIS launch (pre-checks new trio).
# Expects the launch bundle already extracted: /tmp/tqv-bundle.tar.gz decoded
# from chunks/launch-bundle.* and /tmp/tqv-bundle.sha holding its sha256.
# Never prints secrets: the lab key is generated here, only its length is
# echoed, and it travels to the runner via environment only.
set -u
BIN=/root/pilot/bin
LOGD=/root/pilot/logs
PCAPD=/root/pilot/pcaps
TAG="d09e7b95+tqv1"
ip netns del client-ns 2>/dev/null; ip netns del server-ns 2>/dev/null
ip netns del client-ns6 2>/dev/null; ip netns del server-ns6 2>/dev/null
sleep 1
echo "=== tqv pre-checks ==="
[ -z "$(pgrep -x labserver; pgrep -x labclient; pgrep -x labobject)" ] || { echo "LAB_PROCS_PRESENT"; exit 1; }
ip netns list | grep -E 'client-ns|server-ns' && { echo "NETNS_PRESENT"; exit 1; } || echo "NETNS_EMPTY"
[ -f $LOGD/tqv-trio-sha.txt ] || { echo "NO_TRIO_SHA_FILE"; exit 1; }
while read -r sha path; do
  [ "$(sha256sum $path | cut -d' ' -f1)" = "$sha" ] || { echo "MISMATCH $path"; exit 1; }
done < $LOGD/tqv-trio-sha.txt
echo "TRIO_TQV_OK"
$BIN/labclient-tqv -h 2>&1 | grep -q "firstbyte-out" || { echo "NO_FIRSTBYTE_FLAG"; exit 1; }
$BIN/labclient-tqv -h 2>&1 | grep -q "stall-recover" || { echo "NO_STALL_FLAG"; exit 1; }
$BIN/labclient-tqv -h 2>&1 | grep -q "stall-page-timeout" || { echo "NO_PAGE_TIMEOUT_FLAG"; exit 1; }
$BIN/labobject-tqv -h 2>&1 | grep -q "page-delay" || { echo "NO_PAGEDELAY_FLAG"; exit 1; }
echo "FLAGS_OK"
echo "=== tqv bundle ==="
[ -f /tmp/tqv-bundle.tar.gz ] || { echo "NO_BUNDLE_TARBALL"; exit 1; }
[ -f /tmp/tqv-bundle.sha ] || { echo "NO_BUNDLE_SHA_FILE"; exit 1; }
[ "$(sha256sum /tmp/tqv-bundle.tar.gz | cut -d' ' -f1)" = "$(cat /tmp/tqv-bundle.sha)" ] || { echo "BUNDLE_SHA_MISMATCH"; exit 1; }
rm -rf $LOGD/tqv-bundle
mkdir -p $LOGD/tqv-bundle
tar -xzf /tmp/tqv-bundle.tar.gz -C $LOGD/tqv-bundle || { echo "BUNDLE_EXTRACT_FAIL"; exit 1; }
[ -f $LOGD/tqv-bundle/tqv-analyze.py ] && [ -f $LOGD/tqv-bundle/tqv-run.sh ] && [ -f $LOGD/tqv-bundle/tqv-cluster-5s.py ] || { echo "BUNDLE_INCOMPLETE"; exit 1; }
python3 -m py_compile $LOGD/tqv-bundle/tqv-analyze.py $LOGD/tqv-bundle/tqv-cluster-5s.py || { echo "BUNDLE_PY_COMPILE_FAIL"; exit 1; }
bash -n $LOGD/tqv-bundle/tqv-run.sh || { echo "BUNDLE_RUNNER_SYNTAX_FAIL"; exit 1; }
chmod +x $LOGD/tqv-bundle/tqv-run.sh
echo "BUNDLE_OK"
echo "=== tqv prod baseline (fresh snapshot; stagec file is reference only) ==="
ps -eo pid,args | grep -E 'mist-server|xray|hysteria|nginx|tcpdump' | grep -v grep | awk '{print $1}' | sort -n > $LOGD/tqv-prod-before.txt
wc -l $LOGD/tqv-prod-before.txt
if [ -f $LOGD/stagec-prod-baseline.txt ]; then
  grep -oE '^[ ]*[0-9]+' $LOGD/stagec-prod-baseline.txt | tr -d ' ' | sort -n > $LOGD/tqv-prod-stagec.txt
  diff $LOGD/tqv-prod-stagec.txt $LOGD/tqv-prod-before.txt > /dev/null 2>&1 && echo "STAGEC_UNCHANGED" || echo "STAGEC_DRIFT (informational only; before/after diff is the gate)"
fi
echo "=== build v4 domain ==="
ip netns add client-ns || exit 1
ip netns add server-ns || exit 1
ip link add veth-c type veth peer name veth-s || exit 1
ip link set veth-c netns client-ns
ip link set veth-s netns server-ns
ip netns exec client-ns ip addr add 10.200.1.1/24 dev veth-c
ip netns exec server-ns ip addr add 10.200.1.2/24 dev veth-s
ip netns exec client-ns ip link set lo up
ip netns exec server-ns ip link set lo up
ip netns exec client-ns ip link set veth-c up
ip netns exec server-ns ip link set veth-s up
ip netns exec client-ns ip route | grep -q default && { echo "CLIENT_HAS_DEFAULT"; exit 1; } || echo "CLIENT_NO_DEFAULT_OK"
ip netns exec server-ns ip route | grep -q default && { echo "SERVER_HAS_DEFAULT"; exit 1; } || echo "SERVER_NO_DEFAULT_OK"
echo "DOMAIN_OK"
mkdir -p $LOGD/tqv-qlog $PCAPD
K=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
echo "keylen=${#K}"
rm -f $LOGD/tqv-server.pid $LOGD/tqv-object.pid $LOGD/tqv-tcpdump.pid
ip netns exec server-ns bash -c 'echo $$ > /root/pilot/logs/tqv-object.pid; exec /root/pilot/bin/labobject-tqv -listen "10.200.1.2:18080"' > $LOGD/tqv-object.log 2>&1 &
sleep 1
ip netns exec server-ns env MIST_KEY="$K" bash -c 'echo $$ > /root/pilot/logs/tqv-server.pid; exec /root/pilot/bin/labserver-tqv -listen "10.200.1.2:24443" -qlog-dir /root/pilot/logs/tqv-qlog -events-out /root/pilot/logs/tqv-server-events.json -pmtu-out /root/pilot/logs/tqv-server-pmtu.json' > $LOGD/tqv-server.log 2>&1 &
sleep 2
SRV_PID=$(cat $LOGD/tqv-server.pid); OBJ_PID=$(cat $LOGD/tqv-object.pid)
kill -0 "$SRV_PID" 2>/dev/null || { echo "SERVER_DEAD"; tail -5 $LOGD/tqv-server.log; ip netns del client-ns 2>/dev/null; ip netns del server-ns 2>/dev/null; exit 1; }
kill -0 "$OBJ_PID" 2>/dev/null || { echo "OBJECT_DEAD"; tail -5 $LOGD/tqv-object.log; kill -TERM "$SRV_PID" 2>/dev/null; ip netns del client-ns 2>/dev/null; ip netns del server-ns 2>/dev/null; exit 1; }
echo "server_pid=$SRV_PID object_pid=$OBJ_PID"
grep -h buildCommit $LOGD/tqv-server.log $LOGD/tqv-object.log
ps -p "$OBJ_PID" -o args= | sed 's/^/OBJ_CMDLINE /'
echo 0 > $LOGD/tqv-attempts.txt
TQV_SRV_PID="$SRV_PID" TQV_OBJ_PID="$OBJ_PID" nohup env MIST_KEY="$K" TQV_SRV_PID="$SRV_PID" TQV_OBJ_PID="$OBJ_PID" TAG="$TAG" bash $LOGD/tqv-bundle/tqv-run.sh > $LOGD/tqv-run.log 2>&1 < /dev/null &
echo "RUNNER_LAUNCHED pid=$!"
echo "POLL: /root/pilot/logs/tqv-result.txt for TQV_DONE"
