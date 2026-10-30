#!/bin/bash
# run-window.sh <窗口名:W1|W2|W3> <类别:A|B>
# 前置条件：调用方已在同一 shell 内按 §2.3 生成 K（本脚本不生成、不打印密钥）；
#   仿真域已按 §3 建立；抓包已按 §4 启动；watcher 已按附录 B 启动。
# 约定文件（/root/pilot/logs/ 下）：
#   <窗口>-sessions.jsonl：每行一条 labclient 摘要 JSON（成功行无 failure 字段）
#   <窗口>-completions.txt：每行一条完成记录（完成顺序写入）：<arm> <id> <ok|fail>
#   <窗口>.bytes / <窗口>.downbytes：watcher 维护（附录 B）
#   <窗口>.bytes.prev：上一窗口累计总字节（W1 为空即 0，由调用方在 W1 前写入 0）
#   <窗口>.stop：监视进程命中停止条件时写入原因；runner 发起前检查该文件
#
# 版本说明：本文件为试点 runner 的仓库内版本化源（此前只存在于 RUNBOOK
# 附录 A 与 VPS /root/pilot/bin 的手工投送件，W1/W3 两次断管/缺陷教训证明手工
# 流转脆弱）。本提交只落仓库版本，不部署到 VPS；/root/pilot/bin 的更新与
# RUNBOOK/PLAN 中直接臂串行化的文档修订，留待下次窗口派发时一并做。
#
# 直接臂 per-session 隔离规则（2026-10-30，chan 定向：改 harness 拿
# per-session 可分性，不接受段/batch 单位；A/B 两轮证明直接臂会话在 pcap
# 中不可分：同 IP 同端口、无连接字段、SYN 交织，B 类最大 SYN 间隔仅 0.277 秒）：
#   直接格子改为串行 + 每会话退出后静默 6 秒再起下一会话（要求 ≥5 秒，留 1 秒
#   裕量）。静默间隔 > 分析用的 5 秒聚类阈值，故 5 秒间隔聚类可精确还原会话；
#   串行保证会话绝不重叠（隔离由构造保证，不依赖会话时长假设）。
#   Mist 格子不动（UDP 流 = 会话，本身精确；并发仍 ≤4）。
# 窗口预算（串行直接臂）：直接 B 约 50×(3.34+6)≈467 秒；直接 A 约
# 50×(35+6)=2050 秒；叠加 Mist 格子（并发 4：A 约 575 秒、B 约 1863 秒）后，
# A 窗口约 44 分钟、B 窗口约 39 分钟，均在 60 分钟硬时钟内（A 较紧，时钟为兜底）。
set -u
WIN=$1; CLASS=$2
LOG=/root/pilot/logs/$WIN-sessions.jsonl
COMP=/root/pilot/logs/$WIN-completions.txt
BYTES=/root/pilot/logs/$WIN.bytes
PREV=/root/pilot/logs/$WIN.bytes.prev
STOP=/root/pilot/logs/$WIN.stop
START=$SECONDS
touch "$LOG" "$COMP"
[ -f "$PREV" ] || echo 0 > "$PREV"
total_bytes() {
  local cur=0 prev=0
  [ -f "$BYTES" ] && cur=$(cat "$BYTES" 2>/dev/null || echo 0)
  prev=$(cat "$PREV" 2>/dev/null || echo 0)
  echo $((cur + prev))
}
down_bytes() {
  local f=/root/pilot/logs/$WIN.downbytes
  [ -f "$f" ] && cat "$f" || echo 0
}
success_ok() { # $1=arm：成功会话数 = 含该 arm 且不含 failure 的摘要行数
  awk -v arm="$1" 'index($0, "\"arm\":\"" arm "\"") && !index($0, "\"failure\"") {n++} END {print n+0}' "$LOG"
}
# 监视进程：每 10 秒检查时钟 / 总字节硬停 / 类别下行 ceiling / 完成顺序连续失败 ≥5。
# 命中任一即写 STOP 文件并精确杀掉在途 labclient（全路径匹配，生产进程无此路径，不会误杀）。
monitor() {
  local off=0
  declare -A consec
  while true; do
    sleep 10
    if [ $((SECONDS - START)) -ge 3600 ]; then echo "CLOCK" > "$STOP"; break; fi
    local tb=$(total_bytes)
    if [ "$tb" -ge 500000000 ]; then echo "HARD_BYTES total=$tb" > "$STOP"; break; fi
    local db=$(down_bytes)
    if [ "$CLASS" = "A" ] && [ "$db" -gt 200000000 ]; then echo "CLASS_CEILING_A down=$db" > "$STOP"; break; fi
    if [ "$CLASS" = "B" ] && [ "$db" -gt 300000000 ]; then echo "CLASS_CEILING_B down=$db" > "$STOP"; break; fi
    # 按完成顺序（completions 文件行序）计每格子连续失败
    if [ -f "$COMP" ]; then
      local nlines=$(wc -l < "$COMP")
      while [ "$off" -lt "$nlines" ]; do
        off=$((off + 1))
        local line=$(sed -n "${off}p" "$COMP")
        local arm=$(echo "$line" | awk '{print $1}')
        local res=$(echo "$line" | awk '{print $3}')
        if [ "$res" = "ok" ]; then consec[$arm]=0; else consec[$arm]=$((${consec[$arm]:-0} + 1)); fi
        if [ "${consec[$arm]:-0}" -ge 5 ]; then echo "CONSEC_FAIL arm=$arm" > "$STOP"; break 2; fi
      done
    fi
  done
  pkill -f '/root/pilot/bin/labclient' 2>/dev/null
}
monitor &
MONITOR=$!
run_one() { # $1=arm $2=id：单会话；摘要先落单会话临时文件再追加进日志，避免多任务交错
  local arm=$1 id=$2 out=/root/pilot/logs/$id.out
  if [ "$arm" = "mist" ]; then
    ip netns exec client-ns env MIST_KEY="$K" /root/pilot/bin/labclient \
      -server 10.200.1.2:24443 -object 10.200.1.2:18080 -class "$CLASS" -id "$id" > "$out" 2>/root/pilot/logs/$id.err
  else
    ip netns exec client-ns /root/pilot/bin/labclient --direct \
      -object 10.200.1.2:18080 -class "$CLASS" -id "$id" > "$out" 2>/root/pilot/logs/$id.err
  fi
  # 成功判定以摘要 JSON 为准（退出码作复核）：摘要含 failure 字段即 fail；无摘要行（如被时钟杀掉）亦记 fail
  if [ -s "$out" ]; then cat "$out" >> "$LOG"; fi
  if [ -s "$out" ] && ! grep -q failure "$out"; then
    echo "$arm $id ok" >> "$COMP"
  else
    echo "$arm $id fail" >> "$COMP"
  fi
  rm -f "$out"
}
run_cell() { # $1=arm(mist|direct)：attempts 口径（协调员裁决）：i 为已发起数，格子发起满 50 即停，失败不补发
  # 2026-10-27 W3 前修复（W1 教训）：只等 run_one，绝不等 monitor——裸 wait 会连 monitor 一起等，
  # Mist 格子跑满后 runner 卡在 wait 直至时钟触发，直接格子见 STOP 文件跳过（W1 直接臂 0/0 根因）；
  # 并发按存活 run_one 数计（此前 jobs -pr 计数含 monitor，实际并发仅 3）。
  local arm=$1 i=0
  local pids=()
  wait_pids() { # 只等本格子已发起的 run_one，monitor 全程不动、格子间不重启
    local p
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
    pids=()
  }
  while [ "$i" -lt 50 ]; do
    [ -f "$STOP" ] && { echo "STOPPED $WIN $arm reason=$(cat $STOP)"; wait_pids; return 1; }
    if [ $((SECONDS - START)) -ge 3600 ]; then echo "CLOCK STOP $WIN $arm"; wait_pids; return 2; fi
    local tb=$(total_bytes)
    if [ "$tb" -ge 450000000 ]; then echo "SOFT STOP $WIN $arm total=$tb (wait in-flight)"; wait_pids; return 0; fi
    if [ "$tb" -ge 500000000 ]; then echo "HARD BYTE STOP $WIN $arm total=$tb"; wait_pids; return 3; fi
    while true; do
      local alive=()
      local p
      for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null && alive+=("$p"); done
      pids=("${alive[@]}")
      [ "${#pids[@]}" -lt 4 ] && break
      sleep 0.05
    done
    [ -f "$STOP" ] && { echo "STOPPED $WIN $arm reason=$(cat $STOP)"; wait_pids; return 1; }
    i=$((i + 1))
    local id="${WIN}-${arm}-${CLASS}-$(printf %03d $i)"
    run_one "$arm" "$id" &
    pids+=($!)
  done
  wait_pids
  return 0
}
run_cell_direct_isolated() { # 直接臂专用：串行 + 退出后静默 6 秒（见文件头隔离规则）
  # 与 run_cell 同口径：attempts 口径（发起满 50 即停，失败不补发）；
  # 门禁检查（STOP/时钟/软停/硬停）与 run_cell 逐项一致；monitor 全程不动。
  # 串行调用 run_one（前台执行）：会话退出后 sleep 6 再起下一会话，故相邻
  # 会话的段间静默间隔 ≥6 秒 > 5 秒聚类阈值，5 秒间隔聚类可精确还原会话。
  # 最后一会话后不 sleep（省 6 秒）。失败会话由 run_one 记入 $COMP，不补发。
  local i=0
  while [ "$i" -lt 50 ]; do
    [ -f "$STOP" ] && { echo "STOPPED $WIN direct reason=$(cat $STOP)"; return 1; }
    if [ $((SECONDS - START)) -ge 3600 ]; then echo "CLOCK STOP $WIN direct"; return 2; fi
    local tb=$(total_bytes)
    if [ "$tb" -ge 450000000 ]; then echo "SOFT STOP $WIN direct total=$tb"; return 0; fi
    if [ "$tb" -ge 500000000 ]; then echo "HARD BYTE STOP $WIN direct total=$tb"; return 3; fi
    i=$((i + 1))
    local id="${WIN}-direct-${CLASS}-$(printf %03d $i)"
    run_one direct "$id"
    if [ "$i" -lt 50 ]; then sleep 6; fi
  done
  return 0
}
# ONLY_ARM：为空跑两臂；mist|direct 只跑指定臂（W3 补直接臂时 ONLY_ARM=direct，Mist 50 已计入、不重跑），另一臂 rc 记 skip
RC_MIST=skip; RC_DIRECT=skip
if [ "${ONLY_ARM:-}" != "direct" ]; then run_cell mist; RC_MIST=$?; fi
if [ "${ONLY_ARM:-}" != "mist" ]; then run_cell_direct_isolated; RC_DIRECT=$?; fi
kill $MONITOR 2>/dev/null
echo "WINDOW $WIN DONE mist_rc=$RC_MIST direct_rc=$RC_DIRECT mist_ok=$(success_ok mist) direct_ok=$(success_ok direct) mist_launched=$(awk '$1=="mist" {n++} END {print n+0}' "$COMP") direct_launched=$(awk '$1=="direct" {n++} END {print n+0}' "$COMP") stop=$(cat $STOP 2>/dev/null || echo none)"
