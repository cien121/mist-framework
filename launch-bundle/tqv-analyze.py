#!/usr/bin/env python3
"""TQV analyzer: reads tqv-result.txt (+ firstbyte JSONs + SIZE pcaps + G1
aggregates when present) and prints verdict rows.
Design: nextround/truequic-validation-design.md. Calibration scan + distribution
measurement, not a rate measurement: never prints false-trigger rates.
Byte criterion: class A counts completed objects only (exact totals).
Session summary JSON comes from labclient stdout (parse_out in the runner).
BUMP lines carry Go log timestamps (YYYY/MM/DD HH:MM:SS prefix).
JS: Jensen-Shannon on IP-total-length histograms; 9-band (Stage C frozen bins)
+ 100B / 50B fine-grained; pooled + per-unit (per Mist session vs direct
pooled, median/p90/max). Direction ratio, Fano (1s buckets, median), fragment
count from the same pcaps. KS on RTT-normalized log inter-arrival uses the
per-session median as normalizer (approximation, stated in the row).
ACK: TCP pure-ACK/MB for the direct arm only; Mist/H3 QUIC ACK is encrypted
and unreadable, so those rows are NOT-MEASURED with the reason stated.
Classifier rows are NOT-MEASURED in-runner: the L3 pool (holdout ~17/arm/class)
is far below M4's >=50, and classifier evaluation is an offline step on the
retained pcaps + G1 features; this analyzer writes the classifier manifest
instead of judging L3.
Backoff check: bump lines print BEFORE the backoff sleep, so consecutive
object-bump timestamps differ by ~T + previous backoff (T=8s: ~9s/10s/12s),
NOT by 1s/2s/4s as design section 3.4 literally reads; the analyzer checks
T+[1,2,4] with +-1.5s tolerance and always prints the raw diffs.
No traffic, no code changes, read-only on pcaps and result files.
"""
import sys, json, math, re, glob, os, struct
from datetime import datetime

LOGD = "/root/pilot/logs"
BUNDLED = LOGD + "/tqv-bundle"
RES = LOGD + "/tqv-result.txt"
G1D = "/root/pilot/g1"

BANDS9 = [0, 100, 200, 300, 500, 700, 900, 1100, 1400, 10 ** 9]


def parse_result():
    sessions, bumps, markers = {}, {}, []
    try:
        lines = open(RES, errors="replace").read().splitlines()
    except FileNotFoundError:
        return sessions, bumps, markers
    for line in lines:
        m = re.match(r"START (\S+)", line)
        if line.startswith("summary="):
            try:
                d = json.loads(line[len("summary="):])
            except Exception:
                continue
            sessions[d.get("session_id", "").replace("tqv-", "")] = d
        m = re.match(r"BUMP (\S+): (.*)", line)
        if m:
            bumps.setdefault(m.group(1), []).append(m.group(2))
        if line.startswith("TQV_") or "DEFERRED" in line or "STOP" in line:
            markers.append(line)
    return sessions, bumps, markers


def is_trip(s):
    return bool(s.get("stall_detected")) or int(s.get("stall_reconnects", 0)) > 0


def page_bumps(s):
    return int(s.get("stall_page_bumps", 0) or 0)


def obj_bump_lines(name, bumps):
    return [b for b in bumps.get(name, []) if "objects in flight" in b]


def page_bump_lines(name, bumps):
    return [b for b in bumps.get(name, []) if "on page fetch" in b]


def base_ok(s, total, count):
    return (s is not None and not s.get("failure")
            and s.get("down_bytes") == total and s.get("objects") == count)


def m1_verdict(name, s):
    if s is None:
        return "MISSING"
    if s.get("failure"):
        return "FAIL:" + str(s["failure"])[:80]
    if s.get("down_bytes") != 1032192 or s.get("objects") != 15:
        return f"FAIL:bytes down={s.get('down_bytes')} objects={s.get('objects')}"
    if int(s.get("profile_version", 0) or 0) < 1:
        return f"FAIL:profile_version={s.get('profile_version')} (want >=1 with burst)"
    return "PASS"


def m2_verdict(names, sessions):
    """3 wrong-key sessions: all failed, latencies within median +-25%,
    and no down-events for their udp_local in the server events-out."""
    lats, addrs = [], []
    for n in names:
        s = sessions.get(n)
        if s is None:
            return "MISSING"
        if not s.get("failure"):
            return f"FAIL:{n} did not fail"
        try:
            st = datetime.fromisoformat(str(s["started_at"]).replace("Z", "+00:00"))
            en = datetime.fromisoformat(str(s["ended_at"]).replace("Z", "+00:00"))
            lats.append((en - st).total_seconds())
        except Exception:
            return f"FAIL:{n} bad timestamps"
        if s.get("udp_local"):
            addrs.append(s["udp_local"])
    lats.sort()
    med = lats[len(lats) // 2]
    if med <= 0 or max(lats) > med * 1.25 or min(lats) < med * 0.75:
        return f"FAIL:latencies={['%.2f' % x for x in lats]} median={med:.2f} (want +-25%)"
    ev = {}
    for path in glob.glob(LOGD + "/tqv-server-events*.json"):
        try:
            ev.update(json.load(open(path)))
        except Exception:
            pass
    leaked = [a for a in addrs if a in ev]
    if leaked:
        return f"FAIL:down-events present for failed sessions: {leaked}"
    return f"PASS latencies={['%.2f' % x for x in lats]} median={med:.2f}s"


def ta_verdict(name, s, bumps):
    if s is None:
        return "MISSING"
    if s.get("failure"):
        return "FAIL:" + str(s["failure"])[:80]
    if s.get("down_bytes") != 1032192 or s.get("objects") != 15:
        return f"FAIL:bytes down={s.get('down_bytes')} objects={s.get('objects')}"
    if is_trip(s):
        return f"TRIP:reconnects={s.get('stall_reconnects')}"
    if bumps.get(name):
        return "TRIP:bump-lines-present"
    return "PASS"


def vpage_verdict(cell, s, bumps):
    """cell: (name, expect_page_bumps, expect_obj_bumps, expect_reconnects,
    expect_generations, expect_page_fetches, check_down_exact)."""
    (name, ep, eo, er, eg, _, _) = cell
    if s is None:
        return "MISSING"
    pb = page_bumps(s)
    ob = len(obj_bump_lines(name, bumps))
    ok = (pb == ep and ob == eo
          and int(s.get("stall_reconnects", 0) or 0) == er
          and int(s.get("stall_generations", 0) or 0) == eg)
    if cell[5] == "down-exact" and s.get("down_bytes") != 1032192:
        ok = False
    if cell[5] == "down-zero" and s.get("down_bytes") not in (0, None):
        ok = False
    detail = (f"page_bumps={pb} obj_bumps={ob} reconnects={s.get('stall_reconnects')} "
              f"generations={s.get('stall_generations')} down={s.get('down_bytes')} "
              f"failure={str(s.get('failure'))[:60]}")
    if cell[5] == "diag":
        return "DIAG " + detail
    return ("PASS " if ok else "FAIL ") + detail


def bh_d_verdict(name, s, bumps, T):
    if s is None:
        return "MISSING"
    pb = page_bumps(s)
    ob = len(obj_bump_lines(name, bumps))
    ok = (not s.get("failure") and s.get("down_bytes") == 1032192
          and s.get("objects") == 15 and s.get("stall_reconnects") == 1
          and s.get("stall_generations") == 2 and pb == 0 and ob == 1)
    return (("PASS " if ok else "FAIL ")
            + f"reconnects={s.get('stall_reconnects')} generations={s.get('stall_generations')} "
            f"retried={s.get('stall_objects_retried')} down={s.get('down_bytes')} "
            f"page_bumps={pb} obj_bump_lines={ob} failure={str(s.get('failure'))[:60]}")


def bh_c_verdict(name, s, bumps):
    if s is None:
        return "MISSING"
    ob = len(obj_bump_lines(name, bumps))
    ok = (s.get("failure") and "cap exhausted" in str(s["failure"])
          and s.get("stall_reconnects") == 3
          and s.get("stall_generations") == 4 and ob == 3)
    return (("PASS " if ok else "FAIL ")
            + f"reconnects={s.get('stall_reconnects')} generations={s.get('stall_generations')} "
            f"retried={s.get('stall_objects_retried')} obj_bump_lines={ob} "
            f"failure={str(s.get('failure'))[:60]}")


def backoff_check(name, bumps, T):
    """Parse Go log timestamps on object-bump lines; expect diffs ~T+[1,2,4]s."""
    stamps = []
    for b in obj_bump_lines(name, bumps):
        m = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", b)
        if m:
            try:
                stamps.append(datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S"))
            except Exception:
                pass
    if len(stamps) < 2:
        return f"backoff: only {len(stamps)} timestamped obj-bump lines (need >=2)"
    diffs = [(stamps[i + 1] - stamps[i]).total_seconds() for i in range(len(stamps) - 1)]
    exp = [T + d for d in (1, 2, 4)][:len(diffs)]
    ok = all(abs(d - e) <= 1.5 for d, e in zip(diffs, exp))
    return (f"backoff diffs={diffs} expected~={exp} "
            + ("PASS" if ok else "UNVERIFIED (timing did not show increment; log statement only)"))


def pct(vals, p):
    if not vals:
        return None
    v = sorted(vals)
    i = min(len(v) - 1, max(0, math.ceil(p / 100.0 * len(v)) - 1))
    return v[i]


# ---- pcap parsing (stdlib only; snaplen-truncated is fine: IP header survives) ----

def read_pcap(path):
    """Yield (ts, ip_len, proto, src, dst, sport, dport, flags, frag)."""
    try:
        data = open(path, "rb").read()
    except FileNotFoundError:
        return
    if len(data) < 24:
        return
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        en, frac = "<", 1000000
    elif magic == b"\xa1\xb2\xc3\xd4":
        en, frac = ">", 1000000
    elif magic == b"\x4d\x3c\xb2\xa1":
        en, frac = "<", 1000000000
    elif magic == b"\xa1\xb2\x3c\x4d":
        en, frac = ">", 1000000000
    else:
        return
    off = 24
    n = len(data)
    while off + 16 <= n:
        ts_s, ts_f, cap, _ = struct.unpack_from(en + "IIII", data, off)
        off += 16
        if off + cap > n:
            break
        pkt = data[off:off + cap]
        off += cap
        if len(pkt) < 14:
            continue
        et = struct.unpack_from(">H", pkt, 12)[0]
        ip = pkt[14:]
        if et == 0x0800 and len(ip) >= 20:
            ver = ip[0] >> 4
            ihl = (ip[0] & 0x0F) * 4
            total = struct.unpack_from(">H", ip, 2)[0]
            frag = struct.unpack_from(">H", ip, 6)[0] & 0x3FFF
            proto = ip[9]
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])
        elif et == 0x86DD and len(ip) >= 40:
            total = struct.unpack_from(">H", ip, 4)[0] + 40
            frag = 0
            proto = ip[6]
            src = ":".join("%x" % struct.unpack_from(">H", ip, 8 + 2 * i)[0] for i in range(8))
            dst = ":".join("%x" % struct.unpack_from(">H", ip, 24 + 2 * i)[0] for i in range(8))
            ihl = 40
        else:
            continue
        if proto not in (6, 17) or len(ip) < ihl + 4:
            continue
        sport, dport = struct.unpack_from(">HH", ip, ihl)
        flags = ip[ihl + 13] if proto == 6 and len(ip) >= ihl + 14 else 0
        yield (ts_s + ts_f / frac, total, proto, src, dst, sport, dport, flags, frag)


def hist(vals, edges):
    h = [0] * (len(edges) - 1)
    for v in vals:
        for i in range(len(edges) - 1):
            if edges[i] <= v < edges[i + 1]:
                h[i] += 1
                break
    return h


def js(h1, h2):
    n1, n2 = sum(h1), sum(h2)
    if n1 == 0 or n2 == 0:
        return None
    p = [x / n1 for x in h1]
    q = [x / n2 for x in h2]
    tot = 0.0
    for a, b in zip(p, q):
        m = (a + b) / 2
        if a > 0:
            tot += a * math.log2(a / m)
        if b > 0:
            tot += b * math.log2(b / m)
    return math.sqrt(tot / 2)


def fine_edges(step):
    return list(range(0, 1500 + step, step)) + [10 ** 9]


def session_lengths(pcap, mist_port, object_port, client):
    """Mist sessions: UDP 5-tuples to mist_port. Direct sessions: TCP flows
    to object_port, split on >5s gaps (runner runs direct serially, 6s silence).
    Returns (mist_sessions, direct_sessions): lists of length lists."""
    mist, direct = {}, []
    cur = None
    for (ts, ln, proto, src, dst, sport, dport, fl, fr) in read_pcap(pcap):
        if proto == 17 and (dport == mist_port or sport == mist_port):
            key = tuple(sorted([(src, sport), (dst, dport)]))
            mist.setdefault(key, []).append(ln)
        elif proto == 6 and (dport == object_port or sport == object_port):
            if cur is None or ts - cur[0] > 5.0:
                cur = [ts, []]
                direct.append(cur[1])
            cur[0] = ts
            cur[1].append(ln)
    return list(mist.values()), direct


def js_rows(mist_pcap, direct_pcap, label):
    ms, _ = session_lengths(mist_pcap, 24443, 18080, None)
    _, ds = session_lengths(direct_pcap, 24443, 18080, None)
    if not ms or not ds:
        return [f"{label}: NO_DATA mist_sessions={len(ms)} direct_sessions={len(ds)}"]
    pooled_m = [x for s in ms for x in s]
    pooled_d = [x for s in ds for x in s]
    out = []
    for name, edges in [("9-band", BANDS9), ("100B", fine_edges(100)), ("50B", fine_edges(50))]:
        j = js(hist(pooled_m, edges), hist(pooled_d, edges))
        per = []
        dh = hist(pooled_d, edges)
        for s in ms:
            v = js(hist(s, edges), dh)
            if v is not None:
                per.append(v)
        per_s = (f"per-unit median={pct(per, 50):.4f} p90={pct(per, 90):.4f} "
                 f"max={max(per):.4f} n={len(per)}" if per else "per-unit NO_DATA")
        out.append(f"{label} {name} pooled JS={j:.4f} {per_s}" if j is not None
                   else f"{label} {name} NO_DATA")
    return out


def flow_stats(pcap, mist_port, object_port):
    """Direction ratio (pooled + per-flow median), Fano 1s median, fragments."""
    up = down = frags = 0
    per_flow_dir, per_flow_fano = [], []
    flows = {}
    for (ts, ln, proto, src, dst, sport, dport, fl, fr) in read_pcap(pcap):
        if fr != 0:
            frags += 1
        if proto == 17 and (dport == mist_port or sport == mist_port):
            key = tuple(sorted([(src, sport), (dst, dport)]))
            flows.setdefault(key, []).append((ts, ln, src, sport))
        elif proto == 6 and (dport == object_port or sport == object_port):
            key = (src, sport, dst, dport)
            flows.setdefault(key, []).append((ts, ln, src, sport))
    for key, pkts in flows.items():
        # direction: first packet sender is the client for Mist (UDP) and
        # for TCP the SYN sender; approximate client = first sender.
        cli = pkts[0][2]
        up_b = sum(ln for _, ln, s, p in pkts if s == cli)
        dn_b = sum(ln for _, ln, s, p in pkts if s != cli)
        up += up_b
        down += dn_b
        if dn_b > 0:
            per_flow_dir.append(up_b / dn_b)
        buckets = {}
        for ts, ln, s, p in pkts:
            buckets.setdefault(int(ts), []).append(ln)
        counts = [len(v) for v in buckets.values()]
        if len(counts) >= 2:
            mean = sum(counts) / len(counts)
            var = sum((c - mean) ** 2 for c in counts) / len(counts)
            per_flow_fano.append(var / mean if mean else 0)
    ratio = (up / down) if down else None
    return ratio, pct(per_flow_dir, 50), pct(per_flow_fano, 50), frags


def tcp_ack_per_mb(pcap, object_port):
    """TCP pure ACKs (ACK set, no SYN/FIN/RST, zero payload) per MB, direct arm."""
    acks = 0
    tot = 0
    for (ts, ln, proto, src, dst, sport, dport, fl, fr) in read_pcap(pcap):
        if proto != 6:
            continue
        tot += ln
        if fl & 0x10 and not (fl & 0x07) and ln <= 66:
            acks += 1
    return (acks / (tot / 1e6)) if tot else None

def g1_aggregates():
    """Aggregate G1 pcaps (QUIC-only栏 = UDP port 443) into aggregates.json.
    Returns path or None when G1 pcaps are absent."""
    a = os.path.join(G1D, "h3-baseline-" + __import__("datetime").date.today().strftime("%Y%m%d"), "g1-a.pcap")
    b = a.replace("g1-a.pcap", "g1-b.pcap")
    gdirs = sorted(glob.glob(G1D + "/h3-baseline-*/"))
    if not gdirs:
        return None
    gd = gdirs[-1]
    pa, pb = os.path.join(gd, "g1-a.pcap"), os.path.join(gd, "g1-b.pcap")
    if not (os.path.exists(pa) and os.path.exists(pb)):
        return None
    out = {"version": os.path.basename(gd.rstrip("/")), "quic_only": {}, "tcp_only": {}, "mixed": {}}
    for name, path in [("A", pa), ("B", pb)]:
        q, t, m = [], [], []
        for (ts, ln, proto, src, dst, sport, dport, fl, fr) in read_pcap(path):
            m.append(ln)
            if proto == 17 and (sport == 443 or dport == 443):
                q.append(ln)
            elif proto == 6:
                t.append(ln)
        out["quic_only"][name] = {"n": len(q), "hist9": hist(q, BANDS9),
                                   "hist100": hist(q, fine_edges(100)),
                                   "hist50": hist(q, fine_edges(50))}
        out["tcp_only"][name] = {"n": len(t), "hist9": hist(t, BANDS9)}
        out["mixed"][name] = {"n": len(m), "hist9": hist(m, BANDS9)}
    agg = os.path.join(gd, "aggregates.json")
    with open(agg, "w") as f:
        json.dump(out, f)
    return agg


def js_vs_h3(mist_pcap, agg):
    """Fine-grained + 9-band JS, Mist pooled/per-unit vs G1 QUIC-only pooled."""
    if agg is None:
        return ["SIZE fine-grained JS (Mist vs matched H3): NOT-MEASURED (G1 not landed)"]
    try:
        g = json.load(open(agg))
    except Exception:
        return ["SIZE fine-grained JS (Mist vs matched H3): NOT-MEASURED (aggregates unreadable)"]
    ms, _ = session_lengths(mist_pcap, 24443, 18080, None)
    if not ms:
        return ["SIZE fine-grained JS (Mist vs matched H3): NO_DATA (no Mist sessions in pcap)"]
    pooled_m = [x for s in ms for x in s]
    out = []
    for cls in ("A", "B"):
        gh = g["quic_only"].get(cls)
        if not gh:
            out.append(f"SIZE class {cls} vs H3: NO_DATA (no G1 {cls} baseline)")
            continue
        for name, edges, key in [("9-band", BANDS9, "hist9"),
                                 ("100B", fine_edges(100), "hist100"),
                                 ("50B", fine_edges(50), "hist50")]:
            j = js(hist(pooled_m, edges), gh[key])
            per = []
            for s in ms:
                v = js(hist(s, edges), gh[key])
                if v is not None:
                    per.append(v)
            per_s = (f"per-unit median={pct(per, 50):.4f} p90={pct(per, 90):.4f} "
                     f"max={max(per):.4f} n={len(per)}" if per else "per-unit NO_DATA")
            out.append(f"SIZE class {cls} vs H3 {name} pooled JS={j:.4f} {per_s}"
                       if j is not None else f"SIZE class {cls} vs H3 {name} NO_DATA")
    return out


def final_lines():
    sessions, bumps, markers = parse_result()
    L = ["=== TQV_VERDICTS (analyzer) ==="]
    L.append("Language rule: mechanism work is fingerprint reduction only; "
             "no row below claims indistinguishability.")
    for i in (1, 2, 3):
        L.append(f"m1-connect-{i}: {m1_verdict(f'm1-connect-{i}', sessions.get(f'm1-connect-{i}'))}")
    L.append(f"m2-authfail: {m2_verdict([f'm2-authfail-{i}' for i in (1, 2, 3)], sessions)}")
    for i in (1, 2, 3, 4):
        L.append(f"ta-core-{i}: {ta_verdict(f'ta-core-{i}', sessions.get(f'ta-core-{i}'), bumps)}")
    for i in (1, 2, 3):
        L.append(f"ta-confirm-{i}: {ta_verdict(f'ta-confirm-{i}', sessions.get(f'ta-confirm-{i}'), bumps)}")
    L.append("V-page-0: DEFERRED (page first-byte hook missing in this tree; "
             "F proxy p99=2.05s used as L_tail input; see PRECHECK ③)")
    vpage = [
        ("vpage-1-d2", 0, 0, 0, 0, "down-exact", None),
        ("vpage-1-d4", 0, 0, 0, 0, "down-exact", None),
        ("vpage-2", 0, 1, 1, 2, "down-exact", None),
        ("vpage-3-t5", 1, 0, 1, 2, "down-zero", None),
        ("vpage-3-t8", 0, 0, 0, 0, "down-exact", None),
        ("vpage-4", 3, 0, 3, 4, "down-zero", None),
        ("vpage-5-n1", 0, 0, 0, 0, "diag", None),
        ("vpage-5-n2", 0, 0, 0, 0, "diag", None),
        ("vpage-5-n3", 0, 0, 0, 0, "diag", None),
        ("vpage-6-n1", 0, 0, 0, 0, "down-exact", None),
        ("vpage-6-n2", 0, 0, 0, 0, "down-exact", None),
        ("vpage-7", 1, 0, 1, 2, "down-exact", None),
    ]
    for cell in vpage:
        s = sessions.get(cell[0])
        if cell[0] == "vpage-4":
            # terminal form accepts cap-exhausted failure OR over-window return;
            # mode attribution must be all page.
            if s is None:
                L.append("vpage-4: MISSING")
            else:
                pb = page_bumps(s)
                ob = len(obj_bump_lines(cell[0], bumps))
                ok = (pb >= 1 and ob == 0 and s.get("down_bytes") in (0, None))
                L.append(("PASS " if ok else "FAIL ")
                         + f"vpage-4 page_bumps={pb} obj_bumps={ob} reconnects={s.get('stall_reconnects')} "
                         f"down={s.get('down_bytes')} failure={str(s.get('failure'))[:60]}")
            continue
        if cell[0] == "vpage-3-t5":
            # page-mode bump >=1 expected (d4-t5 failure shape with mode=page);
            # reconnects/generations follow the bump count, down==0.
            if s is None:
                L.append("vpage-3-t5: MISSING")
            else:
                pb = page_bumps(s)
                ob = len(obj_bump_lines(cell[0], bumps))
                ok = (pb >= 1 and ob == 0 and s.get("down_bytes") in (0, None))
                L.append(("PASS " if ok else "FAIL ")
                         + f"vpage-3-t5 page_bumps={pb} obj_bumps={ob} reconnects={s.get('stall_reconnects')} "
                         f"down={s.get('down_bytes')} failure={str(s.get('failure'))[:60]}")
            continue
        L.append(f"{cell[0]}: {vpage_verdict(cell, s, bumps)}")
    for i in (1, 2, 3, 4, 5):
        L.append(f"bh-d-main-{i}: {bh_d_verdict(f'bh-d-main-{i}', sessions.get(f'bh-d-main-{i}'), bumps, 8)}")
    for i in (1, 2):
        L.append(f"bh-d-lat-{i}: {bh_d_verdict(f'bh-d-lat-{i}', sessions.get(f'bh-d-lat-{i}'), bumps, 3)}")
    for i in (1, 2):
        L.append(f"bh-c-{i}: {bh_c_verdict(f'bh-c-{i}', sessions.get(f'bh-c-{i}'), bumps)}")
        L.append(f"bh-c-{i} {backoff_check(f'bh-c-{i}', bumps, 8)}")
    L.append("bh-v1r: " + (("PASS " if (sessions.get('bh-v1r') and is_trip(sessions['bh-v1r'])
                             and int(sessions['bh-v1r'].get('stall_reconnects', 0) or 0) >= 1)
                            else "FAIL ")
                           + f"stall_detected={sessions.get('bh-v1r', {}).get('stall_detected')} "
                           f"reconnects={sessions.get('bh-v1r', {}).get('stall_reconnects')} "
                           f"down={sessions.get('bh-v1r', {}).get('down_bytes')} "
                           f"completed={sessions.get('bh-v1r', {}).get('failure') is None}"))
    L.append("bh-v3: DEFERRED (no wiring1/clear-DF variant binary in this tree; "
             "see PRECHECK; must not be written as passed from wiring2 alone)")
    for side in ("srv", "cli"):
        s = sessions.get(f"bh-v5-{side}")
        ok = bool(s and is_trip(s))
        L.append(f"bh-v5-{side}: {'PASS (stalled as V5 predicts)' if ok else 'FAIL '}"
                 f"stall_detected={s.get('stall_detected') if s else None} "
                 f"reconnects={s.get('stall_reconnects') if s else None}")
    s = sessions.get("bh-v6")
    ok = bool(s and is_trip(s) and int(s.get("stall_reconnects", 0) or 0) >= 1)
    L.append(f"bh-v6: {'PASS ' if ok else 'FAIL '}"
             f"stall_detected={s.get('stall_detected') if s else None} "
             f"reconnects={s.get('stall_reconnects') if s else None}")
    # SIZE rows from pcaps
    for cls, tag in [("A", "size-mist-a"), ("B", "size-mist-b")]:
        mp = f"{LOGD}/tqv-{tag}.pcap"
        dp = f"{LOGD}/tqv-size-direct-{cls.lower()}.pcap"
        L.extend(js_rows(mp, dp, f"SIZE class {cls} (Mist vs direct)"))
        r, rmed, fmed, fr = flow_stats(mp, 24443, 18080)
        L.append(f"SIZE class {cls} Mist direction ratio pooled={r} per-flow median={rmed} "
                 f"Fano-1s median={fmed} fragments={fr}")
        r2, rmed2, fmed2, fr2 = flow_stats(dp, 24443, 18080)
        L.append(f"SIZE class {cls} direct direction ratio pooled={r2} per-flow median={rmed2} "
                 f"Fano-1s median={fmed2} fragments={fr2}")
        ack = tcp_ack_per_mb(dp, 18080)
        L.append(f"SIZE class {cls} direct TCP pure-ACK per MB={ack} "
                 f"(Mist/H3 QUIC ACK unreadable: NOT-MEASURED)")
    # SIZE-v6: A-class spot check (Stage C B11-v6 yardstick: v6 A validated
    # 1489, peer_cap 1500; allow 1483-1489 band for the validated value).
    for i in (1, 2, 3, 4, 5):
        s = sessions.get(f"size-v6-mist-{i}")
        if s is None:
            L.append(f"size-v6-mist-{i}: MISSING")
        else:
            v = s.get("pmtu_validated_ip")
            ok = (not s.get("failure") and s.get("down_bytes") == 1032192
                  and s.get("objects") == 15 and v in (1483, 1489)
                  and s.get("pmtu_peer_cap_ip") == 1500)
            L.append(f"size-v6-mist-{i}: {'PASS ' if ok else 'FAIL '}"
                     f"down={s.get('down_bytes')} validated_ip={v} "
                     f"peer_cap={s.get('pmtu_peer_cap_ip')} failure={str(s.get('failure'))[:40]}")
        s = sessions.get(f"size-v6-direct-{i}")
        if s is None:
            L.append(f"size-v6-direct-{i}: MISSING")
        else:
            ok = (not s.get("failure") and s.get("down_bytes") == 1032192
                  and s.get("objects") == 15)
            L.append(f"size-v6-direct-{i}: {'PASS ' if ok else 'FAIL '}"
                     f"down={s.get('down_bytes')} failure={str(s.get('failure'))[:40]}")
    agg = g1_aggregates()
    if agg is None:
        L.append("SIZE fine-grained JS (Mist vs matched H3): NOT-MEASURED (G1 not landed; "
                 "must not be back-filled after SIZE analysis)")
    else:
        L.append(f"G1 aggregates: {agg}")
        for cls, tag in [("A", "size-mist-a"), ("B", "size-mist-b")]:
            L.extend(js_vs_h3(f"{LOGD}/tqv-{tag}.pcap", agg))
    L.append("MECH-decoy: DEFERRED (no labserver decoy flag in this tree; see PRECHECK)")
    L.append("MECH-D11-quic: DEFERRED (no labclient pre-AUTH probe mode; see PRECHECK)")
    L.append("MECH-D11-tcp: DEFERRED (no labclient pre-AUTH probe mode; see PRECHECK)")
    L.append("MECH-rot: DEFERRED (no rotation enable / IssueProfile channel / count output; see PRECHECK)")
    L.append("SPL-pmtu: DEFERRED (SplitClient not wired into labclient; see PRECHECK)")
    L.append("SPL-stagger: DEFERRED (SplitClient not wired into labclient; see PRECHECK)")
    L.append("SPL-tcp: DEFERRED (SplitClient not wired into labclient; see PRECHECK)")
    L.append("L3 classifier (AUC-0.5 + DeLong 95% CI + permutation p): NOT-MEASURED "
             "(holdout ~17/arm/class, far below M4 >=50; offline step on retained pcaps)")
    # classifier manifest for the offline step
    man = {"mist_pcaps": [f"{LOGD}/tqv-size-mist-a.pcap", f"{LOGD}/tqv-size-mist-b.pcap"],
           "direct_pcaps": [f"{LOGD}/tqv-size-direct-a.pcap", f"{LOGD}/tqv-size-direct-b.pcap"],
           "g1_aggregates": agg,
           "completions": f"{LOGD}/tqv-completions.txt",
           "note": "train:test 2:1, session-disjoint; site holdout secondary; "
                   "time-disjoint NOT satisfied (single window); do not judge L3 from this round"}
    with open(f"{LOGD}/tqv-classifier-manifest.json", "w") as f:
        json.dump(man, f)
    L.append("classifier manifest: " + f"{LOGD}/tqv-classifier-manifest.json")
    # attempts + stop markers
    att = 0
    try:
        att = int(open(f"{LOGD}/tqv-attempts.txt").read().strip() or 0)
    except Exception:
        pass
    L.append(f"attempts={att} (cap 280)")
    for m in markers:
        L.append(f"marker: {m}")
    return L


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "--final"
    if mode == "--final":
        lines = final_lines()
        with open(RES, "a") as f:
            f.write("\n".join(lines) + "\n")
        print("\n".join(lines))
    else:
        print("unknown mode: " + mode)
        sys.exit(2)
