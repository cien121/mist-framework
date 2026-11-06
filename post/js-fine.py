#!/usr/bin/env python3
# js-fine.py -- Stage C (W-5) fine-grained packet-length Jensen-Shannon script.
#
# Frozen spec (do not change numbers without a new freeze):
#   - Packet length = IP total length (IPv4 total_length; IPv6 40 +
#     payload_length), NOT Ethernet frame length, NOT captured length
#     (snaplen-safe: the header field survives -s 160 truncation).
#   - Direction: downlink = source == server; uplink = source == client.
#     Packets with neither endpoint are skipped.
#   - JS = Jensen-Shannon divergence, log base 2, range [0, 1];
#     0*log0 counted as 0. Pooled JS = pooled histograms of the two arms.
#   - Binning is left-closed, right-open; the last bin catches the
#     upper tail (see BINNING below).
#   - Three bin sets computed together: 9-bin + 100B + 50B.
#   - GSO-split and original-length variants reported side by side.
#   - Same-class (null) units: GSO-split, session/batch level.
#     Mist units = UDP flow 5-tuple == session (exact, Tier 1 convention).
#     Direct units = cluster-5s.py session definition, re-implemented
#     here verbatim (see DIRECT UNITS below); --cluster-report cross-
#     checks unit counts and per-unit down-byte multisets against a
#     cluster-5s.py JSON report instead of inventing a new partition.
#
# BINNING -- provenance:
#   - 9-bin edges are the frozen canonical Stage 1 bins, from
#     nextround/m4m5-readiness/REPORT.md section 1.1 item 2 and from
#     nextround/pilot-a-analysis/analyze2.py (BINS):
#       [0,100), [100,200), [200,400), [400,600), [600,800),
#       [800,1000), [1000,1200), [1200,1400), [1400, +inf).
#     In interval notation the published labels are 0-99, 100-199,
#     200-399, 400-599, 600-799, 800-999, 1000-1199, 1200-1399, 1400+.
#     A packet of exactly 1400 falls in the 1400+ bin under both the
#     9-bin rule and the merged 6-bin rule.
#   - 100B / 50B bins: NO prior pilot document defines their edges, so
#     this is THIS SCRIPT'S DEFINITION (not a frozen value, not silently
#     borrowed): bin index = ip_length // width, i.e. edges at multiples
#     of the width from 0, left-closed right-open, with the last (max)
#     bin open-ended. JS is invariant to how the empty tail above the
#     data maximum is closed: every bin above the Mist maximum holds
#     Mist mass 0, so its JS contribution is 0.5 * (direct mass) no
#     matter how finely it is split, and bins above the direct maximum
#     hold mass 0 on both sides. What matters -- and what is fixed here
#     -- is that edges sit at multiples of the width from 0.
#
# GSO SPLIT -- provenance (Tier 1 practice, analyze2.py / analyze-b.py
# "GSO diagnostics" block, same in both files; REPORT.md section 4 of
# each pilot report describes it in words):
#   - Only the DIRECT arm is split (Mist UDP packets never exceed 1500
#     in Tier 1: 0 packets > 1500, so splitting Mist would be a no-op;
#     the code splits direct-arm TCP packets only, exactly as Tier 1).
#   - modal_doff = mode of the TCP data-offset header length (bytes)
#     over direct-arm TCP packets with payload > 0 (both directions);
#     fallback 32 if there is none. Tier 1 measured modal 32.
#   - mss = 1500 - ip_header - modal_doff (IPv4 header 20, IPv6 header
#     40; Tier 1 hardcodes 20 because its data is IPv4-only, and lab
#     IPv4 packets carry no IP options so ihl == 20, hence this
#     generalisation reduces exactly to Tier 1 on Tier 1 data).
#   - A direct TCP packet with ip_length > 1500 is replaced by
#     nf = payload // mss full wire packets of length
#     mss + ip_header + per_packet_doff, plus one remainder packet of
#     length rem + ip_header + per_packet_doff if rem = payload % mss
#     is nonzero. payload = ip_length - ip_header - per_packet_doff.
#     (Tier 1 literal: a >1500 packet with payload <= 0 would emit
#     nothing; that cannot occur for a real TCP packet since headers
#     are at most ~120 bytes, and it is counted in diagnostics if seen.)
#   - Non-TCP packets and packets <= 1500 keep their original length.
#   - The modal doff / mss are computed ONCE per direct arm (arm-global)
#     and applied to every unit of that arm, pooled and per-unit alike.
#   - This is a wire reconstruction (each emitted segment carries its
#     own IP + TCP header), explicitly NOT the primary measurement --
#     Tier 1 labels it a sensitivity analysis, and so does this script.
#
# DIRECT UNITS -- cluster-5s.py definition, reused verbatim:
#   - Packet set: TCP packets with the object port in (sport, dport)
#     and endpoints exactly {client, server}, sorted by timestamp
#     (stable sort over pcap order, as in cluster-5s.py).
#   - A new unit starts when ts - previous_packet_ts > gap (default
#     5.0 s). Under Tier 1 concurrent direct arms this yields batches;
#     under the serial + 6 s silence runner it yields sessions. The
#     script does not distinguish: it reports whatever the rule yields
#     and labels the count honestly (units, not sessions, when the
#     input is a batch-yielding capture).
#
# MIST UNITS -- UDP flow 5-tuple == session:
#   - Key = (client_port, server_port) with client/server identified by
#     IP, i.e. the full 5-tuple (proto UDP, client IP, client port,
#     server IP, server port) given fixed lab addresses -- identical to
#     cluster-5s.py's key.
#
# LOO NULL -- definition (this script's definition; the B8 work states
# values but no percentile routine):
#   - Downlink ONLY, per the frozen direction spec: unit histograms and
#     arm pooled histograms are built from downlink packets only.
#     (Mixing uplink packets into both sides dilutes the statistic with
#     a near-identical small-packet component and understates the null;
#     an earlier draft of this script mixed directions and failed the
#     Tier 1 Mist LOO reproduction -- see validation note in the report.
#     The pooled cross-arm JS was unaffected: it was always per-direction.)
#   - For each unit i of an arm: JS(unit_split_hist, arm_pooled_split
#     hist MINUS unit i's counts) -- leave-one-out, exclusive. Units
#     with an empty pooled remainder (single-unit arm) yield null.
#   - p95 primary = linear interpolation (numpy percentile type-7
#     equivalent); p95_nr = nearest-rank (ceil(0.95*n)-th smallest) is
#     reported alongside as a diagnostic. Tier 1 reproduction
#     discriminates in favour of linear interpolation: it matches all
#     four published Mist fine-bin p95 values to 4 decimals, while
#     nearest-rank misses three of the four at the 4th decimal
#     (A-100B 0.0035 vs 0.0034, A-50B 0.0056 vs 0.0055, B-50B 0.0015
#     vs 0.0014). Exclusive (leave-one-out) likewise beats inclusive
#     (inclusive misses A-100B, A-50B and B-100B at the 4th decimal).
#   - An inclusive variant (unit vs pooled INCLUDING itself) p95 is
#     reported for Mist fine bins only, as a mismatch diagnostic.
#
# FRAGMENTATION: Tier 1 JS code applies no fragmentation special case,
# and neither does this script. Fragmented packets (MF set or fragment
# offset != 0) are counted in diagnostics; if the count is nonzero the
# validation report must flag it, because GSO splitting a fragment
# would be meaningless. Tier 1 lab captures have 0 fragments.
#
# Stdlib only. Zero traffic. Read-only on pcaps (opened 'rb'); the
# script writes nothing except stdout JSON (aggregate numbers only:
# counts, histograms, JS values -- no payloads, no keys, no identities
# beyond the lab addresses given on the command line).
#
# Usage:
#   js-fine.py --mist <pcap> --direct <pcap> --class A|B
#     [--server 10.200.1.2] [--client 10.200.1.1]
#     [--mist-port 24443] [--object-port 18080] [--gap 5.0]
#     [--cluster-report <cluster-5s.py JSON>] [--histograms]
#   --mist and --direct may be the same file (W2-style: both arms in one
#   capture); each file then contributes only its designated arm
#   (Mist = UDP + mist port; direct = TCP + object port).

import argparse
import ipaddress
import json
import math
import struct
import sys
from collections import Counter

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100
PROTO_TCP = 6
PROTO_UDP = 17

# Frozen canonical 9-bin edges (see header).
BINS9 = [0, 100, 200, 400, 600, 800, 1000, 1200, 1400, float("inf")]


def bin9(length):
    for i in range(9):
        if BINS9[i] <= length < BINS9[i + 1]:
            return i
    return 8


def parse_pcap(path):
    """Yield packet dicts for IPv4/IPv6 TCP/UDP packets.

    Fields: ts, ip_len, proto, src, dst, sport, dport, flags (TCP),
    ip_header (20/ihl for v4, 40 for v6), doff (TCP header bytes or 0),
    paylen (TCP payload bytes or None), frag (bool).
    Skipped packets are counted, not yielded.
    """
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("pcap too short for global header")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, frac_div = "<", 1_000_000
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, frac_div = ">", 1_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, frac_div = "<", 1_000_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, frac_div = ">", 1_000_000_000
    else:
        raise ValueError("unsupported pcap magic %r" % magic)
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 1:
        raise ValueError("unsupported linktype %d (need 1/Ethernet)" % linktype)
    off = 24
    skipped = 0
    while off + 16 <= len(data):
        ts_s, ts_f, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        if len(pkt) < 14:
            skipped += 1
            continue
        et = struct.unpack("!H", pkt[12:14])[0]
        o = 14
        if et == ETH_VLAN:
            if len(pkt) < 18:
                skipped += 1
                continue
            et = struct.unpack("!H", pkt[16:18])[0]
            o = 18
        ts = ts_s + ts_f / frac_div
        try:
            if et == ETH_IPV4:
                if len(pkt) < o + 20:
                    skipped += 1
                    continue
                ip = pkt[o:]
                ihl = (ip[0] & 0x0F) * 4
                if ihl < 20 or len(ip) < ihl:
                    skipped += 1
                    continue
                total = struct.unpack("!H", ip[2:4])[0]
                frag_field = struct.unpack("!H", ip[6:8])[0]
                frag = bool(frag_field & 0x3FFF) or bool(frag_field & 0x2000)
                proto = ip[9]
                src = str(ipaddress.IPv4Address(ip[12:16]))
                dst = str(ipaddress.IPv4Address(ip[16:20]))
                header = ihl
                l4 = ip[ihl:]
            elif et == ETH_IPV6:
                if len(pkt) < o + 40:
                    skipped += 1
                    continue
                ip = pkt[o:]
                total = struct.unpack("!H", ip[4:6])[0] + 40
                proto = ip[6]
                frag = False
                src = str(ipaddress.IPv6Address(ip[8:24]))
                dst = str(ipaddress.IPv6Address(ip[24:40]))
                header = 40
                l4 = ip[40:]
            else:
                skipped += 1
                continue
        except (struct.error, IndexError, ValueError):
            skipped += 1
            continue
        if proto not in (PROTO_TCP, PROTO_UDP) or len(l4) < 4:
            skipped += 1
            continue
        sport, dport = struct.unpack("!HH", l4[0:4])
        flags = 0
        doff = 0
        paylen = None
        if proto == PROTO_TCP:
            if len(l4) < 14:
                skipped += 1
                continue
            doff = (l4[12] >> 4) * 4
            flags = l4[13]
            paylen = total - header - doff
        yield {"ts": ts, "ip_len": total, "proto": proto, "src": src,
               "dst": dst, "sport": sport, "dport": dport, "flags": flags,
               "header": header, "doff": doff, "paylen": paylen,
               "frag": frag}
    return skipped


def js_div(p, q):
    """Jensen-Shannon divergence, log2, over aligned probability lists."""
    tot = 0.0
    for pi, qi in zip(p, q):
        m = (pi + qi) / 2.0
        if pi > 0:
            tot += 0.5 * pi * math.log2(pi / m)
        if qi > 0:
            tot += 0.5 * qi * math.log2(qi / m)
    return tot


def probs(counts):
    s = sum(counts)
    if s == 0:
        return [0.0] * len(counts)
    return [c / s for c in counts]


def hist9_of(lengths):
    h = [0] * 9
    for ln in lengths:
        h[bin9(ln)] += 1
    return h


def hist_fine_of(lengths, width):
    idx = [ln // width for ln in lengths]
    n = (max(idx) + 1) if idx else 0
    h = [0] * n
    for i in idx:
        h[i] += 1
    return h


def align(a, b):
    n = max(len(a), len(b))
    return (a + [0] * (n - len(a)), b + [0] * (n - len(b)))


def pct_linear(sorted_vals, p):
    """Linear-interpolation percentile (numpy type-7 equivalent)."""
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = p * (len(sorted_vals) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (rank - lo)


def pct_nearest_rank(sorted_vals, p):
    if not sorted_vals:
        return None
    k = int(math.ceil(p * len(sorted_vals)))
    return sorted_vals[max(0, min(len(sorted_vals) - 1, k - 1))]


def summarise(vals):
    if not vals:
        return {"n": 0, "p95": None, "p95_nearest_rank": None,
                "median": None, "mean": None, "max": None}
    s = sorted(vals)
    n = len(s)
    med = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0
    return {"n": n, "p95": pct_linear(s, 0.95),
            "p95_nearest_rank": pct_nearest_rank(s, 0.95),
            "median": med, "mean": sum(s) / n, "max": s[-1]}


def main():
    ap = argparse.ArgumentParser(description="Stage C fine-grained JS (W-5)")
    ap.add_argument("--mist", required=True, help="pcap holding the Mist arm")
    ap.add_argument("--direct", required=True, help="pcap holding the direct arm")
    ap.add_argument("--class", dest="cls", required=True, choices=["A", "B"])
    ap.add_argument("--server", default="10.200.1.2")
    ap.add_argument("--client", default="10.200.1.1")
    ap.add_argument("--mist-port", type=int, default=24443)
    ap.add_argument("--object-port", type=int, default=18080)
    ap.add_argument("--gap", type=float, default=5.0)
    ap.add_argument("--cluster-report", default=None,
                    help="cluster-5s.py JSON report to cross-check against")
    ap.add_argument("--histograms", action="store_true",
                    help="also emit fine-bin histograms (aggregate counts)")
    args = ap.parse_args()

    def norm_ip(s):
        try:
            return str(ipaddress.ip_address(s))
        except ValueError:
            return s

    server, client = norm_ip(args.server), norm_ip(args.client)

    mist_pkts = []
    direct_pkts = []
    frag = {"mist": 0, "direct": 0}
    skipped = {"mist": 0, "direct": 0}
    for arm, path, want in (("mist", args.mist, "mist"),
                            ("direct", args.direct, "direct")):
        gen = parse_pcap(path)
        try:
            while True:
                p = next(gen)
                hosts = {p["src"], p["dst"]}
                if hosts != {client, server}:
                    continue
                if want == "mist":
                    if p["proto"] == PROTO_UDP and args.mist_port in (p["sport"], p["dport"]):
                        p["dir"] = "down" if p["src"] == server else "up"
                        if p["frag"]:
                            frag["mist"] += 1
                        mist_pkts.append(p)
                else:
                    if p["proto"] == PROTO_TCP and args.object_port in (p["sport"], p["dport"]):
                        p["dir"] = "down" if p["src"] == server else "up"
                        if p["frag"]:
                            frag["direct"] += 1
                        direct_pkts.append(p)
        except StopIteration as e:
            skipped[arm] = e.value or 0

    # ---- Mist units: UDP flow 5-tuple == session (cluster-5s key). ----
    mist_flows = {}
    for p in mist_pkts:
        if p["src"] == client:
            key = (p["sport"], p["dport"])
        else:
            key = (p["dport"], p["sport"])
        mist_flows.setdefault(key, []).append(p)
    mist_units = sorted(mist_flows.values(), key=lambda ps: min(x["ts"] for x in ps))

    # ---- Direct units: cluster-5s 5s-gap rule, verbatim. ----
    direct_pkts.sort(key=lambda p: p["ts"])
    direct_units = []
    for p in direct_pkts:
        if direct_units and p["ts"] - direct_units[-1][-1]["ts"] > args.gap:
            direct_units.append([p])
        elif not direct_units:
            direct_units.append([p])
        else:
            direct_units[-1].append(p)

    # ---- GSO split parameters from the direct arm (arm-global). ----
    doffs = Counter(p["doff"] for p in direct_pkts
                    if p["proto"] == PROTO_TCP and (p["paylen"] or 0) > 0)
    modal_doff = doffs.most_common(1)[0][0] if doffs else 32
    mss_by_header = {20: 1500 - 20 - modal_doff, 40: 1500 - 40 - modal_doff}
    gt1500 = sum(1 for p in direct_pkts if p["ip_len"] > 1500)
    zero_payload_gt1500 = sum(1 for p in direct_pkts
                              if p["ip_len"] > 1500 and (p["paylen"] or 0) <= 0)

    def split_lengths(packets):
        """Tier 1 GSO reconstruction for direct-arm packets."""
        out = []
        for p in packets:
            if p["proto"] == PROTO_TCP and p["ip_len"] > 1500:
                data = p["paylen"] or 0
                if data <= 0:
                    continue  # Tier 1 literal (counted in diagnostics)
                mss = mss_by_header[p["header"]]
                nf, rem = divmod(data, mss)
                for _ in range(nf):
                    out.append(mss + p["header"] + p["doff"])
                if rem:
                    out.append(rem + p["header"] + p["doff"])
            else:
                out.append(p["ip_len"])
        return out

    def orig_lengths(packets):
        return [p["ip_len"] for p in packets]

    # ---- Pooled cross-arm JS, downlink primary + uplink secondary. ----
    pooled = {}
    hist9_out = {}
    fine_hist_out = {}
    for direction in ("down", "up"):
        m_pk = [p for p in mist_pkts if p["dir"] == direction]
        d_pk = [p for p in direct_pkts if p["dir"] == direction]
        m_orig, d_orig = orig_lengths(m_pk), orig_lengths(d_pk)
        # Uniform split rule (TCP > 1500 only): a no-op for Mist UDP.
        m_split = split_lengths(m_pk)
        d_split = split_lengths(d_pk)
        pooled[direction] = {}
        for name, fn in (("9", lambda ls: hist9_of(ls)),
                         ("100", lambda ls: hist_fine_of(ls, 100)),
                         ("50", lambda ls: hist_fine_of(ls, 50))):
            mh_o, dh_o = align(fn(m_orig), fn(d_orig))
            mh_s, dh_s = align(fn(m_split), fn(d_split))
            pooled[direction][name] = {
                "orig": js_div(probs(mh_o), probs(dh_o)),
                "split": js_div(probs(mh_s), probs(dh_s)),
            }
        if direction == "down":
            hist9_out = {"mist": hist9_of(m_orig),
                         "direct": hist9_of(d_orig),
                         "direct_split": hist9_of(d_split)}
            if args.histograms:
                fine_hist_out = {
                    "100": {"mist": hist_fine_of(m_orig, 100),
                            "direct": hist_fine_of(d_orig, 100),
                            "direct_split": hist_fine_of(d_split, 100)},
                    "50": {"mist": hist_fine_of(m_orig, 50),
                           "direct": hist_fine_of(d_orig, 50),
                           "direct_split": hist_fine_of(d_split, 50)},
                }

    # ---- Same-class LOO null (GSO-split, per unit vs arm pooled minus unit). ----
    def loo(arm_units):
        """Per-scheme LOO summaries for one arm's units (GSO-split, downlink only)."""
        unit_hists = {}
        pooled_counts = {}
        for name, width in (("9", None), ("100", 100), ("50", 50)):
            uh = []
            for unit in arm_units:
                sl = split_lengths([p for p in unit if p["dir"] == "down"])
                uh.append(hist9_of(sl) if width is None else hist_fine_of(sl, width))
            unit_hists[name] = uh
            tot = [0] * max((len(h) for h in uh), default=0)
            for h in uh:
                for i, c in enumerate(h):
                    tot[i] += c
            pooled_counts[name] = tot
        out = {}
        for name in ("9", "100", "50"):
            excl, incl = [], []
            tot = pooled_counts[name]
            for h in unit_hists[name]:
                n = max(len(tot), len(h))
                tt = tot + [0] * (n - len(tot))
                hh = h + [0] * (n - len(h))
                rem = [a - b for a, b in zip(tt, hh)]
                if sum(rem) > 0 and sum(h) > 0:
                    excl.append(js_div(probs(hh), probs(rem)))
                if sum(tt) > 0 and sum(h) > 0:
                    incl.append(js_div(probs(hh), probs(tt)))
            summ = summarise(excl)
            if name in ("100", "50"):
                summ["inclusive_p95"] = pct_linear(sorted(incl), 0.95) if incl else None
            out[name] = summ
        return out

    loo_mist = loo(mist_units)
    loo_direct = loo(direct_units)

    report = {
        "tool": "js-fine.py (Stage C W-5)",
        "class": args.cls,
        "mist_pcap": args.mist,
        "direct_pcap": args.direct,
        "gap_s": args.gap,
        "units": {"mist": len(mist_units), "direct": len(direct_units)},
        "packets": {
            "mist": {"down": sum(1 for p in mist_pkts if p["dir"] == "down"),
                     "up": sum(1 for p in mist_pkts if p["dir"] == "up")},
            "direct": {"down": sum(1 for p in direct_pkts if p["dir"] == "down"),
                       "up": sum(1 for p in direct_pkts if p["dir"] == "up")},
        },
        "fragmented_packets": frag,
        "skipped_packets": skipped,
        "gso": {"modal_tcp_doff": modal_doff,
                "mss_ipv4": mss_by_header[20],
                "mss_ipv6": mss_by_header[40],
                "direct_gt1500": gt1500,
                "direct_gt1500_zero_payload_dropped": zero_payload_gt1500,
                "direct_split_emitted": len(split_lengths(direct_pkts))},
        "pooled_js": pooled,
        "hist9_down": hist9_out,
        "loo_split": {"mist": loo_mist, "direct": loo_direct},
    }
    if args.histograms:
        report["hist_fine_down"] = fine_hist_out

    if args.cluster_report:
        with open(args.cluster_report) as f:
            cl = json.load(f)
        m_down = sorted(sum(p["ip_len"] for p in u if p["dir"] == "down")
                        for u in mist_units)
        d_down = sorted(sum(p["ip_len"] for p in u if p["dir"] == "down")
                        for u in direct_units)
        cl_m = sorted(u["down"] for u in cl.get("mist", {}).get("per_unit", []))
        cl_d = sorted(u["down"] for u in cl.get("direct", {}).get("per_unit", []))
        report["cluster_check"] = {
            "mist_units_match": len(mist_units) == cl.get("mist", {}).get("units"),
            "mist_down_multiset_match": m_down == cl_m,
            "direct_units_match": len(direct_units) == cl.get("direct", {}).get("units"),
            "direct_down_multiset_match": d_down == cl_d,
        }

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
