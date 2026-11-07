#!/usr/bin/env python3
# tqv-h3null.py -- True QUIC post-G1 analysis, part 1: fine-grained JS vs
# matched H3 + same-kind (null) distributions + threshold derivation.
#
# CHANGELOG
#   v2 (2026-11-06): fixes the empty-result failure of the VPS run
#     (tqv-post-h3null.json: mist_completed=0/50, direct_completed=0/50,
#     all pooled JS and Mist/direct LOO NO_DATA, threshold 6.60).
#     (a) Removed the exact-equality completion filter
#     (down == CLASS_DOWN): captured ip_len sums include IP/UDP/TCP +
#     QUIC headers and retransmitted bytes, so they can never equal the
#     application byte count; units are now ALL Mist flows / ALL direct
#     clusters (as in analyzer session_lengths and Stage C js-fine.py).
#     Per-unit down bytes are still recorded, and units below the class
#     value are counted (partial/failed) but included.
#     (b) H3 visits: the gap whose unit count is closest to 50 wins
#     (tie-break: --h3-gap, then 5s, then 20s); exactly 50 is no longer
#     required. The flow-level LOO is a diagnostic footnote only and
#     never feeds the threshold.
#     (c) Threshold guard: NOT-DERIVABLE unless all 12 LOO p95 slots
#     (Mist/direct/H3-visit x A/B x 100B/50B) are present; any proposed
#     threshold above 1.0 (the JS maximum) is rejected as impossible.
#     (d) Input pcap paths are recorded as realpaths (symlinks resolved)
#     with size + sha256, and the as-passed value is kept alongside.
#   v1 (2026-11-06): first version; produced empty results on the VPS
#     for the reasons fixed in v2 (see above).
#
# Method provenance (do not change the method without a new freeze):
#   - Packet length = IP total length (IPv4 total_length; IPv6 40 +
#     payload_length). JS = Jensen-Shannon, log base 2, range [0, 1].
#   - GSO split: verbatim Tier 1 / Stage C W-5 practice from
#     nextround/pilot/js-fine.py -- TCP packets with ip_length > 1500 are
#     rebuilt into line packets of MSS (1500 - ip_header - modal_doff,
#     modal_doff = mode of TCP data-offset over payload-carrying TCP
#     packets, fallback 32). Applied uniformly; it is the identity for
#     UDP arms (Mist and H3 never exceed 1500), so for Mist-vs-H3 the
#     split variant equals the original-length variant by construction.
#   - Null (same-kind scatter): leave-one-out, DOWNLINK ONLY, GSO-split.
#     For each unit i of an arm: JS(unit hist, arm pooled hist MINUS
#     unit i). p95 primary = linear interpolation (numpy type-7
#     equivalent); nearest-rank p95 alongside as a diagnostic. This is
#     exactly the B8 derivation (Stage C freeze: GSO-split null p95
#     0.0079-0.0088 -> threshold 0.10 at ~11-13x margin).
#   - Units: Mist = UDP flow 5-tuple == session (cluster-5s / Tier 1
#     convention), ALL flows (no completion filter; see changelog v2).
#     Direct = cluster-5s 5s-gap rule on the serial direct stream, ALL
#     clusters. Units below the class byte value are counted as
#     below_class (partial/failed sessions) but still included, so the
#     pooled/LOO computation matches the matrix analyzer's published
#     SIZE numbers, which used all sessions.
#     H3 = visit units recovered from the G1 pcap by gap clustering the
#     QUIC-only (UDP 443) packet stream; visits are sequential 35s
#     (A) / 120s (B) windows, so a 10s gap separates load bursts.
#     The chosen gap is the one whose unit count is closest to 50
#     (tie-break: --h3-gap, then 5s, then 20s); gaps 5s/20s are
#     reported as sensitivity checks. The flow-level H3 null
#     (UDP 5-tuple to port 443) is a diagnostic only: flows within a
#     visit are correlated and heterogeneous, so it must NOT feed the
#     threshold.
#   - Direction: the threshold-bearing JS is DOWNLINK ONLY (frozen W-5
#     direction spec; mixing uplink dilutes the statistic). The
#     analyzer tqv-analyze.py (js_vs_h3 / js_rows) mixes directions, so
#     its fine-grained rows are a DIFFERENT statistic: this script also
#     prints the mixed-direction values so the two can be compared, but
#     only the downlink-only values are judged against the threshold.
#   - Threshold formula (B8-isomorphic): threshold = ceil to the next
#     0.05 step of (max per-kind LOO p95 across Mist-A/B, direct-A/B,
#     H3-visit-A/B) x 10. The actual multiplier (threshold / max p95) is
#     reported. B8 chose 0.10 from p95 0.0079-0.0088 (11-13x); the same
#     rounding rule reproduces 0.10 from that range. The threshold is
#     NOT-DERIVABLE unless all 12 LOO p95 slots are present, and any
#     proposed value above 1.0 is rejected (JS is bounded by 1.0).
#
# Inputs: SIZE pcaps + completions (Mist/direct) and G1 pcaps.
# Outputs: JSON to --out (full numbers) + a short human summary on stdout.
# Stdlib only. Zero traffic. Read-only on pcaps; writes only --out.
#
# Usage:
#   tqv-h3null.py --mist-a <pcap> --mist-b <pcap>
#     --direct-a <pcap> --direct-b <pcap>
#     --g1-a <pcap> --g1-b <pcap> --out <json>
#     [--server 10.200.1.2] [--client 10.200.1.1]
#     [--mist-port 24443] [--object-port 18080] [--gap 5.0]
#     [--h3-gap 10.0]

import argparse
import hashlib
import ipaddress
import json
import math
import os
import struct
import sys
from collections import Counter

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100
PROTO_TCP = 6
PROTO_UDP = 17

BINS9 = [0, 100, 200, 400, 600, 800, 1000, 1200, 1400, float("inf")]
CLASS_DOWN = {"A": 1032192, "B": 3145728}


def bin9(length):
    for i in range(9):
        if BINS9[i] <= length < BINS9[i + 1]:
            return i
    return 8


def parse_pcap(path):
    """Yield packet dicts. Verbatim parser from js-fine.py (Stage C W-5)."""
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


def gso_params(packets):
    """Modal TCP data-offset + MSS table, arm-global (js-fine.py)."""
    doffs = Counter(p["doff"] for p in packets
                    if p["proto"] == PROTO_TCP and (p["paylen"] or 0) > 0)
    modal_doff = doffs.most_common(1)[0][0] if doffs else 32
    mss = {20: 1500 - 20 - modal_doff, 40: 1500 - 40 - modal_doff}
    return modal_doff, mss


def split_lengths(packets, mss):
    """Tier 1 GSO reconstruction; identity for UDP and <=1500 packets."""
    out = []
    for p in packets:
        if p["proto"] == PROTO_TCP and p["ip_len"] > 1500:
            data = p["paylen"] or 0
            if data <= 0:
                continue
            m = mss[p["header"]]
            nf, rem = divmod(data, m)
            for _ in range(nf):
                out.append(m + p["header"] + p["doff"])
            if rem:
                out.append(rem + p["header"] + p["doff"])
        else:
            out.append(p["ip_len"])
    return out


def loo_null(units, mss):
    """LOO null per band: unit vs arm pooled minus unit, downlink only,
    GSO-split. Units are lists of packet dicts with a 'dir' field."""
    unit_hists = {}
    pooled_counts = {}
    for name, width in (("9", None), ("100", 100), ("50", 50)):
        uh = []
        for unit in units:
            sl = split_lengths([p for p in unit if p["dir"] == "down"], mss)
            uh.append(hist9_of(sl) if width is None else hist_fine_of(sl, width))
        unit_hists[name] = uh
        tot = [0] * max((len(h) for h in uh), default=0)
        for h in uh:
            for i, c in enumerate(h):
                tot[i] += c
        pooled_counts[name] = tot
    out = {}
    for name in ("9", "100", "50"):
        vals = []
        tot = pooled_counts[name]
        for h in unit_hists[name]:
            n = max(len(tot), len(h))
            tt = tot + [0] * (n - len(tot))
            hh = h + [0] * (n - len(h))
            rem = [a - b for a, b in zip(tt, hh)]
            if sum(rem) > 0 and sum(h) > 0:
                vals.append(js_div(probs(hh), probs(rem)))
        out[name] = summarise(vals)
    return out


def js_pooled(a_lengths, b_lengths, width):
    """Pooled JS between two length lists at one band width (None = 9-band).
    Returns None when either side is empty (no data, not a zero)."""
    if not a_lengths or not b_lengths:
        return None
    if width is None:
        ha, hb = hist9_of(a_lengths), hist9_of(b_lengths)
    else:
        ha, hb = hist_fine_of(a_lengths, width), hist_fine_of(b_lengths, width)
    ha, hb = align(ha, hb)
    return js_div(probs(ha), probs(hb))


def derive_threshold(p95s):
    """B8-isomorphic threshold derivation with guards.

    p95s: dict of the 12 slots {class}-{kind}-{band} -> p95 or None,
    kinds = mist/direct/h3_visit, bands = 100/50.
    Returns a dict with status DERIVED or NOT-DERIVABLE. A numeric
    threshold is only proposed when every slot is present; any value
    above 1.0 is impossible (JS is bounded by 1.0) and is rejected.
    The v1 run proposed 6.60 from a partial, flow-level input -- that
    failure mode is what these guards exist to prevent."""
    missing = sorted(k for k, v in p95s.items() if v is None)
    present = [v for v in p95s.values() if v is not None]
    max_p95 = max(present) if present else None
    if missing:
        return {"status": "NOT-DERIVABLE", "proposed_threshold": None,
                "actual_multiplier": None, "max_p95": max_p95,
                "missing_slots": missing,
                "reason": "missing LOO p95 slots: %s" % ", ".join(missing)}
    if max_p95 is None or max_p95 <= 0:
        return {"status": "NOT-DERIVABLE", "proposed_threshold": None,
                "actual_multiplier": None, "max_p95": max_p95,
                "missing_slots": [],
                "reason": ("max_p95 is %s: no scatter measured (all nulls "
                           "zero); threshold cannot be derived" % (max_p95,))}
    proposed = round(math.ceil(max_p95 * 10.0 / 0.05) * 0.05, 2)
    if proposed > 1.0:
        return {"status": "NOT-DERIVABLE", "proposed_threshold": None,
                "actual_multiplier": None, "max_p95": max_p95,
                "missing_slots": [],
                "reason": ("proposed threshold %.2f exceeds the JS maximum "
                           "of 1.0 (max_p95=%.4f); impossible, no threshold "
                           "derived" % (proposed, max_p95))}
    return {"status": "DERIVED", "proposed_threshold": proposed,
            "actual_multiplier": proposed / max_p95, "max_p95": max_p95,
            "missing_slots": [], "reason": None}


def fmt4(x):
    return ("%.4f" % x) if x is not None else "NO_DATA"


def main():
    ap = argparse.ArgumentParser(description="TQV post-G1 fine JS + nulls")
    ap.add_argument("--mist-a", required=True)
    ap.add_argument("--mist-b", required=True)
    ap.add_argument("--direct-a", required=True)
    ap.add_argument("--direct-b", required=True)
    ap.add_argument("--g1-a", required=True)
    ap.add_argument("--g1-b", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--server", default="10.200.1.2")
    ap.add_argument("--client", default="10.200.1.1")
    ap.add_argument("--mist-port", type=int, default=24443)
    ap.add_argument("--object-port", type=int, default=18080)
    ap.add_argument("--gap", type=float, default=5.0)
    ap.add_argument("--h3-gap", type=float, default=10.0)
    args = ap.parse_args()

    def norm_ip(s):
        try:
            return str(ipaddress.ip_address(s))
        except ValueError:
            return s

    server, client = norm_ip(args.server), norm_ip(args.client)
    report = {"tool": "tqv-h3null.py v2 (TQV post-G1 part 1)",
              "method": "B8-isomorphic: downlink-only, GSO-split, LOO null, "
                        "linear-interpolation p95; see file header",
              "classes": {}}

    def input_provenance(path):
        """Real path (symlinks resolved) + size + sha256 of an input pcap,
        with the as-passed value kept alongside for audit."""
        real = os.path.realpath(path)
        try:
            size = os.path.getsize(real)
        except OSError:
            size = None
        sha = None
        try:
            h = hashlib.sha256()
            with open(real, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            sha = h.hexdigest()
        except OSError:
            pass
        return {"arg": path, "realpath": real, "size_bytes": size,
                "sha256": sha}

    report["inputs"] = {
        "mist_a": input_provenance(args.mist_a),
        "mist_b": input_provenance(args.mist_b),
        "direct_a": input_provenance(args.direct_a),
        "direct_b": input_provenance(args.direct_b),
        "g1_a": input_provenance(args.g1_a),
        "g1_b": input_provenance(args.g1_b),
    }
    cls_inputs = {"A": ("mist_a", "direct_a", "g1_a"),
                  "B": ("mist_b", "direct_b", "g1_b")}

    # ---- load arms ----
    def load_lab(path, want, port):
        pkts = []
        frags = 0
        gen = parse_pcap(path)
        try:
            while True:
                p = next(gen)
                if {p["src"], p["dst"]} != {client, server}:
                    continue
                if want == "mist":
                    if p["proto"] == PROTO_UDP and port in (p["sport"], p["dport"]):
                        p["dir"] = "down" if p["src"] == server else "up"
                        if p["frag"]:
                            frags += 1
                        pkts.append(p)
                else:
                    if p["proto"] == PROTO_TCP and port in (p["sport"], p["dport"]):
                        p["dir"] = "down" if p["src"] == server else "up"
                        if p["frag"]:
                            frags += 1
                        pkts.append(p)
        except StopIteration:
            pass
        return pkts, frags

    def mist_units(pkts, cls):
        """ALL UDP flows are units. No completion filter: captured ip_len
        sums include headers and retransmissions and can never equal the
        application byte count (v1's `down == CLASS_DOWN` kept zero
        units). Returns (units, n_below_class, per-unit down sums);
        below-class units are partial/failed sessions, counted but
        still included in the pooled/LOO computation."""
        flows = {}
        for p in pkts:
            key = (p["sport"], p["dport"]) if p["src"] == client else (p["dport"], p["sport"])
            flows.setdefault(key, []).append(p)
        units = sorted(flows.values(), key=lambda ps: min(x["ts"] for x in ps))
        downs = [sum(p["ip_len"] for p in u if p["dir"] == "down") for u in units]
        below = sum(1 for d in downs if d < CLASS_DOWN[cls])
        return units, below, downs

    def direct_units(pkts):
        pkts = sorted(pkts, key=lambda p: p["ts"])
        units = []
        for p in pkts:
            if units and p["ts"] - units[-1][-1]["ts"] > args.gap:
                units.append([p])
            elif not units:
                units.append([p])
            else:
                units[-1].append(p)
        return units

    def h3_visit_units(path):
        """Gap-cluster the QUIC-only stream into visit units. Try gaps
        10s (default), 5s, 20s; the gap whose unit count is CLOSEST to
        50 wins (tie-break: --h3-gap, then 5s, then 20s). Exactly 50 is
        not required. Returns (units, chosen_gap, counts_by_gap)."""
        q = []
        gen = parse_pcap(path)
        try:
            while True:
                p = next(gen)
                if p["proto"] == PROTO_UDP and (p["sport"] == 443 or p["dport"] == 443):
                    p["dir"] = "down" if p["sport"] == 443 else "up"
                    q.append(p)
        except StopIteration:
            pass
        q.sort(key=lambda p: p["ts"])
        counts = {}
        clustered = {}
        for gap in (args.h3_gap, 5.0, 20.0):
            units = []
            for p in q:
                if units and p["ts"] - units[-1][-1]["ts"] > gap:
                    units.append([p])
                elif not units:
                    units.append([p])
                else:
                    units[-1].append(p)
            counts[str(gap)] = len(units)
            clustered[str(gap)] = units
        chosen = None
        best_dist = None
        for gap in (args.h3_gap, 5.0, 20.0):
            dist = abs(counts[str(gap)] - 50)
            if best_dist is None or dist < best_dist:
                best_dist = dist
                chosen = str(gap)
        return q, clustered, counts, chosen

    def h3_flow_units(q):
        flows = {}
        for p in q:
            key = (p["sport"], p["dport"]) if p["dport"] == 443 else (p["dport"], p["sport"])
            flows.setdefault(key, []).append(p)
        return sorted(flows.values(), key=lambda ps: min(x["ts"] for x in ps))

    for cls, mp, dp, gp in (("A", args.mist_a, args.direct_a, args.g1_a),
                            ("B", args.mist_b, args.direct_b, args.g1_b)):
        m_pk, m_frag = load_lab(mp, "mist", args.mist_port)
        d_pk, d_frag = load_lab(dp, "direct", args.object_port)
        m_units, m_below, m_downs = mist_units(m_pk, cls)
        d_units = direct_units(d_pk)
        d_downs = [sum(p["ip_len"] for p in u if p["dir"] == "down") for u in d_units]
        d_below = sum(1 for d in d_downs if d < CLASS_DOWN[cls])
        d_doff, d_mss = gso_params(d_pk)
        # GSO params are arm-global per arm; Mist/H3 are UDP, for which
        # split_lengths is the identity and the MSS table is never
        # consulted. The direct arm uses its own modal doff (js-fine.py
        # convention); UDP_MSS below is a never-consulted placeholder.
        UDP_MSS = {20: 1448, 40: 1428}
        q, h3_clustered, h3_counts, h3_chosen = h3_visit_units(gp)
        h3_units = h3_clustered[h3_chosen]
        h3_flows = h3_flow_units(q)
        # H3 downlink pooled lengths (split == identity for UDP).
        h3_down = [p["ip_len"] for p in q if p["dir"] == "down"]
        h3_all = [p["ip_len"] for p in q]
        m_down = [p["ip_len"] for u in m_units for p in u if p["dir"] == "down"]
        m_all_len = [p["ip_len"] for u in m_units for p in u]
        d_down = [p["ip_len"] for u in d_units for p in u if p["dir"] == "down"]
        # LOO nulls (downlink-only, split).
        null_mist = loo_null(m_units, UDP_MSS)
        null_direct = loo_null(d_units, d_mss)
        null_h3_visit = loo_null(h3_units, UDP_MSS) if h3_units else None
        null_h3_flow = loo_null(h3_flows, UDP_MSS)
        # Pooled cross-arm JS, downlink-only, split.
        vs_h3_down, vs_h3_mixed, vs_direct_down, vs_direct_orig = {}, {}, {}, {}
        for name, width in (("9", None), ("100", 100), ("50", 50)):
            vs_h3_down[name] = js_pooled(
                split_lengths([p for u in m_units for p in u if p["dir"] == "down"], UDP_MSS),
                split_lengths([p for p in q if p["dir"] == "down"], UDP_MSS), width)
            vs_h3_mixed[name] = js_pooled(
                [p["ip_len"] for u in m_units for p in u],
                [p["ip_len"] for p in q], width)
            vs_direct_down[name] = js_pooled(
                split_lengths([p for u in m_units for p in u if p["dir"] == "down"], UDP_MSS),
                split_lengths([p for u in d_units for p in u if p["dir"] == "down"], d_mss), width)
            vs_direct_orig[name] = js_pooled(
                [p["ip_len"] for u in m_units for p in u if p["dir"] == "down"],
                [p["ip_len"] for u in d_units for p in u if p["dir"] == "down"], width)
        # Per-unit Mist vs H3 pooled (downlink-only, split).
        per_unit = {}
        h3_down_hist = {}
        for name, width in (("100", 100), ("50", 50)):
            hh = hist_fine_of(h3_down, width)
            vals = []
            for u in m_units:
                sl = split_lengths([p for p in u if p["dir"] == "down"], UDP_MSS)
                if not sl:
                    continue
                uh = hist_fine_of(sl, width)
                a, b = align(uh, hh)
                vals.append(js_div(probs(a), probs(b)))
            per_unit[name] = summarise(vals)
        # Gap diagnostics for the H3 visit clustering.
        gaps = []
        if len(q) > 1:
            qs = sorted(p["ts"] for p in q)
            gaps = [round(b - a, 1) for a, b in zip(qs, qs[1:]) if b - a > 1.0]
        report["classes"][cls] = {
            "mist_pcap": report["inputs"][cls_inputs[cls][0]]["realpath"],
            "mist_pcap_arg": mp,
            "direct_pcap": report["inputs"][cls_inputs[cls][1]]["realpath"],
            "direct_pcap_arg": dp,
            "g1_pcap": report["inputs"][cls_inputs[cls][2]]["realpath"],
            "g1_pcap_arg": gp,
            "units": {"mist_flows": len(m_units), "mist_units": len(m_units),
                      "mist_below_class": m_below,
                      "mist_down_bytes": summarise(m_downs),
                      "direct_clusters": len(d_units),
                      "direct_units": len(d_units),
                      "direct_below_class": d_below,
                      "direct_down_bytes": summarise(d_downs),
                      "h3_visit_units_by_gap": h3_counts,
                      "h3_visit_gap_chosen": h3_chosen,
                      "h3_visit_units": len(h3_units),
                      "h3_flows": len(h3_flows)},
            "packets": {"mist_down": len(m_down), "mist_all": len(m_all_len),
                        "direct_down": len(d_down),
                        "h3_quic_down": len(h3_down), "h3_quic_all": len(h3_all)},
            "fragments": {"mist": m_frag, "direct": d_frag},
            "gso": {"direct_modal_doff": d_doff,
                    "direct_mss_ipv4": d_mss[20], "direct_mss_ipv6": d_mss[40],
                    "direct_gt1500": sum(1 for p in d_pk if p["ip_len"] > 1500)},
            "h3_gap_seconds_over_1s": {"n": len(gaps),
                                       "median": pct_linear(sorted(gaps), 0.50) if gaps else None,
                                       "min": min(gaps) if gaps else None,
                                       "max": max(gaps) if gaps else None},
            "pooled_js_vs_h3_downlink_split": vs_h3_down,
            "pooled_js_vs_h3_mixed_direction_raw": vs_h3_mixed,
            "pooled_js_vs_direct_downlink_split": vs_direct_down,
            "pooled_js_vs_direct_downlink_orig": vs_direct_orig,
            "per_unit_mist_vs_h3_downlink_split": per_unit,
            "loo_null_split_downlink": {
                "mist": null_mist, "direct": null_direct,
                "h3_visit": null_h3_visit, "h3_flow": null_h3_flow,
                "h3_flow_note": "diagnostic only: flows within a visit are "
                                "correlated and heterogeneous; the flow-level "
                                "LOO never feeds the threshold"},
        }

    # ---- threshold derivation (B8-isomorphic, guarded) ----
    p95s = {}
    for cls in ("A", "B"):
        c = report["classes"][cls]["loo_null_split_downlink"]
        for kind in ("mist", "direct"):
            for band in ("100", "50"):
                p95s["%s-%s-%s" % (cls, kind, band)] = c[kind][band]["p95"]
        # H3-visit only: the flow-level LOO is a diagnostic and never
        # feeds the threshold (v1 fell back to it and proposed 6.60).
        hv = c["h3_visit"]
        for band in ("100", "50"):
            p95s["%s-h3_visit-%s" % (cls, band)] = (
                hv[band]["p95"] if hv is not None else None)
    td = derive_threshold(p95s)
    max_p95 = td["max_p95"]
    proposed = td["proposed_threshold"]
    multiplier = td["actual_multiplier"]
    report["threshold_derivation"] = {
        "status": td["status"],
        "per_kind_loo_p95": p95s,
        "missing_kinds": td["missing_slots"],
        "max_p95": max_p95,
        "formula": "threshold = ceil(max_p95 * 10 / 0.05) * 0.05",
        "proposed_threshold": proposed,
        "actual_multiplier": multiplier,
        "degenerate": td["reason"] if td["status"] == "NOT-DERIVABLE" else None,
        "reason": td["reason"],
        "h3_unit_used": "visit",
        "h3_flow_note": "flow-level LOO is a diagnostic only; it never "
                        "feeds the threshold",
        "excluded": "original-length (raw) variant: known segment-length-"
                    "variance artifact, footnote only, never the derivation basis",
    }
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    # ---- human summary ----
    print("=== TQV-H3NULL SUMMARY ===")
    for cls in ("A", "B"):
        c = report["classes"][cls]
        print("class %s: mist_units=%d (below_class=%d) direct_units=%d "
              "(below_class=%d) h3_visit_units=%d (gap %s, counts %s) "
              "h3_flows=%d" % (
                  cls, c["units"]["mist_units"], c["units"]["mist_below_class"],
                  c["units"]["direct_units"], c["units"]["direct_below_class"],
                  c["units"]["h3_visit_units"],
                  c["units"]["h3_visit_gap_chosen"],
                  c["units"]["h3_visit_units_by_gap"],
                  c["units"]["h3_flows"]))
        print("  pooled JS vs H3 downlink/split: 9=%s 100B=%s 50B=%s" % (
            fmt4(c["pooled_js_vs_h3_downlink_split"]["9"]),
            fmt4(c["pooled_js_vs_h3_downlink_split"]["100"]),
            fmt4(c["pooled_js_vs_h3_downlink_split"]["50"])))
        print("  pooled JS vs H3 mixed/raw:     9=%s 100B=%s 50B=%s" % (
            fmt4(c["pooled_js_vs_h3_mixed_direction_raw"]["9"]),
            fmt4(c["pooled_js_vs_h3_mixed_direction_raw"]["100"]),
            fmt4(c["pooled_js_vs_h3_mixed_direction_raw"]["50"])))
        print("  pooled JS vs direct down/split: 9=%s 100B=%s 50B=%s" % (
            fmt4(c["pooled_js_vs_direct_downlink_split"]["9"]),
            fmt4(c["pooled_js_vs_direct_downlink_split"]["100"]),
            fmt4(c["pooled_js_vs_direct_downlink_split"]["50"])))
        print("  per-unit Mist vs H3 (100B): median=%s p95=%s max=%s n=%d" % (
            fmt4(c["per_unit_mist_vs_h3_downlink_split"]["100"]["median"]),
            fmt4(c["per_unit_mist_vs_h3_downlink_split"]["100"]["p95"]),
            fmt4(c["per_unit_mist_vs_h3_downlink_split"]["100"]["max"]),
            c["per_unit_mist_vs_h3_downlink_split"]["100"]["n"]))
        for kind in ("mist", "direct", "h3_visit", "h3_flow"):
            n = c["loo_null_split_downlink"][kind]
            if n is None:
                print("  LOO null %s: NOT-COMPUTED" % kind)
            else:
                print("  LOO null %s%s: 100B p95=%s 50B p95=%s (n=%d)" % (
                    kind, " (diagnostic only)" if kind == "h3_flow" else "",
                    fmt4(n["100"]["p95"]), fmt4(n["50"]["p95"]),
                    n["100"]["n"]))
    td = report["threshold_derivation"]
    print("threshold: status=%s max_p95=%s proposed=%s multiplier=%s missing=%s" % (
        td["status"],
        fmt4(max_p95),
        ("%.2f" % proposed) if proposed is not None else "NONE",
        ("%.1fx" % multiplier) if multiplier is not None else "NONE",
        td["missing_kinds"]))
    if td["degenerate"]:
        print("threshold degenerate: %s" % td["degenerate"])
    print("full JSON: %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
