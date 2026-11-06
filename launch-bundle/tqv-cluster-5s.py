#!/usr/bin/env python3
# cluster-5s.py -- Stage C analysis-side 5-second isolation clustering (C4).
#
# Reads a client-side veth pcap (tcpdump -s 160, LINKTYPE_ETHERNET) and
# splits it into per-session units, following the Tier 1 convention
# (analyze2.py cluster_by_start, gap=5.0) with one change made possible
# by the d09e7b95 runner: the direct arm is now SERIAL with 6s silence
# between sessions, so 5s-gap clustering on the direct packet stream
# yields SESSIONS (Tier 1 concurrent direct sessions only yielded
# batches). Mist sessions are concurrent, so they are clustered by
# UDP flow 5-tuple (flow == session, exact, Tier 1 convention).
#
# Verification (C4, order-free -- no flow/session order matching):
#   - unit count == launched count (from --completions or --expected-*)
#   - successful units have down_bytes == class value (deterministic
#     load: A 1032192 / B 3145728, overridable with --expected-down)
#   - successful direct units have SYN count == objects + 1, where the
#     +1 is the page-fetch connection (each fetch uses a fresh
#     Transport with DisableKeepAlives, so each fetch == one TCP
#     connection; page fetch happens once per session).
# Byte caliber: IP total_length sums, same as byte-watch.py
# (captured bytes may be snaplen-truncated; the header field survives).
# Stdlib only. Zero traffic, read-only on the pcap.
#
# Usage:
#   cluster-5s.py <pcap> --class A|B [--server 10.200.1.2]
#     [--client 10.200.1.1] [--mist-port 24443] [--object-port 18080]
#     [--gap 5.0] [--objects N] [--expected-down N]
#     [--completions <file>] [--sessions <file>]
#   --class sets the default objects (A 15, B 12) and down_bytes
#   (A 1032192, B 3145728); explicit flags override. --completions is
#   the runner's <window>-completions.txt (lines "<arm> <id> ok|fail").
#   Exit 0 iff every performed check passes; skipped checks (no data
#   source) are reported, not silently passed.

import argparse
import ipaddress
import json
import struct
import sys

ETHERTYPE_IPv4 = 0x0800
ETHERTYPE_IPv6 = 0x86DD
PROTO_TCP = 6
PROTO_UDP = 17

CLASS_OBJECTS = {"A": 15, "B": 12}
CLASS_DOWN = {"A": 1032192, "B": 3145728}


def parse_pcap(path):
    """Yield (ts_float, ip_total_len, proto, src, dst, sport, dport,
    tcp_flags) for IPv4/IPv6 packets. Skipped packets are counted."""
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
        ts = ts_s + ts_f / frac_div
        try:
            if et == ETHERTYPE_IPv4:
                if len(pkt) < 34:
                    skipped += 1
                    continue
                ip = pkt[14:]
                ihl = (ip[0] & 0x0F) * 4
                total = struct.unpack("!H", ip[2:4])[0]
                proto = ip[9]
                src = str(ipaddress.IPv4Address(ip[12:16]))
                dst = str(ipaddress.IPv4Address(ip[16:20]))
                l4 = ip[ihl:]
            elif et == ETHERTYPE_IPv6:
                if len(pkt) < 54:
                    skipped += 1
                    continue
                ip = pkt[14:]
                total = struct.unpack("!H", ip[4:6])[0] + 40
                proto = ip[6]
                src = str(ipaddress.IPv6Address(ip[8:24]))
                dst = str(ipaddress.IPv6Address(ip[24:40]))
                l4 = ip[40:]
            else:
                skipped += 1
                continue
        except (struct.error, IndexError):
            skipped += 1
            continue
        if proto not in (PROTO_TCP, PROTO_UDP) or len(l4) < 4:
            skipped += 1
            continue
        sport, dport = struct.unpack("!HH", l4[0:4])
        flags = 0
        if proto == PROTO_TCP and len(l4) >= 14:
            flags = l4[13]
        yield ts, total, proto, src, dst, sport, dport, flags
    # Malformed/truncated packets are skipped silently (tcpdump output
    # is well-formed in practice); only well-formed IP packets yield.


def main():
    ap = argparse.ArgumentParser(description="Stage C 5s-gap session clustering (C4)")
    ap.add_argument("pcap")
    ap.add_argument("--class", dest="cls", required=True, choices=["A", "B"])
    ap.add_argument("--server", default="10.200.1.2")
    ap.add_argument("--client", default="10.200.1.1")
    ap.add_argument("--mist-port", type=int, default=24443)
    ap.add_argument("--object-port", type=int, default=18080)
    ap.add_argument("--gap", type=float, default=5.0)
    ap.add_argument("--objects", type=int, default=None)
    ap.add_argument("--expected-down", type=int, default=None)
    ap.add_argument("--completions", default=None)
    ap.add_argument("--expected-mist", type=int, default=None)
    ap.add_argument("--expected-direct", type=int, default=None)
    args = ap.parse_args()

    objects = args.objects if args.objects is not None else CLASS_OBJECTS[args.cls]
    exp_down = args.expected_down if args.expected_down is not None else CLASS_DOWN[args.cls]
    exp_syn = objects + 1  # page-fetch connection + one per object

    def norm_ip(s):
        try:
            return str(ipaddress.ip_address(s))
        except ValueError:
            return s

    server, client = norm_ip(args.server), norm_ip(args.client)

    launched = {"mist": 0, "direct": 0}
    ok = {"mist": 0, "direct": 0}
    if args.completions:
        with open(args.completions) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[0] in launched:
                    launched[parts[0]] += 1
                    if parts[2] == "ok":
                        ok[parts[0]] += 1
    if args.expected_mist is not None:
        launched["mist"] = args.expected_mist
    if args.expected_direct is not None:
        launched["direct"] = args.expected_direct

    mist_flows = {}
    direct_pkts = []
    skipped = 0
    total_pkts = 0
    for ts, total, proto, src, dst, sport, dport, flags in parse_pcap(args.pcap):
        total_pkts += 1
        hosts = {src, dst}
        if hosts != {client, server}:
            continue
        if proto == PROTO_UDP and args.mist_port in (sport, dport):
            # Flow key: (client port, server port); client side is the
            # endpoint whose IP == client addr.
            cport = sport if src == client else dport
            sport_ = dport if src == client else sport
            key = (cport, sport_)
            fl = mist_flows.setdefault(key, {"pkts": 0, "down": 0, "up": 0,
                                             "first": ts, "last": ts})
            fl["pkts"] += 1
            fl["last"] = ts
            if src == server:
                fl["down"] += total
            else:
                fl["up"] += total
        elif proto == PROTO_TCP and args.object_port in (sport, dport):
            direct_pkts.append((ts, total, src, flags))
    # NOTE: parse_pcap is a generator; its trailing `skipped` count is
    # not recoverable here (generators return it via StopIteration).
    # Skipped-packet accounting is therefore omitted from the report;
    # the parser only yields well-formed IP packets.

    # Direct sessions: split the timestamp-ordered packet stream at
    # silence gaps > threshold. Sessions are serial, so no packet
    # falls in a silence gap; every packet belongs to exactly one
    # session span.
    direct_pkts.sort(key=lambda p: p[0])
    clusters = []
    for ts, total, src, flags in direct_pkts:
        if clusters and ts - clusters[-1]["last"] > args.gap:
            clusters.append({"pkts": 0, "syn": 0, "down": 0, "up": 0,
                             "first": ts, "last": ts})
        if not clusters:
            clusters.append({"pkts": 0, "syn": 0, "down": 0, "up": 0,
                             "first": ts, "last": ts})
        cl = clusters[-1]
        cl["pkts"] += 1
        cl["last"] = ts
        if flags & 0x02 and not (flags & 0x10):
            cl["syn"] += 1
        if src == server:
            cl["down"] += total
        else:
            cl["up"] += total

    mist_units = sorted(mist_flows.values(), key=lambda fl: fl["first"])
    mist_down_ok = sum(1 for fl in mist_units if fl["down"] == exp_down)
    dir_syn_ok = sum(1 for cl in clusters if cl["syn"] == exp_syn)
    dir_down_ok = sum(1 for cl in clusters if cl["down"] == exp_down)

    checks = []
    def check(name, cond, detail):
        checks.append({"name": name, "pass": bool(cond), "detail": detail})

    if launched["mist"]:
        check("mist_unit_count", len(mist_units) == launched["mist"],
              "flows=%d launched=%d" % (len(mist_units), launched["mist"]))
        check("mist_down_match", mist_down_ok == ok["mist"],
              "down==%d: %d flows, ok=%d" % (exp_down, mist_down_ok, ok["mist"]))
    else:
        checks.append({"name": "mist_unit_count", "pass": None,
                       "detail": "skipped: no completions/expected count"})
    if launched["direct"]:
        check("direct_unit_count", len(clusters) == launched["direct"],
              "clusters=%d launched=%d" % (len(clusters), launched["direct"]))
        check("direct_syn_match", dir_syn_ok == ok["direct"],
              "syn==%d: %d clusters, ok=%d" % (exp_syn, dir_syn_ok, ok["direct"]))
        check("direct_down_match", dir_down_ok == ok["direct"],
              "down==%d: %d clusters, ok=%d" % (exp_down, dir_down_ok, ok["direct"]))
    else:
        checks.append({"name": "direct_unit_count", "pass": None,
                       "detail": "skipped: no completions/expected count"})

    performed = [c for c in checks if c["pass"] is not None]
    verdict = all(c["pass"] for c in performed) if performed else None
    report = {
        "tool": "cluster-5s.py (C4)",
        "pcap": args.pcap,
        "class": args.cls,
        "gap_threshold_s": args.gap,
        "expected_objects_per_session": objects,
        "expected_syn_per_session": exp_syn,
        "expected_down_bytes": exp_down,
        "packets_seen": total_pkts,
        "mist": {
            "units": len(mist_units),
            "launched": launched["mist"],
            "ok": ok["mist"],
            "down_match_units": mist_down_ok,
            "per_unit": [{"down": fl["down"], "up": fl["up"],
                          "pkts": fl["pkts"],
                          "duration_s": round(fl["last"] - fl["first"], 3)}
                         for fl in mist_units],
        },
        "direct": {
            "units": len(clusters),
            "launched": launched["direct"],
            "ok": ok["direct"],
            "syn_match_units": dir_syn_ok,
            "down_match_units": dir_down_ok,
            "per_unit": [{"syn": cl["syn"], "down": cl["down"], "up": cl["up"],
                          "pkts": cl["pkts"],
                          "duration_s": round(cl["last"] - cl["first"], 3)}
                         for cl in clusters],
        },
        "checks": checks,
        "verdict": ("PASS" if verdict else
                    "FAIL" if verdict is False else "PARTIAL"),
        "notes": [
            "Mist units keyed by UDP flow 5-tuple (flow == session).",
            "Direct units split at silence gaps > %.1fs (d09e7b95 serial "
            "+ 6s silence); Tier 1 concurrent direct sessions only "
            "yielded batches under the same rule." % args.gap,
            "SYN count per direct unit == objects + 1 (page-fetch "
            "connection); cross-check against sessions.jsonl objects "
            "field if SYN counts deviate.",
            "Byte caliber: IP total_length sums (snaplen-safe).",
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
