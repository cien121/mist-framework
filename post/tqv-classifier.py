#!/usr/bin/env python3
# tqv-classifier.py -- True QUIC post-G1 analysis, part 2: L3 classifier
# evaluation (Q15) on the Mist-vs-H3 pool.
#
# What this script does and does NOT do:
#   - It EXTRACTS the Q15 named feature set from the retained pcaps and
#     EVALUATES the named classifier families on a session-disjoint
#     holdout. It does NOT judge L3: the holdout is ~17 sessions per arm
#     per class, far below M4's >=50, and the single-window collection
#     cannot satisfy time-disjoint holdout. The output is therefore
#     numbers + CIs + p-values only, labelled NOT-JUDGED. Any report
#     that writes a PASS/FAIL verdict from these numbers is wrong.
#   - Strongest-attacker rule (design §1.1 item 1): the reported
#     classifier basis is the holdout AUC of the STRONGEST available
#     family, never the weakest. Volume-only AUC is reported alongside:
#     if the volume-only model is already significantly separable, the
#     round's classifier evaluation is VOID (load mismatch = experiment
#     design failure, not a Mist pass/fail).
#
# Feature set (design §1.1 item 2, per unit, downlink length primary):
#   length: downlink 9-band proportions (9) + downlink 50B-bin
#     proportions for 1200-1499 (6) + mean down/up length (2);
#   direction ratio up_bytes/down_bytes (1);
#   burst: median packets per burst, median inter-burst gap (log),
#     burst count (3; bursts = gaps > 50ms inside the unit);
#   timing: log(p10/p50/p90 downlink inter-arrival / min-gap proxy)
#     (3; the min-gap proxy is the per-unit RTT stand-in, recorded);
#   multiplexing: flow count, mean packets per flow, lifetime log (3).
#   Volume-only model: total down bytes, total packets, lifetime (3).
# Forbidden features are never built: no decrypted fields, no SNI, no
# domain, no destination IP (site-family labels are used ONLY to define
# the site-holdout split, never as features), no absolute timestamps,
# no session IDs, no port numbers, no handshake private extensions.
#
# Units: Mist = UDP flow 5-tuple == session, completed only
# (down_bytes == class value). H3 = visit units recovered by the same
# gap clustering as tqv-h3null.py (10s default, validated count == 50);
# visit j (time order, 1-based) maps to the frozen site list
# (g1-site-list.txt sha 09ab18fe...) position (j-1) % 9, hence its site
# family (cloudflare/github/google). If the visit count is not 50, the
# site holdout is NOT-COMPUTED (no reliable visit->URL mapping).
#
# Splits (per class, never mixed): main random holdout train:test 2:1,
# session-disjoint, seed 20261106; site holdout 3 folds (one H3 family
# held out per fold, Mist test = random 1/3, seed 1000+fold).
# Models: logistic regression (L2, standardized on train, stdlib
# gradient descent, frozen hyperparameters) + volume-only LR; random
# forest + HistGradientBoosting IF sklearn imports, else recorded
# NOT-AVAILABLE (missing dependency) and the strongest-attacker claim
# is limited to the available families.
# Metrics: holdout AUC + DeLong 95% CI + permutation p (>=1000 perms,
# fixed seed). Pass structure (design §1.1 item 5, only if holdout n
# were adequate): AUC <= 0.55 and CI upper <= 0.60 and p > 0.05.
# Epsilon is NOT set by this script.
#
# Stdlib only except for the optional sklearn import. Zero traffic.
# Read-only on pcaps; writes only --out.
#
# Usage:
#   tqv-classifier.py --mist-a <pcap> --mist-b <pcap>
#     --g1-a <pcap> --g1-b <pcap> --out <json>
#     [--server 10.200.1.2] [--client 10.200.1.1] [--mist-port 24443]
#     [--gap 5.0] [--h3-gap 10.0] [--perms 1000]

import argparse
import ipaddress
import json
import math
import random
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
SEED = 20261106
# Frozen G1 site list (g1-site-list.txt, sha 09ab18fe...), in order.
# Visit j (1-based, time order) -> list[(j-1) % 9]; family per position.
SITE_FAMILIES = ["cloudflare", "cloudflare", "cloudflare",
                 "github", "github", "github",
                 "google", "google", "google"]

try:
    from sklearn.ensemble import (HistGradientBoostingClassifier,
                                  RandomForestClassifier)
    SKLEARN = True
except Exception:
    SKLEARN = False


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


def auc_score(scores, labels):
    """Mann-Whitney AUC, ties count 0.5. labels: 1 = Mist, 0 = H3."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return None
    tot = 0.0
    for p in pos:
        for q in neg:
            tot += 1.0 if p > q else (0.5 if p == q else 0.0)
    return tot / (len(pos) * len(neg))


def delong_ci(scores, labels):
    """DeLong 95% CI for AUC. Returns (auc, lo, hi, se)."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    m, n = len(pos), len(neg)
    if m < 2 or n < 2:
        a = auc_score(scores, labels)
        return a, None, None, None

    def psi(a, b):
        return 1.0 if a > b else (0.5 if a == b else 0.0)

    v10 = [sum(psi(p, q) for q in neg) / n for p in pos]
    v01 = [sum(psi(p, q) for p in pos) / m for q in neg]
    auc = sum(v10) / m

    def var(v):
        mu = sum(v) / len(v)
        return sum((x - mu) ** 2 for x in v) / (len(v) - 1)

    se = math.sqrt(var(v10) / m + var(v01) / n)
    return auc, max(0.0, auc - 1.96 * se), min(1.0, auc + 1.96 * se), se


def perm_p(scores, labels, n_perm, seed):
    """One-sided permutation p: P(permuted AUC >= observed AUC)."""
    obs = auc_score(scores, labels)
    if obs is None:
        return None
    rng = random.Random(seed)
    labs = list(labels)
    cnt = 0
    for _ in range(n_perm):
        rng.shuffle(labs)
        a = auc_score(scores, labs)
        if a is not None and a >= obs:
            cnt += 1
    return (cnt + 1) / (n_perm + 1)


def train_lr(X, y, l2=1.0, lr=0.1, iters=3000):
    """Full-batch gradient descent logistic regression, L2 on weights."""
    n, d = len(X), len(X[0])
    w = [0.0] * d
    b = 0.0
    for _ in range(iters):
        gw = [0.0] * d
        gb = 0.0
        for xi, yi in zip(X, y):
            z = b + sum(wj * xj for wj, xj in zip(w, xi))
            z = max(-30.0, min(30.0, z))
            p = 1.0 / (1.0 + math.exp(-z))
            err = p - yi
            for j in range(d):
                gw[j] += err * xi[j]
            gb += err
        for j in range(d):
            w[j] -= lr * (gw[j] / n + l2 * w[j] / n)
        b -= lr * gb / n
    return w, b


def predict_lr(w, b, X):
    out = []
    for xi in X:
        z = b + sum(wj * xj for wj, xj in zip(w, xi))
        z = max(-30.0, min(30.0, z))
        out.append(1.0 / (1.0 + math.exp(-z)))
    return out


def standardize(X_train, X_test):
    d = len(X_train[0])
    mu, sd = [], []
    for j in range(d):
        col = [x[j] for x in X_train]
        m = sum(col) / len(col)
        v = sum((c - m) ** 2 for c in col) / len(col)
        mu.append(m)
        sd.append(math.sqrt(v) if v > 0 else 1.0)
    def tf(X):
        return [[(x[j] - mu[j]) / sd[j] for j in range(d)] for x in X]
    return tf(X_train), tf(X_test)


def features_for_unit(pkts, is_mist):
    """27-feature vector + 3 volume features for one unit (list of packet
    dicts with a 'dir' field; Mist units are single flows, H3 units are
    visits spanning several flows)."""
    pkts = sorted(pkts, key=lambda p: p["ts"])
    down = [p for p in pkts if p["dir"] == "down"]
    up = [p for p in pkts if p["dir"] == "up"]
    down_bytes = sum(p["ip_len"] for p in down)
    up_bytes = sum(p["ip_len"] for p in up)
    n_down, n_up = len(down), len(up)
    # length: 9-band downlink proportions
    h9 = [0] * 9
    for p in down:
        h9[bin9(p["ip_len"])] += 1
    f9 = [c / n_down if n_down else 0.0 for c in h9]
    # length: 50B bins 1200-1499 downlink proportions
    f50 = [0.0] * 6
    for p in down:
        ln = p["ip_len"]
        if 1200 <= ln < 1500:
            f50[(ln - 1200) // 50] += 1
    f50 = [c / n_down if n_down else 0.0 for c in f50]
    mean_down = (down_bytes / n_down) if n_down else 0.0
    mean_up = (up_bytes / n_up) if n_up else 0.0
    ratio = (up_bytes / down_bytes) if down_bytes else 0.0
    # bursts: gap > 50ms inside the unit (all directions)
    bursts = []
    for p in pkts:
        if bursts and p["ts"] - bursts[-1][-1]["ts"] > 0.05:
            bursts.append([p])
        elif not bursts:
            bursts.append([p])
        else:
            bursts[-1].append(p)
    per_burst = [len(b) for b in bursts]
    med_per_burst = pct_linear(sorted(per_burst), 0.5) if per_burst else 0.0
    idle = [bursts[i + 1][0]["ts"] - bursts[i][-1]["ts"] for i in range(len(bursts) - 1)]
    med_idle_log = math.log(max(pct_linear(sorted(idle), 0.5), 1e-6)) if idle else 0.0
    n_bursts = len(bursts)
    # timing: downlink inter-arrival quantiles / min-gap proxy
    ts_d = sorted(p["ts"] for p in down)
    gaps = [b - a for a, b in zip(ts_d, ts_d[1:])]
    if len(gaps) >= 2:
        proxy = max(min(gaps), 1e-6)
        t_feats = [math.log(max(pct_linear(sorted(gaps), q), 1e-6) / proxy)
                   for q in (0.10, 0.50, 0.90)]
        rtt_proxy = proxy
    else:
        t_feats = [0.0, 0.0, 0.0]
        rtt_proxy = None
    # multiplexing: flow count, mean packets per flow, lifetime
    flows = {}
    for p in pkts:
        key = (p["src"], p["sport"], p["dst"], p["dport"])
        flows.setdefault(key, 0)
        flows[key] += 1
    n_flows = len(flows)
    mean_per_flow = (len(pkts) / n_flows) if n_flows else 0.0
    life = (pkts[-1]["ts"] - pkts[0]["ts"]) if len(pkts) > 1 else 0.0
    life_log = math.log(max(life, 1e-3))
    feats = (f9 + f50 + [mean_down, mean_up, ratio, med_per_burst,
                         med_idle_log, float(n_bursts)] + t_feats +
             [float(n_flows), mean_per_flow, life_log])
    vol = [float(down_bytes), float(len(pkts)), life_log]
    return feats, vol, {"rtt_proxy_s": rtt_proxy, "n_flows": n_flows,
                        "life_s": life}


def evaluate(scores, labels, n_perm):
    auc, lo, hi, se = delong_ci(scores, labels)
    p = perm_p(scores, labels, n_perm, SEED)
    return {"auc": auc, "delong_ci95": [lo, hi], "delong_se": se,
            "perm_p": p, "n_perm": n_perm,
            "n_test": len(labels), "n_pos_test": sum(labels),
            "n_neg_test": len(labels) - sum(labels)}


def main():
    ap = argparse.ArgumentParser(description="TQV L3 classifier evaluation")
    ap.add_argument("--mist-a", required=True)
    ap.add_argument("--mist-b", required=True)
    ap.add_argument("--g1-a", required=True)
    ap.add_argument("--g1-b", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--server", default="10.200.1.2")
    ap.add_argument("--client", default="10.200.1.1")
    ap.add_argument("--mist-port", type=int, default=24443)
    ap.add_argument("--gap", type=float, default=5.0)
    ap.add_argument("--h3-gap", type=float, default=10.0)
    ap.add_argument("--perms", type=int, default=1000)
    args = ap.parse_args()

    def norm_ip(s):
        try:
            return str(ipaddress.ip_address(s))
        except ValueError:
            return s

    server, client = norm_ip(args.server), norm_ip(args.client)

    def load_mist(path, cls):
        pkts = []
        gen = parse_pcap(path)
        try:
            while True:
                p = next(gen)
                if {p["src"], p["dst"]} != {client, server}:
                    continue
                if p["proto"] == PROTO_UDP and args.mist_port in (p["sport"], p["dport"]):
                    p["dir"] = "down" if p["src"] == server else "up"
                    pkts.append(p)
        except StopIteration:
            pass
        flows = {}
        for p in pkts:
            key = (p["sport"], p["dport"]) if p["src"] == client else (p["dport"], p["sport"])
            flows.setdefault(key, []).append(p)
        units = sorted(flows.values(), key=lambda ps: min(x["ts"] for x in ps))
        kept = []
        for u in units:
            down = sum(p["ip_len"] for p in u if p["dir"] == "down")
            if down == CLASS_DOWN[cls]:
                kept.append(u)
        return units, kept

    def load_h3(path):
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
        for gap in (args.h3_gap, 5.0, 20.0):
            if counts[str(gap)] == 50:
                chosen = str(gap)
                break
        units = clustered[chosen] if chosen else None
        fams = None
        if units is not None:
            fams = [SITE_FAMILIES[i % 9] for i in range(len(units))]
        return q, units, counts, chosen, fams

    report = {"tool": "tqv-classifier.py (TQV post-G1 part 2)",
              "method": "Q15: 3 model families (LR stdlib + RF/GBM if sklearn), "
                        "named 27-feature set, train:test 2:1 session-disjoint, "
                        "site holdout secondary, DeLong 95% CI + permutation p",
              "verdict": "NOT-JUDGED: holdout ~17/arm/class is far below M4 "
                         ">=50, and single-window collection cannot satisfy "
                         "time-disjoint holdout. Numbers + CI + p only; any "
                         "PASS/FAIL written from them is wrong.",
              "sklearn_available": SKLEARN,
              "classes": {}}

    for cls, mp, gp in (("A", args.mist_a, args.g1_a),
                        ("B", args.mist_b, args.g1_b)):
        m_all, m_kept = load_mist(mp, cls)
        q, h3_units, h3_counts, h3_chosen, h3_fams = load_h3(gp)
        if h3_units is None:
            report["classes"][cls] = {
                "error": "H3 visit clustering did not yield 50 units "
                         "(counts by gap: %s); classifier not run for "
                         "this class" % (h3_counts,),
                "mist_flows": len(m_all), "mist_completed": len(m_kept)}
            continue
        X, V, y, fams, meta = [], [], [], [], []
        for u in m_kept:
            f, v, m = features_for_unit(u, True)
            X.append(f)
            V.append(v)
            y.append(1)
            fams.append(None)
            meta.append(m)
        for i, u in enumerate(h3_units):
            f, v, m = features_for_unit(u, False)
            X.append(f)
            V.append(v)
            y.append(0)
            fams.append(h3_fams[i])
            meta.append(m)
        n_mist, n_h3 = len(m_kept), len(h3_units)

        def run_models(Xtr, ytr, Xte, yte, Vtr, Vte):
            out = {}
            Xtr_s, Xte_s = standardize(Xtr, Xte)
            w, b = train_lr(Xtr_s, ytr)
            out["logreg"] = evaluate(predict_lr(w, b, Xte_s), yte, args.perms)
            Vtr_s, Vte_s = standardize(Vtr, Vte)
            wv, bv = train_lr(Vtr_s, ytr)
            out["volume_only_logreg"] = evaluate(predict_lr(wv, bv, Vte_s), yte, args.perms)
            if SKLEARN:
                rf = RandomForestClassifier(n_estimators=200,
                                            random_state=SEED, n_jobs=1)
                rf.fit(Xtr, ytr)
                out["random_forest"] = evaluate(
                    [p[1] for p in rf.predict_proba(Xte)], yte, args.perms)
                gb = HistGradientBoostingClassifier(random_state=SEED)
                gb.fit(Xtr, ytr)
                out["grad_boosting"] = evaluate(
                    [p[1] for p in gb.predict_proba(Xte)], yte, args.perms)
            else:
                out["random_forest"] = None
                out["grad_boosting"] = None
            return out

        # ---- main random holdout (stratified per arm, seed fixed) ----
        rng = random.Random(SEED)
        idx_m = list(range(n_mist))
        idx_h = list(range(n_mist, n_mist + n_h3))
        rng.shuffle(idx_m)
        rng.shuffle(idx_h)
        ntr_m = (2 * n_mist) // 3
        ntr_h = (2 * n_h3) // 3
        tr = idx_m[:ntr_m] + idx_h[:ntr_h]
        te = idx_m[ntr_m:] + idx_h[ntr_h:]
        main = run_models([X[i] for i in tr], [y[i] for i in tr],
                          [X[i] for i in te], [y[i] for i in te],
                          [V[i] for i in tr], [V[i] for i in te])
        aucs = [v["auc"] for v in main.values() if v and v["auc"] is not None]
        main["strongest_auc"] = max(aucs) if aucs else None
        # volume guard: volume-only separable => evaluation VOID
        vol = main["volume_only_logreg"]
        vol_void = bool(vol and vol["auc"] is not None and
                        vol["delong_ci95"][0] is not None and
                        vol["delong_ci95"][0] > 0.5)
        main["volume_guard_void"] = vol_void
        # ---- site holdout (3 folds; H3 family held out, Mist random 1/3) ----
        site = {"folds": [], "available": True}
        for fold, fam in enumerate(("cloudflare", "github", "google")):
            te_h = [i for i in range(n_mist, n_mist + n_h3) if fams[i] == fam]
            tr_h = [i for i in range(n_mist, n_mist + n_h3) if fams[i] != fam]
            r2 = random.Random(1000 + fold)
            idx = list(range(n_mist))
            r2.shuffle(idx)
            nte_m = n_mist - (2 * n_mist) // 3
            te_m = idx[:nte_m]
            tr_m = idx[nte_m:]
            tr_i = tr_m + tr_h
            te_i = te_m + te_h
            fold_res = run_models([X[i] for i in tr_i], [y[i] for i in tr_i],
                                  [X[i] for i in te_i], [y[i] for i in te_i],
                                  [V[i] for i in tr_i], [V[i] for i in te_i])
            fa = [v["auc"] for v in fold_res.values() if v and v["auc"] is not None]
            fold_res["strongest_auc"] = max(fa) if fa else None
            fold_res["held_out_family"] = fam
            fold_res["n_test_h3"] = len(te_h)
            fold_res["n_test_mist"] = len(te_m)
            site["folds"].append(fold_res)
        report["classes"][cls] = {
            "n_mist_completed": n_mist, "n_h3_visits": n_h3,
            "h3_visit_units_by_gap": h3_counts,
            "h3_visit_gap_chosen": h3_chosen,
            "n_features": len(X[0]) if X else 0,
            "main_holdout_2to1": main,
            "site_holdout": site,
            "time_disjoint": "NOT SATISFIED (single window); L3 verdict "
                             "deferred to multi-day collection regardless "
                             "of these numbers",
        }

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("=== TQV-CLASSIFIER SUMMARY ===")
    print("sklearn_available=%s (RF/GBM run only if True)" % SKLEARN)
    for cls in ("A", "B"):
        c = report["classes"][cls]
        if "error" in c:
            print("class %s: ERROR %s" % (cls, c["error"]))
            continue
        print("class %s: n_mist=%d n_h3=%d features=%d" % (
            cls, c["n_mist_completed"], c["n_h3_visits"], c["n_features"]))
        m = c["main_holdout_2to1"]
        for name in ("logreg", "volume_only_logreg", "random_forest", "grad_boosting"):
            v = m.get(name)
            if v is None:
                print("  %s: NOT-AVAILABLE (sklearn missing)" % name)
            else:
                print("  %s: AUC=%.3f CI=[%.3f, %.3f] perm_p=%.3f n_test=%d" % (
                    name, v["auc"], v["delong_ci95"][0], v["delong_ci95"][1],
                    v["perm_p"], v["n_test"]))
        print("  strongest_auc=%.3f volume_guard_void=%s" % (
            m["strongest_auc"], m["volume_guard_void"]))
        for fo in c["site_holdout"]["folds"]:
            print("  site-holdout %s: strongest_auc=%.3f (logreg AUC=%.3f)" % (
                fo["held_out_family"], fo["strongest_auc"],
                fo["logreg"]["auc"] if fo["logreg"] else -1))
    print("verdict: NOT-JUDGED (see header); full JSON: %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
