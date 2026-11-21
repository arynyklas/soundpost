# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Row-building helpers shared by the `numeric` partition modules. Not an
extension module itself (the driver only loads ext_*.py)."""
import copy, math, struct

INF = float("inf")
NAN = float("nan")
NAN_BITS = "7ff8000000000001"
STALE_BITS = "7ff0000000000002"
SUB = 5e-324
NZ = -0.0


def bits(x):
    if isinstance(x, str):
        return x
    if math.isnan(x):
        return NAN_BITS
    return struct.pack(">d", x).hex()


def ms(t):
    return str(int(round(t * 1000)) * 1_000_000)


def labels(name, **kv):
    return [{"name": k, "value": v} for k, v in sorted([("__name__", name)] + list(kv.items()))]


def fser(name, samples, **kv):
    """Float series: samples is [(seconds, value | bits-string)]."""
    return {"labels": labels(name, **kv), "samples": [{"time": ms(t), "float_bits": bits(v)} for t, v in samples]}


def mkhist(ctx, count=4, sum_bits=None, flavor="counter", zero_count=0, offset=1):
    h = copy.deepcopy(ctx.HIST)
    i = h["integer"]
    i["count"] = str(count)
    i["flavor"] = flavor
    i["zero_count"] = str(zero_count)
    i["positive_spans"] = [{"offset": offset, "length": 1}]
    i["positive_counts"] = [str(count - zero_count)]
    i["sum"] = sum_bits if sum_bits else bits(float(count) * 1.5)
    return h


def hser(ctx, name, samples, **kv):
    """Histogram series: samples is [(seconds, histogram-dict)]; a bare number n means mkhist(n)."""
    out = []
    for t, h in samples:
        out.append({"time": ms(t), "histogram": h if isinstance(h, dict) else mkhist(ctx, h)})
    return {"labels": labels(name, **kv), "samples": out}


def mixed(name, samples, **kv):
    """Series with float and histogram samples: samples is [(seconds, float | histogram-dict)]."""
    out = []
    for t, v in samples:
        if isinstance(v, dict):
            out.append({"time": ms(t), "histogram": v})
        else:
            out.append({"time": ms(t), "float_bits": bits(v)})
    return {"labels": labels(name, **kv), "samples": out}


def row(rid, profile, query, series, enabled=(), kind="instant", time=20, start=None, end=None, step=None):
    r = {"id": rid, "profiles": [profile], "enabled_features": list(enabled), "query": query, "kind": kind}
    if kind == "instant":
        r["time"] = ms(time)
    else:
        r["start"], r["end"], r["step"] = ms(start), ms(end), ms(step)
    r["series"] = copy.deepcopy(series)
    return r


def union(parts):
    """Tags each (query, tag) part with label q=tag and unions them with `or`."""
    return " or ".join('label_replace(%s, "q", "%s", "", "")' % (q, tag) for q, tag in parts)


def spec(query, series, enabled=(), kind="instant", **kw):
    d = dict(query=query, series=series, enabled=tuple(enabled), kind=kind)
    d.update(kw)
    return d


def series_key(s):
    return [(l["name"], l["value"]) for l in s["labels"]]


def spec_row(rid, prof, s):
    # Fixture series are ingested in label order: an instant vector is not sorted by the
    # reference (series order) while the owned scan is, so the authored order is the sorted one.
    return row(rid, prof, s["query"], sorted(s["series"], key=series_key), enabled=s.get("enabled", ()), kind=s.get("kind", "instant"),
               time=s.get("time", 20), start=s.get("start"), end=s.get("end"), step=s.get("step"))
