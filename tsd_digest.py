"""mcp-tool-set-digest/1 — an independent implementation written from SPEC.md alone.

This file is self-contained (standard library only). Nothing in it is taken from the
`implementations/` directory of alexar76/mcp-tool-set-digest: the rules implemented here are
read off the specification text (sections 3 to 10) and RFC 8785.

Usage:
    python tsd_digest.py --vectors data/vectors.json --ids extras-present,extras-annotation-flipped
    python tsd_digest.py --vectors data/vectors.json            # all vectors, self-check
Exit code: 0 when every requested vector reproduces the published value (or error code).
"""
import argparse, base64, hashlib, json, sys
from decimal import Decimal

CONTRACT_MEMBERS = ("name", "description", "inputSchema", "outputSchema")


# ---- ordering: UTF-16 code units (SPEC 5.1)
def u16_key(s):
    return s.encode("utf-16-be", "surrogatepass")


# ---- ECMAScript Number::toString (SPEC 6)
def es_number(x):
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("TSD-NUMBER")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    a = abs(x)
    r = repr(a)
    if "e" in r or "E" in r:
        mant, exp = r.split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    if ip.lstrip("0") == "":
        lead = len(fp) - len(fp.lstrip("0"))
        n = exp - lead
        digits = fp.lstrip("0")
    else:
        n = len(ip.lstrip("0")) + exp
        digits = (ip + fp).lstrip("0")
    if digits == "":
        return "0"
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def es_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch in _ESC:
            out.append(_ESC[ch])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            raise ValueError("TSD-TEXT")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(v):
    """RFC 8785 text. Depth is checked separately (depth_check)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, Decimal, float)):
        return es_number(float(v))
    if isinstance(v, str):
        return es_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if any(0xD800 <= ord(c) <= 0xDFFF for c in k):
                raise ValueError("TSD-TEXT")
        return "{" + ",".join(es_string(k) + ":" + jcs(v[k]) for k in sorted(v.keys(), key=u16_key)) + "}"
    raise TypeError(type(v))


def depth_check(v, level=1, max_level=511):
    """A container at level 1 is the root of the hashed value; one level deeper than the
    deepest accepted level is TSD-DEPTH (the vectors pin the boundary: 509 arrays under
    inputSchema.x are accepted, 510 are refused)."""
    if isinstance(v, (list, tuple, dict)):
        if level > max_level:
            raise ValueError("TSD-DEPTH")
        for x in (v if isinstance(v, (list, tuple)) else v.values()):
            depth_check(x, level + 1, max_level)


def sri(text):
    d = hashlib.sha256(text.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(d).decode(), "sha256:" + d.hex()


def read_tools(inp):
    if isinstance(inp, str):
        inp = json.loads(inp, parse_float=Decimal, parse_int=Decimal)
    if isinstance(inp, list):
        return inp
    if isinstance(inp, dict):
        if "tools" in inp and "result" in inp:
            raise ValueError("TSD-TOOL")
        if "nextCursor" in inp:
            raise ValueError("TSD-PAGE")
        if "tools" in inp:
            return read_tools(inp["tools"])
        if "result" in inp:
            return read_tools(inp["result"])
    raise ValueError("TSD-TOOL")


def contract_entry(t):
    if not isinstance(t, dict):
        raise ValueError("TSD-TOOL")
    name = t.get("name")
    if not isinstance(name, str) or name == "":
        raise ValueError("TSD-TOOL")
    e = {"name": name,
         "description": t["description"] if isinstance(t.get("description"), str) else "",
         "inputSchema": t["inputSchema"] if isinstance(t.get("inputSchema"), dict) else {}}
    if isinstance(t.get("outputSchema"), dict):
        e["outputSchema"] = t["outputSchema"]
    return e


def digests(tools_array):
    entries = [contract_entry(t) for t in tools_array]
    for e in entries:
        depth_check(e)
    pairs = sorted(((e["name"], e) for e in entries), key=lambda p: (u16_key(p[0]), jcs(p[1]).encode("utf-8")))
    contract_text = "[" + ",".join(jcs(e) for _, e in pairs) + "]"
    c_sri, c_hex = sri(contract_text)

    by_name, conflict = {}, False
    for t, e in zip(tools_array, entries):
        x = {k: v for k, v in t.items() if k not in CONTRACT_MEMBERS}
        if not x:
            continue
        if e["name"] in by_name:
            conflict = True
        else:
            by_name[e["name"]] = x
    if conflict:
        raise ValueError("TSD-NAME")
    if by_name:
        for x in by_name.values():
            depth_check(x)
        extras_text = jcs({"tools": by_name})
        x_sri, x_hex = sri(extras_text)
    else:
        extras_text, x_sri, x_hex = None, None, None
    return {"contract": {"digest": c_sri, "hex": c_hex, "canonical": contract_text},
            "extras": {"digest": x_sri, "hex": x_hex, "canonical": extras_text}}


def judge(vector):
    """Return (result, error_code)."""
    try:
        return digests(read_tools(vector["tools"])), None
    except RecursionError:
        return None, "TSD-DEPTH"
    except ValueError as e:
        return None, str(e).split(":")[0].strip() or str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", default="data/vectors.json")
    ap.add_argument("--ids", default="", help="comma separated vector ids; empty means all")
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    sys.setrecursionlimit(9000)
    doc = json.load(open(a.vectors, encoding="utf-8"))
    wanted = [x.strip() for x in a.ids.split(",") if x.strip()]
    vs = doc["vectors"]
    if wanted:
        vs = [v for v in vs if v["id"] in wanted]
        missing = set(wanted) - {v["id"] for v in vs}
        if missing:
            print("MISSING_VECTORS:", sorted(missing))
            return 2

    rows, bad = [], 0
    for v in vs:
        exp_c, exp_x = v.get("contract") or {}, v.get("extras") or {}
        got, err = judge(v)
        expect = {"contract_error": exp_c.get("error"), "extras_error": exp_x.get("error"),
                  "contract_digest": exp_c.get("digest"), "extras_digest": exp_x.get("digest"),
                  "contract_hex": exp_c.get("hex"), "extras_hex": exp_x.get("hex"),
                  "contract_canonical": exp_c.get("canonical"), "extras_canonical": exp_x.get("canonical")}
        ok = True
        detail = []
        if err:
            ok = err in (exp_c.get("error"), exp_x.get("error"))
            detail.append("raised " + err)
        else:
            if exp_c.get("error"):
                ok = False; detail.append("expected contract error " + exp_c["error"])
            if exp_x.get("error"):
                ok = False; detail.append("expected extras error " + exp_x["error"])
            for path, exp in (("contract", "contract_digest"), ("extras", "extras_digest"),
                              ("contract", "contract_hex"), ("extras", "extras_hex"),
                              ("contract", "contract_canonical"), ("extras", "extras_canonical")):
                want = expect[exp]
                if want is None:
                    continue
                gotv = (got or {}).get(path, {}).get(exp.split("_", 1)[1])
                if path == "extras" and exp == "extras_digest" and want == "null":
                    want = None
                if gotv != want:
                    ok = False
                    detail.append(f"{path}.{exp.split('_',1)[1]} mismatch")
        bad += 0 if ok else 1
        rows.append({"id": v["id"], "note": v.get("note"), "pass": ok, "detail": detail,
                     "computed": (got if not err else {"error": err}), "expected": expect})
        print(("PASS " if ok else "FAIL ") + v["id"] + ("  " + "; ".join(detail) if detail else ""))

    print(f"\n{len(rows)} vectors, {len(rows)-bad} pass, {bad} fail")
    if a.out:
        json.dump({"vectors_total": len(rows), "pass": len(rows) - bad, "fail": bad, "rows": rows},
                  open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
