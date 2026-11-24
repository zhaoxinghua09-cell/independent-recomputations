"""Recompute one published measurement-capsule batch from the draft text alone.

Rules, from draft-templeman-scitt-measurement-capsule-01 (sections "Canonicalisation and
Identifier" and "Batches, Merkle Root and Index"):

  * capsule_id = SHA-256 of the JCS serialisation of the capsule with capsule_id removed,
    written as 64 lowercase hexits;
  * the capsule file stores one capsule per line, each line being exactly the JCS bytes of
    the capsule, LF-terminated, sorted by capsule_id, no duplicates;
  * batch Merkle root = RFC 9162 section 2.1.1 Merkle Tree Hash (SHA-256) over the capsule_id
    values as 32-byte strings in ascending byte order.

Usage:
    python capsule_batch.py --file data/a2a_card.capsules.jsonl.gz \
        --expect-root bf12f4ad340a11a14ecbd359ba90b3aaebb36bb75bcf9e11f433148441bae436
Exit code: 0 when every check passes.
"""
import argparse, gzip, hashlib, json, sys, io
from decimal import Decimal

sys.setrecursionlimit(9000)
from tsd_digest import jcs  # the same JCS used for the other task, written from RFC 8785


def leaf_hash(d):
    return hashlib.sha256(b"\x00" + d).digest()


def node_hash(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def mth(leaves):
    """RFC 9162 section 2.1.1; the odd node is promoted, never duplicated."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def mth_duplicate_last(leaves):
    """The other construction in common use: pad an odd tail by repeating its last leaf.
    Reported only to show what a reader would get if it used that instead."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    left, right = leaves[:k], leaves[k:]
    if len(right) < k:
        right = right + [right[-1]] * (k - len(right))
    return node_hash(mth_duplicate_last(left), mth_duplicate_last(right))


def open_maybe_gzip(path):
    raw = open(path, "rb").read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--expect-root", default="")
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    raw = open_maybe_gzip(a.file)
    lines = [l for l in raw.split(b"\n") if l]
    ids, problems, exact = [], [], 0
    for i, line in enumerate(lines):
        obj = json.loads(line, parse_float=Decimal, parse_int=Decimal)
        cid = obj.get("capsule_id")
        if cid is None:
            problems.append({"index": i, "problem": "no capsule_id"})
            continue
        if jcs(obj).encode("utf-8") == line:
            exact += 1
        else:
            problems.append({"index": i, "problem": "line is not the JCS bytes of the capsule"})
        body = {k: v for k, v in obj.items() if k != "capsule_id"}
        rid = hashlib.sha256(jcs(body).encode("utf-8")).hexdigest()
        if rid != cid:
            problems.append({"index": i, "problem": "capsule_id mismatch", "stored": cid, "recomputed": rid})
        ids.append(cid)

    ascending = ids == sorted(ids)
    duplicates = len(ids) != len(set(ids))
    root = mth(sorted(bytes.fromhex(i) for i in ids)).hex()
    alt = mth_duplicate_last(sorted(bytes.fromhex(i) for i in ids)).hex()
    root_ok = (root == a.expect_root) if a.expect_root else None

    print(f"capsules={len(lines)} jcs_exact={exact} problems={len(problems)} "
          f"ascending={ascending} duplicates={duplicates}")
    print(f"root={root}")
    if a.expect_root:
        print(f"expected={a.expect_root} match={root_ok}")
    print(f"duplicate-last-leaf root={alt} differs={alt != root}")
    for p in problems[:10]:
        print("  ", p)

    result = {"file": a.file, "capsules": len(lines), "jcs_exact_lines": exact,
              "problems": problems, "ascending_by_id": ascending, "duplicates": duplicates,
              "root_rfc9162": root, "root_duplicate_last_leaf": alt,
              "expected_root": a.expect_root or None, "root_matches": root_ok}
    if a.out:
        json.dump(result, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    ok = (not problems) and ascending and not duplicates and (root_ok is not False)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
