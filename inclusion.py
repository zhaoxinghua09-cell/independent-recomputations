"""Per-leaf inclusion proofs for the published a2a_card batch (RFC 9162 sections 2.1.3 / 2.1.4).

The publisher states a batch Merkle root but ships no per-capsule proof, so nobody can show
"my capsule is in that root" without rebuilding the whole tree. This script derives the
inclusion path for every capsule, then re-derives the root from each path and compares it to
the published root. A path that does not re-derive the published root is reported as a
failure, never silently dropped.

Usage:
    python inclusion.py --file data/a2a_card.capsules.jsonl.gz \
        --expect-root bf12f4ad340a11a14ecbd359ba90b3aaebb36bb75bcf9e11f433148441bae436 \
        --out expected/inclusion.json
Exit code: 0 when all leaves verify.
"""
import argparse, hashlib, json, sys
from capsule_batch import leaf_hash, node_hash, mth, open_maybe_gzip


def inclusion_path(m, leaves):
    """RFC 9162 section 2.1.3 PATH(m, D[n])."""
    n = len(leaves)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return inclusion_path(m, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_path(m - k, leaves[k:]) + [mth(leaves[:k])]


def root_from_path(leaf, m, n, path):
    """RFC 9162 section 2.1.4.2, the verifier an outside reader would run."""
    if m >= n:
        raise ValueError("leaf index out of range")
    fn, sn, r = m, n - 1, leaf_hash(leaf)
    for p in path:
        if (fn & 1) or fn == sn:
            r = node_hash(p, r)
            if not (fn & 1):
                while fn and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("path length wrong")
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="", help="the capsule batch (generation mode)")
    ap.add_argument("--expect-root", required=True)
    ap.add_argument("--out", default="")
    ap.add_argument("--verify-file", default="", help="re-verify a shipped inclusion.json (no batch file needed)")
    a = ap.parse_args()

    if a.verify_file:
        d = json.load(open(a.verify_file, encoding="utf-8"))
        published = bytes.fromhex(a.expect_root)
        bad = 0
        for row in d["proofs"]:
            leaf = bytes.fromhex(row["capsule_id"])
            path = [bytes.fromhex(p) for p in row["path"]]
            try:
                derived = root_from_path(leaf, row["index"], d["n_leaves"], path)
            except ValueError:
                derived = None
            if derived != published:
                bad += 1
        print(f"re-verified {len(d['proofs']) - bad}/{len(d['proofs'])} shipped proofs; failures={bad}")
        return 0 if bad == 0 else 1

    if not a.file:
        ap.error("--file is required when generating proofs")

    raw = open_maybe_gzip(a.file)
    lines = [l for l in raw.split(b"\n") if l]
    ids = [json.loads(l)["capsule_id"] for l in lines]
    leaves = sorted(bytes.fromhex(i) for i in ids)
    root = mth(leaves)
    published = bytes.fromhex(a.expect_root)
    print(f"leaves={len(leaves)} root={root.hex()} published_match={root == published}")

    rows, failures = [], 0
    for m, leaf in enumerate(leaves):
        path = inclusion_path(m, leaves)
        try:
            derived = root_from_path(leaf, m, len(leaves), path)
        except ValueError as e:
            derived, ok = None, False
            print(f"  [{m}] verifier error: {e}")
        else:
            ok = derived == published
        if not ok:
            failures += 1
        rows.append({"index": m, "capsule_id": leaf.hex(), "path_len": len(path),
                     "path": [p.hex() for p in path], "verifies_to_published_root": ok})

    # a leaf that is not in the batch must fail the same verifier
    outsider = hashlib.sha256(b"not a capsule of this batch").digest()
    path0 = inclusion_path(0, leaves)
    neg = root_from_path(outsider, 0, len(leaves), path0) == published
    print(f"negative control (outsider leaf at index 0): verifies={neg} (must be False)")

    print(f"verified {len(rows) - failures}/{len(rows)} inclusion proofs; failures={failures}")
    if a.out:
        json.dump({"root": root.hex(), "published_root": a.expect_root, "n_leaves": len(leaves),
                   "proofs": rows, "failures": failures,
                   "negative_control_passed": not neg}, open(a.out, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
    return 0 if (failures == 0 and not neg and root == published) else 1


if __name__ == "__main__":
    sys.exit(main())
