"""One command: fetch the inputs, run both checks, compare against the shipped expectations, run
the tamper tests, and print a table. Exit code 0 only if every line is PASS.

    python verify.py
"""
import json, hashlib, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).parent
PY = sys.executable
ROOT = "bf12f4ad340a11a14ecbd359ba90b3aaebb36bb75bcf9e11f433148441bae436"


def run(args):
    p = subprocess.run(args, cwd=HERE, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def same_json(a, b):
    if not (a.exists() and b.exists()):
        return False
    return json.loads(a.read_text(encoding="utf-8")) == json.loads(b.read_text(encoding="utf-8"))


def main():
    rows, rc_all = [], 0

    def add(name, ok, detail=""):
        nonlocal rc_all
        rows.append((name, "PASS" if ok else "FAIL", detail))
        if not ok:
            rc_all = 1

    rc, _, err = run([PY, "fetch_data.py"])
    add("fetch inputs, pin SHA-256", rc == 0, err[:80])

    out_v = HERE / "out_vectors.json"
    rc, _, err = run([PY, "tsd_digest.py", "--vectors", "data/vectors.json", "--out", str(out_v)])
    add("92 published vectors", rc == 0, err[:80])

    out_3 = HERE / "out_three.json"
    rc, _, err = run([PY, "tsd_digest.py", "--vectors", "data/vectors.json", "--ids",
                      "extras-present,extras-annotation-flipped,extras-contract-changed",
                      "--out", str(out_3)])
    add("three target vectors", rc == 0, err[:80])
    add("three vectors equal shipped expectation", same_json(out_3, HERE / "expected" / "out_three.json"))

    out_b = HERE / "out_batch.json"
    rc, _, err = run([PY, "capsule_batch.py", "--file", "data/a2a_card.capsules.jsonl.gz",
                      "--expect-root", ROOT, "--record", "data/a2a_card.record.json",
                      "--out", str(out_b)])
    add("33 capsules, root, record four values", rc == 0, err[:80])
    add("batch result equal shipped expectation", same_json(out_b, HERE / "expected" / "out_batch.json"))

    rc, out, err = run([PY, "tamper_test.py"])
    add("tamper tests (checks must fail on bad evidence)", rc == 0, (err or out.splitlines()[-1] if out else "")[:80])

    for n in (out_v, out_3, out_b):
        n.unlink(missing_ok=True)

    width = max(len(r[0]) for r in rows)
    for name, verdict, detail in rows:
        print(f"{verdict:4s}  {name:<{width}}  {detail}")
    print(f"\n{sum(1 for r in rows if r[1] == 'PASS')} of {len(rows)} checks PASS")
    return rc_all


if __name__ == "__main__":
    sys.exit(main())
