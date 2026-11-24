"""Tamper tests: the checks must FAIL when the evidence is wrong. A verifier that only passes the
happy path proves nothing about discrimination.

Each case mutates one thing and expects a non-zero exit from the check under test.
"""
import gzip, hashlib, json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).parent
PY = sys.executable
BATCH = HERE / "data" / "a2a_card.capsules.jsonl.gz"
RECORD = HERE / "data" / "a2a_card.record.json"
VEC = HERE / "data" / "vectors.json"
ROOT = "bf12f4ad340a11a14ecbd359ba90b3aaebb36bb75bcf9e11f433148441bae436"


def run(args):
    p = subprocess.run(args, cwd=HERE, capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def mutate_capsule(tmp):
    raw = gzip.decompress(BATCH.read_bytes()).split(b"\n")
    lines = [l for l in raw if l]
    obj = json.loads(lines[3])
    obj["capsule_id"] = "0" * 64          # break the identifier, keep everything else
    lines[3] = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    out = tmp / "tampered.jsonl.gz"
    out.write_bytes(gzip.compress(b"\n".join(lines) + b"\n", mtime=0))
    return out


def mutate_record(tmp):
    rec = json.loads(RECORD.read_text(encoding="utf-8"))
    rec["merkle_root"] = "f" * 64          # a record that claims another root
    out = tmp / "record_bad_root.json"
    out.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def mutate_vectors(tmp):
    v = json.loads(VEC.read_text(encoding="utf-8"))
    for case in v["vectors"]:
        if case.get("id") == "extras-present":
            case["extras"]["digest"] = "sha256-AAAAreplacementAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            break
    out = tmp / "vectors_bad.json"
    out.write_text(json.dumps(v, ensure_ascii=False), encoding="utf-8")
    return out


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="tamper_"))
    cases, ok = [], True

    good, _ = run([PY, "capsule_batch.py", "--file", "data/a2a_card.capsules.jsonl.gz",
                   "--expect-root", ROOT, "--record", "data/a2a_card.record.json"])
    cases.append({"case": "baseline (untouched evidence)", "expected_rc": 0, "got_rc": good,
                  "verdict": "PASS" if good == 0 else "FAIL"})

    bad_caps = mutate_capsule(tmp)
    rc, _ = run([PY, "capsule_batch.py", "--file", str(bad_caps), "--expect-root", ROOT])
    cases.append({"case": "one capsule_id replaced by zeros", "expected_rc": "non-zero", "got_rc": rc,
                  "verdict": "PASS" if rc != 0 else "FAIL"})

    bad_rec = mutate_record(tmp)
    rc, _ = run([PY, "capsule_batch.py", "--file", "data/a2a_card.capsules.jsonl.gz",
                 "--expect-root", ROOT, "--record", str(bad_rec)])
    cases.append({"case": "record claims a different merkle_root", "expected_rc": "non-zero", "got_rc": rc,
                  "verdict": "PASS" if rc != 0 else "FAIL"})

    rc, _ = run([PY, "capsule_batch.py", "--file", "data/a2a_card.capsules.jsonl.gz",
                 "--expect-root", "0" * 64])
    cases.append({"case": "expected root wrong", "expected_rc": "non-zero", "got_rc": rc,
                  "verdict": "PASS" if rc != 0 else "FAIL"})

    bad_vec = mutate_vectors(tmp)
    rc, _ = run([PY, "tsd_digest.py", "--vectors", str(bad_vec), "--ids", "extras-present"])
    cases.append({"case": "one published vector's expected digest altered", "expected_rc": "non-zero",
                  "got_rc": rc, "verdict": "PASS" if rc != 0 else "FAIL"})

    # flip one byte in one shipped inclusion path: the proof must stop re-deriving the root
    inc = json.loads((HERE / "expected" / "inclusion.json").read_text(encoding="utf-8"))
    hexits = inc["proofs"][12]["path"][0]
    flipped = ("0" if hexits[0] != "0" else "1") + hexits[1:]
    inc["proofs"][12]["path"][0] = flipped
    bad_inc = tmp / "inclusion_flipped.json"
    bad_inc.write_text(json.dumps(inc, ensure_ascii=False), encoding="utf-8")
    rc, _ = run([PY, "inclusion.py", "--expect-root", ROOT, "--verify-file", str(bad_inc)])
    cases.append({"case": "one byte of one inclusion path flipped", "expected_rc": "non-zero",
                  "got_rc": rc, "verdict": "PASS" if rc != 0 else "FAIL"})

    ok = all(c["verdict"] == "PASS" for c in cases)
    result = {"cases": cases, "verdict": "PASS" if ok else "FAIL"}
    (HERE / "expected" / "tamper.json").write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                                   encoding="utf-8")
    for c in cases:
        print(f'{c["verdict"]:4s} {c["case"]:48s} rc={c["got_rc"]}')
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
