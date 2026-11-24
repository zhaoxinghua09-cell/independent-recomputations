"""Build manifest.json and SHA256SUMS: every check, what it reads, what it must produce, and the
SHA-256 of the artifact that pins it. Anything that changes silently breaks the CI gate."""
import hashlib, json, pathlib

HERE = pathlib.Path(__file__).parent
DATA = HERE / "data"


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


inputs = {name: {"file": f"data/{name}", "sha256": sha(DATA / name),
                 "bytes": (DATA / name).stat().st_size,
                 "source_pinned": True}
          for name in ("vectors.json", "a2a_card.capsules.jsonl.gz", "a2a_card.record.json")}

checks = [
    {"id": "tsd-all-vectors", "entry": "tsd_digest.py", "spec": "mcp-tool-set-digest/1 (editors' draft 2026-11-23)",
     "profile": "conformance", "vector_file": "data/vectors.json", "case_count": 92,
     "expect_file": "expected/out_vectors.json",
     "asserts": "canonical text, both written forms of each digest, and the six error codes"},
    {"id": "tsd-three-target", "entry": "tsd_digest.py --ids extras-present,extras-annotation-flipped,extras-contract-changed",
     "spec": "mcp-tool-set-digest/1", "profile": "conformance", "vector_file": "data/vectors.json", "case_count": 3,
     "expect_file": "expected/out_three.json",
     "asserts": "the three digests quoted in the reply to the editor"},
    {"id": "capsule-batch", "entry": "capsule_batch.py --record data/a2a_card.record.json",
     "spec": "draft-templeman-scitt-measurement-capsule-01 + RFC 9162 s2.1.1 + RFC 8785",
     "profile": "recomputation", "vector_file": "data/a2a_card.capsules.jsonl.gz", "case_count": 33,
     "expect_file": "expected/out_batch.json",
     "asserts": "capsule_id recomputation, JCS line bytes, ordering, RFC 9162 root, and the record's "
                "n_capsules / merkle_root / file SHA-256 / state counts"},
    {"id": "inclusion-proofs", "entry": "inclusion.py",
     "spec": "RFC 9162 s2.1.3 PATH + s2.1.4.2 root-from-path",
     "profile": "derivation", "vector_file": "data/a2a_card.capsules.jsonl.gz", "case_count": 33,
     "expect_file": "expected/inclusion.json",
     "asserts": "one inclusion path per capsule (33), each re-deriving the published root from leaf, "
                "index and path alone; plus an outsider leaf that must not verify"},
    {"id": "discrimination", "entry": "tamper_test.py", "spec": "metamorphic: a wrong witness must fail",
     "profile": "negative", "vector_file": "inline mutations", "case_count": 6,
     "expect_file": "expected/tamper.json",
     "asserts": "six mutations (capsule_id, record root, expected root, published digest, one flipped "
                "byte of one inclusion path, baseline) each return the required exit code"},
    {"id": "end-to-end", "entry": "verify.py", "spec": "this manifest", "profile": "orchestration",
     "vector_file": "all of the above", "case_count": 9, "expect_file": "expected/verify.log",
     "asserts": "nine steps PASS, exit code 0"},
]

coverage = {
    "covered": ["identifier recomputation", "canonical line bytes", "ordering and duplicate detection",
                "RFC 9162 set root", "record-stated values (n, root, file SHA-256, state counts)",
                "per-capsule inclusion proofs against the published root (RFC 9162 s2.1.3/2.1.4.2)",
                "published vector conformance for both digests"],
    "not_covered": ["signature checks the capsules report (a claim inside each capsule)",
                    "signatures on record.signed.json and index.signed.json",
                    "timestamp proofs (record.json.ots, index.json.ots)",
                    "what any MCP server does at runtime"],
}

manifest = {
    "repository": "zhaoxinghua09-cell/independent-recomputations",
    "generated_by": "make_manifest.py",
    "runtime": "Python 3 standard library only; no network for the checks themselves",
    "inputs": inputs,
    "checks": checks,
    "coverage": coverage,
}
(HERE / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

lines = []
for p in sorted(HERE.rglob("*")):
    rel = p.relative_to(HERE).as_posix()
    if not p.is_file():
        continue
    if rel.startswith(("data/", "expected/", ".git/")) or rel == "SHA256SUMS" or rel.startswith(".git"):
        continue
    lines.append(f"{sha(p)}  {rel}")
(HERE / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"manifest: {len(checks)} checks, {sum(c['case_count'] for c in checks)} cases")
print(f"SHA256SUMS: {len(lines)} files")
print("\n".join(lines))
