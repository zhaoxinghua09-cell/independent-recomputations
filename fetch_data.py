"""Fetch the two input files this repository checks, and verify their SHA-256.

Both files are published by their authors; nothing here is redistributed by us beyond
data/vectors.json, which the mcp-tool-set-digest repository offers under Apache-2.0 OR MIT.

    python fetch_data.py

Exit code 0 means both files are present and hash exactly as recorded.
"""
import hashlib, pathlib, sys, time, urllib.request

HERE = pathlib.Path(__file__).parent
DATA = HERE / "data"
RECORD_SHA = "180a16f838f33372e1e6345fb272d7b3427a55dacee5571c34a6947a116cc6b6"
TARGETS = [
    {
        "path": DATA / "vectors.json",
        "url": "https://raw.githubusercontent.com/alexar76/mcp-tool-set-digest/"
               "13046f6e1b73e306927e18029b1d0fba59fbc4c5/vectors/vectors.json",
        "alt": "https://cdn.jsdelivr.net/gh/alexar76/mcp-tool-set-digest@"
               "13046f6e1b73e306927e18029b1d0fba59fbc4c5/vectors/vectors.json",
        "sha256": "1b1e6706681755740faa85966ece46150ffc70ba452113dc9ae05eb2357d63eb",
    },
    {
        "path": DATA / "a2a_card.capsules.jsonl.gz",
        "url": "https://councilof.ai/measurement-capsules/v0.2/a2a_card/capsules.jsonl.gz",
        "alt": "",
        "sha256": "ba413e8160120205d8b9ec87fec95fa9e0f3ac2e6c858d4e6e807851882cd661",
    },
    {
        "path": DATA / "a2a_card.record.json",
        "url": "https://raw.githubusercontent.com/CSOAI-ORG/councilof-ai/"
               "857a6cc02696cdc575c5b540f7b4ab7d043cb591/public/measurement-capsules/"
               "v0.2/a2a_card/record.json",
        "alt": "https://cdn.jsdelivr.net/gh/CSOAI-ORG/councilof-ai@"
               "857a6cc02696cdc575c5b540f7b4ab7d043cb591/public/measurement-capsules/"
               "v0.2/a2a_card/record.json",
        "sha256": RECORD_SHA,
    },
]


def get(url, timeout=90, attempts=4):
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8.4.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:
            last = e
            time.sleep(2 * (i + 1))
    raise last


def main():
    DATA.mkdir(exist_ok=True)
    bad = 0
    for t in TARGETS:
        p = t["path"]
        if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() == t["sha256"]:
            print(f"OK (already present) {p.relative_to(HERE)}")
            continue
        body = None
        for u in [t["url"]] + ([t["alt"]] if t.get("alt") else []):
            try:
                body = get(u)
                break
            except Exception as e:
                print(f"  {type(e).__name__} on {u}: {e}")
        if body is None:
            print(f"MISSING {p.name}: could not fetch; place the file by hand and rerun")
            bad += 1
            continue
        p.write_bytes(body)
        got = hashlib.sha256(body).hexdigest()
        if got != t["sha256"]:
            print(f"FAIL {p.name}: sha256 {got} != {t['sha256']}")
            bad += 1
        else:
            print(f"OK (fetched) {p.relative_to(HERE)} {len(body)} bytes")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
