# independent-recomputations

Two checks written from specification text alone, so that someone other than the author can run
them and see the same numbers. Standard library only, Python 3, no credentials, no network for the
checks themselves.

## 1. `mcp-tool-set-digest/1` — contract digest and extras digest

`tsd_digest.py` implements the two digests of the editors' draft *MCP tool-set digest, version 1*
(2026-11-23, commit `13046f6e`): the contract digest over `name`, `description`, `inputSchema`,
`outputSchema`, and the extras digest over every other member, both as SHA-256 over RFC 8785
canonical text. Ordering is by UTF-16 code units; numbers are written as ECMAScript writes a double.

It was written from `SPEC.md` and RFC 8785. None of the repository's Python, JavaScript or Go
implementations was read while writing it.

```
python tsd_digest.py --vectors data/vectors.json --out expected/out_vectors.json
python tsd_digest.py --vectors data/vectors.json \
    --ids extras-present,extras-annotation-flipped,extras-contract-changed \
    --out expected/out_three.json
```

`92 of 92` published vectors reproduce, including the canonical text, both written forms of each
digest, and the six error codes `TSD-PAGE`, `TSD-TOOL`, `TSD-NUMBER`, `TSD-TEXT`, `TSD-NAME`,
`TSD-DEPTH`.

## 2. A measurement-capsule batch

`capsule_batch.py` implements, from `draft-templeman-scitt-measurement-capsule-01`, the recomputation
of `capsule_id` (SHA-256 over JCS with `capsule_id` removed) and the batch Merkle root (RFC 9162
section 2.1.1, SHA-256, over the 32-byte identifiers in ascending byte order).

```
python capsule_batch.py --file data/a2a_card.capsules.jsonl.gz \
    --expect-root bf12f4ad340a11a14ecbd359ba90b3aaebb36bb75bcf9e11f433148441bae436 \
    --record data/a2a_card.record.json \
    --out expected/out_batch.json
```

For the batch published at `councilof.ai/measurement-capsules/v0.2/a2a_card/`: 33 capsules, every
line is exactly its own JCS bytes, all 33 identifiers recompute, sorted with no duplicates, and the
root equals the published value byte for byte. With `--record`, the script also holds four values
the batch record states against what it computes itself: `n_capsules` (33), `merkle_root`
(`bf12f4ad…`), the SHA-256 of `capsules.jsonl.gz` (`ba413e81…`, i.e. the bytes it was reading are the
bytes the record commits to) and the per-state counts (13 `VERIFIED`, 12 `UNCHECKABLE`, 8 `FAILED`).
All four agree. The record's own `as_of` is `2026-09-26`.

The same file also prints what the *other* construction in common use would give — padding an odd
tail by repeating its last leaf — which is `e949bf1d…02727` and therefore different. With an odd
count the two constructions diverge; the record states that it splits at the largest power of two
below `n` and hashes the single remaining leaf on its own, with nothing promoted or duplicated, and
the published root agrees with that. The draft text does not say which construction it uses.

## Run everything

```
python fetch_data.py
python tsd_digest.py --vectors data/vectors.json --out expected/out_vectors.json
python capsule_batch.py --file data/a2a_card.capsules.jsonl.gz \
    --expect-root bf12f4ad340a11a14ecbd359ba90b3aaebb36bb75bcf9e11f433148441bae436 \
    --record data/a2a_card.record.json \
    --out expected/out_batch.json
```

Exit code 0 from each command means the published values were reproduced. `expected/run.log`
records one run of both commands on a Linux host with Python 3.12.11.

## What these checks do not show

* `tsd_digest.py` checks the rules of the specification. It does not contact any MCP server and says
  nothing about what any tool does.
* `capsule_batch.py` checks identifiers, line bytes and the set root. Given the batch record it
  also compares the four values the record states, but it does **not** verify the record's
  signature or its timestamp proof, it does not check the signed index, and it does **not**
  re-verify the signature checks the capsules report — those are claims inside each capsule.
* Both implementations were written by the same person who wrote the messages that cite them. That
  makes them a second implementation from the text, not an independent third party. Running them
  yourself is what removes that limitation.

## Data and licence

* `data/vectors.json` — the 92 published vectors of `alexar76/mcp-tool-set-digest`
  (commit `13046f6e`), offered there under Apache-2.0 OR MIT; copied unchanged.
* `data/a2a_card.capsules.jsonl.gz` — not redistributed here; `fetch_data.py` downloads it from
  `councilof.ai` and verifies its SHA-256.
* `data/a2a_card.record.json` — likewise not redistributed; downloaded from `CSOAI-ORG/councilof-ai`
  at commit `857a6cc0` and verified against its SHA-256.
* The two scripts in this repository are offered under Apache-2.0; see `LICENSE`.
