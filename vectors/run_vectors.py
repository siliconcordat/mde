"""Reference runner for zone-canon-v0, standard library only.

Usage: python3 -B run_vectors.py [--mutate] [vectors.json]

Exit 0 when every accept case gives the listed canonical bytes and digest and
every reject case is refused. Exit 1 otherwise. --mutate lets floats through,
so the run must fail. It is the control that shows the checks can go red.
"""
import hashlib
import json
import sys
from pathlib import Path


class Reject(Exception):
    pass


LIMIT = 2**53 - 1


def _int(text):
    if text == "-0":
        raise Reject("negative zero")
    if len(text) > 40:
        raise Reject("integer out of range")
    n = int(text)
    if abs(n) > LIMIT:
        raise Reject("integer out of range")
    return n


def _float(text):
    raise Reject("float " + text)


def _constant(text):
    raise Reject("constant " + text)


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Reject("duplicate key " + key)
        out[key] = value
    return out


def canon(text, mutate=False):
    """Return the canonical bytes of one JSON text, or raise Reject."""
    try:
        value = json.loads(
            text,
            parse_int=_int,
            parse_float=float if mutate else _float,
            parse_constant=_constant,
            object_pairs_hook=_pairs,
        )
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except ValueError as err:
        if isinstance(err, UnicodeEncodeError):
            raise Reject("lone surrogate")
        raise Reject("not valid JSON: " + str(err))


def main(argv):
    mutate = "--mutate" in argv
    paths = [a for a in argv if not a.startswith("--")]
    path = Path(paths[0]) if paths else Path(__file__).resolve().parent / "zone-canon-v0.json"
    with open(path, encoding="utf-8") as fh:
        vec = json.load(fh)
    bad = 0
    for case in vec["accept"]:
        try:
            got = canon(case["input"], mutate)
        except Reject as err:
            print("FAIL accept", case["name"], err)
            bad += 1
            continue
        if got.decode("utf-8") != case["canonical"]:
            print("FAIL accept (bytes)", case["name"], got)
            bad += 1
        elif hashlib.sha256(got).hexdigest() != case["sha256"]:
            print("FAIL accept (digest)", case["name"])
            bad += 1
    for case in vec["reject"]:
        try:
            canon(case["input"], mutate)
        except Reject:
            continue
        print("FAIL reject (accepted)", case["name"])
        bad += 1
    print(
        "python: %d accept, %d reject, %d failures"
        % (len(vec["accept"]), len(vec["reject"]), bad)
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
