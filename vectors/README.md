# zone-canon-v0 test vectors

This folder holds a proposed rule for turning a JSON value into bytes before it is hashed, plus test vectors and two runners that check it. The proposal comes from issue #7. A zone manifest id is a SHA-256 over a body that holds floating-point numbers. Python layers print `1e-05` where the Rust layer prints `0.00001`, so two layers can compute two ids for one manifest.

## Canonical bytes

The canonical bytes of a value are the one exact byte string it is turned into before it is hashed. Two layers agree on a digest only if they agree on these bytes first.

## The rule

This is the rule text from `zone-canon-v0.json`:

> Parse strictly. Objects sorted by key in code point order. No whitespace.
>
> Strings in raw UTF-8, escaping only quote, backslash and code points below 0x20 (short forms for b f n r t, otherwise lowercase \u00xx).
>
> Numbers are integers with absolute value at most 2^53-1, written in decimal with no sign for zero, no leading zeros, no fraction or exponent. Any other number, any duplicate key, NaN and Infinity are rejected.
>
> digest is lowercase hex sha256 of the canonical bytes.

A scale such as 0.2 is then stored as an integer over a power of two, for example `{"scale_den_log2":10,"scales_num":{"corpus":205}}`. Integers print the same way in every language.

## What is in the folder

- `zone-canon-v0.json` holds the rule, 7 accept cases and 10 reject cases. An accept case has an input, the canonical bytes and the SHA-256 digest. A reject case has an input that must be refused. A last section, `observed_today_not_a_rule`, records two digests that the shipped code produced for one manifest. It is a record and the runners do not read it.
- `run_vectors.py` is the Python runner. It uses only the standard library.
- `../tests/zone_canon_vectors.rs` is the Rust runner. It is an ordinary `cargo test` file with its own strict parser and encoder. It uses only crates mde already depends on, and it does not call `src/zone_manifest.rs`.

## How to run

```sh
python3 -B -W error vectors/run_vectors.py
python3 -B -W error vectors/run_vectors.py --mutate
cargo test --test zone_canon_vectors
```

The first command exits 0. The second lets floats through on purpose and exits 1, which shows the checks can fail. The Rust test holds the same kind of control. Each control breaks one part of the rule and the test checks that the vectors catch it.

## Status

This is a proposed rule, tagged `v0` the way mde tags drafts. It is not part of `PROTOCOL.md` and nothing in the mde binary reads it. mde's own manifest code is not changed by this folder. It still prints floats, and it still computes the id it computed before.

## Adopting it in a layer

1. Read `zone-canon-v0.json` from a copy kept in your repository.
2. Write a canonicalizer that follows the rule text.
3. Run every accept case and compare bytes and digest. Run every reject case and check it is refused.
4. Add a control that makes your canonicalizer accept floats and check that the float reject cases then fail.
5. Only then change which bytes your layer hashes, and plan how existing manifest ids are migrated.
