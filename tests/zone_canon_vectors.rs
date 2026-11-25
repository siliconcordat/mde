//! Runs the zone-canon-v0 vectors through a strict canonicalizer defined in this file.
//!
//! The canonicalizer does not use `src/zone_manifest.rs` and does not use serde_json
//! for the text under test, so no float printer takes part in the bytes. serde_json
//! only reads the vector file itself. The mutated canonicalizers at the bottom are
//! controls: each one breaks one part of the rule and must fail the vectors.

use sha2::{Digest, Sha256};
use std::path::Path;

const LIMIT: i128 = (1i128 << 53) - 1;

/// One switch per part of the rule. `Rule::strict()` is the rule itself.
#[derive(Clone, Copy)]
struct Rule {
    reject_floats: bool,
    reject_negative_zero: bool,
    check_range: bool,
    reject_duplicates: bool,
    sort_keys: bool,
    raw_utf8: bool,
}

impl Rule {
    fn strict() -> Rule {
        Rule {
            reject_floats: true,
            reject_negative_zero: true,
            check_range: true,
            reject_duplicates: true,
            sort_keys: true,
            raw_utf8: true,
        }
    }
}

enum V {
    Null,
    Bool(bool),
    Int(i128),
    Float(String),
    Str(String),
    Arr(Vec<V>),
    Obj(Vec<(String, V)>),
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    rule: Rule,
}

type R<T> = Result<T, String>;

impl<'a> P<'a> {
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\n' | b'\t' | b'\r')) {
            self.i += 1;
        }
    }

    fn lit(&mut self, word: &str, v: V) -> R<V> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("bad token at {}", self.i))
        }
    }

    fn val(&mut self) -> R<V> {
        self.ws();
        match self.s.get(self.i).copied() {
            Some(b'{') => {
                self.i += 1;
                let mut m: Vec<(String, V)> = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(V::Obj(m));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return Err("expected colon".into());
                    }
                    self.i += 1;
                    let v = self.val()?;
                    if self.rule.reject_duplicates && m.iter().any(|(x, _)| *x == k) {
                        return Err(format!("duplicate key {k}"));
                    }
                    m.push((k, v));
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(V::Obj(m));
                        }
                        _ => return Err("bad object".into()),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(V::Arr(a));
                }
                loop {
                    a.push(self.val()?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(V::Arr(a));
                        }
                        _ => return Err("bad array".into()),
                    }
                }
            }
            Some(b'"') => Ok(V::Str(self.string()?)),
            Some(b't') => self.lit("true", V::Bool(true)),
            Some(b'f') => self.lit("false", V::Bool(false)),
            Some(b'n') => self.lit("null", V::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.num(),
            _ => Err(format!("unexpected token at {}", self.i)),
        }
    }

    fn num(&mut self) -> R<V> {
        let st = self.i;
        while matches!(
            self.s.get(self.i),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.i += 1;
        }
        let t = std::str::from_utf8(&self.s[st..self.i]).map_err(|_| "utf8")?;
        if t.contains(['.', 'e', 'E']) {
            if self.rule.reject_floats {
                return Err(format!("float {t}"));
            }
            return Ok(V::Float(t.to_string()));
        }
        if t == "-0" && self.rule.reject_negative_zero {
            return Err("negative zero".into());
        }
        let digits = t.strip_prefix('-').unwrap_or(t);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("bad number {t}"));
        }
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(format!("leading zero {t}"));
        }
        if digits.len() > 30 {
            return Err("integer out of range".into());
        }
        let n: i128 = t.parse().map_err(|_| format!("bad number {t}"))?;
        if self.rule.check_range && n.abs() > LIMIT {
            return Err("integer out of range".into());
        }
        Ok(V::Int(n))
    }

    fn hex4(&mut self) -> R<u32> {
        let h = self.s.get(self.i..self.i + 4).ok_or("short escape")?;
        self.i += 4;
        let h = std::str::from_utf8(h).map_err(|_| "utf8")?;
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("bad hex".into());
        }
        u32::from_str_radix(h, 16).map_err(|_| "bad hex".to_string())
    }

    fn string(&mut self) -> R<String> {
        if self.s.get(self.i) != Some(&b'"') {
            return Err("expected string".into());
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = *self.s.get(self.i).ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = *self.s.get(self.i).ok_or("short escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut u = self.hex4()?;
                            if (0xD800..0xDC00).contains(&u) {
                                if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err("lone surrogate".into());
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("bad surrogate pair".into());
                                }
                                u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                            }
                            out.push(char::from_u32(u).ok_or("lone surrogate")?);
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                c if c < 0x20 => return Err("raw control character".into()),
                _ => {
                    let st = self.i - 1;
                    let mut e = self.i;
                    while e < self.s.len() && (self.s[e] & 0xC0) == 0x80 {
                        e += 1;
                    }
                    out.push_str(std::str::from_utf8(&self.s[st..e]).map_err(|_| "utf8")?);
                    self.i = e;
                }
            }
        }
    }
}

fn enc_str(s: &str, o: &mut String, raw_utf8: bool) {
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c if !raw_utf8 && (c as u32) > 0x7e => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    o.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => o.push(c),
        }
    }
    o.push('"');
}

fn enc(v: &V, o: &mut String, rule: &Rule) {
    match v {
        V::Null => o.push_str("null"),
        V::Bool(b) => o.push_str(if *b { "true" } else { "false" }),
        V::Int(n) => o.push_str(&n.to_string()),
        V::Float(t) => o.push_str(t),
        V::Str(s) => enc_str(s, o, rule.raw_utf8),
        V::Arr(a) => {
            o.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                enc(x, o, rule);
            }
            o.push(']');
        }
        V::Obj(m) => {
            let mut items: Vec<&(String, V)> = m.iter().collect();
            if rule.sort_keys {
                // String order in Rust is byte order of UTF-8, which is code point order.
                items.sort_by(|a, b| a.0.cmp(&b.0));
            }
            o.push('{');
            for (i, (k, x)) in items.into_iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                enc_str(k, o, rule.raw_utf8);
                o.push(':');
                enc(x, o, rule);
            }
            o.push('}');
        }
    }
}

fn canon(text: &str, rule: Rule) -> R<String> {
    let mut p = P {
        s: text.as_bytes(),
        i: 0,
        rule,
    };
    let v = p.val()?;
    p.ws();
    if p.i != p.s.len() {
        return Err("trailing characters".into());
    }
    let mut o = String::new();
    enc(&v, &mut o, &rule);
    Ok(o)
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

struct Vectors {
    accept: Vec<(String, String, String, String)>,
    reject: Vec<(String, String)>,
}

fn load() -> Vectors {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/zone-canon-v0.json");
    let text = std::fs::read_to_string(&path).expect("read vector file");
    let root: serde_json::Value = serde_json::from_str(&text).expect("vector file is JSON");
    let field = |c: &serde_json::Value, k: &str| -> String {
        c.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("missing string field {k}"))
            .to_string()
    };
    let list = |k: &str| -> Vec<serde_json::Value> {
        root.get(k)
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("missing list {k}"))
            .clone()
    };
    Vectors {
        accept: list("accept")
            .iter()
            .map(|c| {
                (
                    field(c, "name"),
                    field(c, "input"),
                    field(c, "canonical"),
                    field(c, "sha256"),
                )
            })
            .collect(),
        reject: list("reject")
            .iter()
            .map(|c| (field(c, "name"), field(c, "input")))
            .collect(),
    }
}

/// Names of the cases that fail under `rule`.
fn run(v: &Vectors, rule: Rule) -> Vec<String> {
    let mut failed = Vec::new();
    for (name, input, canonical, digest) in &v.accept {
        match canon(input, rule) {
            Ok(b) if b == *canonical && sha256_hex(b.as_bytes()) == *digest => {}
            _ => failed.push(name.clone()),
        }
    }
    for (name, input) in &v.reject {
        if canon(input, rule).is_ok() {
            failed.push(name.clone());
        }
    }
    failed
}

#[test]
fn vector_file_has_the_expected_shape() {
    let v = load();
    assert!(v.accept.len() >= 7, "accept cases: {}", v.accept.len());
    assert!(v.reject.len() >= 10, "reject cases: {}", v.reject.len());
}

#[test]
fn every_vector_passes_the_strict_rule() {
    let failed = run(&load(), Rule::strict());
    assert!(failed.is_empty(), "failing cases: {failed:?}");
}

#[test]
fn strict_parser_refuses_forms_the_vector_file_does_not_cover() {
    let rule = Rule::strict();
    for bad in [
        "{\"a\":01}",
        "{\"a\":-}",
        "{\"a\":\"x\u{1}y\"}",
        "{\"a\":\"\\ud800\"}",
        "{\"a\":1} x",
        "{\"a\":Infinity}",
        "",
    ] {
        assert!(canon(bad, rule).is_err(), "accepted {bad:?}");
    }
}

fn names(prefix: &str, v: &Vectors) -> Vec<String> {
    v.reject
        .iter()
        .filter(|(n, _)| n.starts_with(prefix))
        .map(|(n, _)| n.clone())
        .collect()
}

#[test]
fn control_floats_accepted_fails_every_float_reject_case() {
    let v = load();
    let failed = run(
        &v,
        Rule {
            reject_floats: false,
            ..Rule::strict()
        },
    );
    let floats = names("float_", &v);
    assert!(floats.len() >= 5, "float reject cases: {}", floats.len());
    for n in &floats {
        assert!(
            failed.contains(n),
            "float case {n} still passed with floats accepted"
        );
    }
}

#[test]
fn control_negative_zero_accepted_fails() {
    let failed = run(
        &load(),
        Rule {
            reject_negative_zero: false,
            ..Rule::strict()
        },
    );
    assert!(failed.contains(&"negative_zero".to_string()), "{failed:?}");
}

#[test]
fn control_range_unchecked_fails() {
    let failed = run(
        &load(),
        Rule {
            check_range: false,
            ..Rule::strict()
        },
    );
    assert!(
        failed.contains(&"integer_2_pow_53".to_string()),
        "{failed:?}"
    );
}

#[test]
fn control_duplicates_accepted_fails() {
    let failed = run(
        &load(),
        Rule {
            reject_duplicates: false,
            ..Rule::strict()
        },
    );
    assert!(failed.contains(&"duplicate_key".to_string()), "{failed:?}");
}

#[test]
fn control_unsorted_keys_fail() {
    let failed = run(
        &load(),
        Rule {
            sort_keys: false,
            ..Rule::strict()
        },
    );
    assert!(
        failed.contains(&"key_order_nested".to_string()),
        "{failed:?}"
    );
}

#[test]
fn control_ascii_escaping_fails() {
    let failed = run(
        &load(),
        Rule {
            raw_utf8: false,
            ..Rule::strict()
        },
    );
    assert!(
        failed.contains(&"non_ascii_raw_utf8".to_string()),
        "{failed:?}"
    );
}
