//! Spike 0.8 (PLAN Phase 0): compile real blocklists (padded with synthetic
//! names to a target count), then, in a fresh process the way the resolver
//! would, map the file and time lookups.
//!
//!   blocklist-bench compile <out.w4bl> <pad-to> <list.txt>...
//!   blocklist-bench lookup <out.w4bl> <queries>
//!
//! `compile` also writes `<out>.sample`: listed names for the lookup run.

use std::path::Path;
use std::time::Instant;

use w4_dns::compile::{compile, new_key, write_atomic};
use w4_dns::lists::{Format, parse};
use w4_dns::matcher::Blocklist;
use w4_dns::rules::Rules;

fn mb(bytes: u64) -> f64 {
    bytes as f64 / 1_048_576.0
}

/// A small deterministic generator (xorshift), so runs compare.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn label(&mut self, len: usize) -> String {
        (0..len)
            .map(|_| (b'a' + (self.next() % 26) as u8) as char)
            .collect()
    }
}

fn compile_cmd(out: &Path, pad_to: usize, lists: &[String]) {
    let started = Instant::now();
    let mut all: Vec<Vec<String>> = Vec::new();
    for path in lists {
        let text = std::fs::read_to_string(path).expect("read list");
        let t = Instant::now();
        let parsed = parse(&text, Format::Domains);
        println!(
            "{path}: {} domains, {} skipped, parsed in {:?}",
            parsed.domains.len(),
            parsed.skipped,
            t.elapsed()
        );
        all.push(parsed.domains);
    }
    let real: usize = all.iter().map(Vec::len).sum();
    // Padded to `pad_to` different names: the real lists overlap a lot.
    let mut unique: std::collections::HashSet<&str> =
        all.iter().flatten().map(String::as_str).collect();
    println!("{real} domains given, {} different", unique.len());
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut synthetic = Vec::new();
    while unique.len() + synthetic.len() < pad_to {
        let len = 5 + (rng.next() % 12) as usize;
        let tld = ["com", "net", "org", "io", "xyz"][(rng.next() % 5) as usize];
        let name = format!("{}.{tld}", rng.label(len));
        if !unique.contains(name.as_str()) {
            synthetic.push(name);
        }
    }
    unique.clear();
    all.push(synthetic);
    let inputs: Vec<(u16, &[String])> = all
        .iter()
        .enumerate()
        .map(|(i, d)| (i as u16, d.as_slice()))
        .collect();
    let t = Instant::now();
    let bytes = compile(&inputs, new_key());
    let compile_time = t.elapsed();
    write_atomic(out, &bytes).expect("write");
    let entries = (bytes.len() - 64) / 10;
    println!(
        "compiled {entries} unique domains ({} given) in {compile_time:?}; file {:.1} MB; total {:?}",
        real + all.last().map_or(0, Vec::len),
        mb(bytes.len() as u64),
        started.elapsed()
    );
    // A sample of listed names for the lookup run: every 10th of the real lists.
    let sample: Vec<&str> = all[..all.len() - 1]
        .iter()
        .flatten()
        .step_by(10)
        .map(String::as_str)
        .collect();
    std::fs::write(out.with_extension("sample"), sample.join("\n")).expect("write sample");
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

fn lookup_cmd(file: &Path, queries: usize) {
    let (base_ws, _) = w4_sys::process::own_usage();
    let start = Instant::now();
    let bl = Blocklist::open(file).expect("open");
    let first = bl.lookup("ads.example.com").is_some();
    let start_to_first = start.elapsed();
    println!(
        "opened {} entries; start to first answer {start_to_first:?} (first lookup blocked: {first})",
        bl.len()
    );
    let sample_text = std::fs::read_to_string(file.with_extension("sample")).expect("sample");
    let sample: Vec<&str> = sample_text.lines().collect();
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    // A mix like real traffic: a third blocked through a parent (a random
    // subdomain of a listed name), two thirds unlisted names 2 to 5 labels
    // deep. Made one at a time, so they don't count in the working set.
    let mut name = |i: usize| {
        if i.is_multiple_of(3) {
            let listed = sample[(rng.next() % sample.len() as u64) as usize];
            format!("{}.{listed}", rng.label(6))
        } else {
            let depth = 2 + (rng.next() % 4) as usize;
            let mut labels: Vec<String> = (0..depth)
                .map(|_| {
                    let len = 3 + (rng.next() % 8) as usize;
                    rng.label(len)
                })
                .collect();
            labels.push("com".into());
            labels.join(".")
        }
    };
    let (rules, _) = Rules::new(Vec::new(), Vec::new(), Vec::new());
    let mut times = Vec::with_capacity(queries);
    let mut blocked = 0;
    let mut kept = Vec::new();
    let mut busy = std::time::Duration::ZERO;
    for i in 0..queries {
        let n = name(i);
        let t = Instant::now();
        if !matches!(rules.decide(&n, Some(&bl)), w4_dns::rules::Verdict::Pass) {
            blocked += 1;
        }
        let took = t.elapsed();
        busy += took;
        times.push(took.as_nanos() as u64);
        if i < 100_000 {
            kept.push(n);
        }
    }
    let total = busy;
    times.sort_unstable();
    let (ws, _) = w4_sys::process::own_usage();
    println!(
        "{queries} lookups ({blocked} blocked), {total:?} spent looking up: p50 {} ns, p99 {} ns, p99.9 {} ns, max {} µs",
        percentile(&times, 0.5),
        percentile(&times, 0.99),
        percentile(&times, 0.999),
        times.last().copied().unwrap_or(0) / 1000
    );
    println!(
        "working set: {:.1} MB before mapping, {:.1} MB after the lookups (the sample of listed names, {:.1} MB, and 100k kept queries included)",
        mb(base_ws),
        mb(ws),
        mb(sample_text.len() as u64 + sample.len() as u64 * 16)
    );
    // Worst case: every page of the file touched.
    for n in &sample {
        let _ = bl.lookup(n);
    }
    let (ws_all, _) = w4_sys::process::own_usage();
    println!(
        "working set with the whole file touched: {:.1} MB",
        mb(ws_all)
    );
    // Regex rules, as in typical regex blocklists, timed apart.
    let patterns: Vec<String> = (0..100)
        .map(|i| format!(r"(^|\.)(ad|track|metric|telemetry){i}[0-9]*\.[a-z]+$"))
        .collect();
    let (with_regex, problems) = Rules::new(Vec::new(), Vec::new(), patterns);
    assert!(problems.is_empty(), "{problems:?}");
    let mut rt = Vec::with_capacity(kept.len());
    for n in &kept {
        let t = Instant::now();
        let _ = with_regex.decide(n, Some(&bl));
        rt.push(t.elapsed().as_nanos() as u64);
    }
    rt.sort_unstable();
    println!(
        "with 100 regex rules: p50 {} ns, p99 {} ns",
        percentile(&rt, 0.5),
        percentile(&rt, 0.99)
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("compile") if args.len() >= 5 => compile_cmd(
            Path::new(&args[2]),
            args[3].parse().expect("pad-to"),
            &args[4..],
        ),
        Some("lookup") if args.len() == 4 => {
            lookup_cmd(Path::new(&args[2]), args[3].parse().expect("queries"))
        }
        _ => eprintln!(
            "usage: blocklist-bench compile <out> <pad-to> <lists...> | lookup <out> <queries>"
        ),
    }
}
