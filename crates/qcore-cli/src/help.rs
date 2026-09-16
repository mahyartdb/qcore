//! Lawful-use + jurisdiction statements (T092).
//!
//! Shown by `qcore legal` (text or `--json`). These are product statements,
//! not legal advice: the tool ships no jurisdiction-tuned evasion defaults,
//! and every obfuscation/scan profile is data the operator selects.

/// Plain-text rendering for `qcore legal`.
pub const LEGAL_TEXT: &str = "\
qcore lawful-use statement
=========================

WARP (Cloudflare): use only with a lawful subscription and only where you
are authorized to tunnel traffic. qcore speaks to WARP endpoints as a
client; it does not bypass account, billing, or access controls.

Psiphon: integration is authorized-use only. You must run a Psiphon
endpoint you operate or are explicitly permitted to use, and pass its
location via an explicit sidecar path (qcore never resolves a Psiphon
binary from PATH by default).

Tor: qcore routes through the Tor network via arti where linked. Tor
provides no legal protection by itself; you are responsible for complying
with the laws of your jurisdiction. qcore makes no anonymity or
legal-protection claims beyond what the underlying network provides.

Jurisdiction defaults: qcore ships no jurisdiction-tuned evasion presets.
Scan profiles (turbo/balanced/stealth) trade speed for politeness, and
obfuscation profiles are labeled data — selecting one is an explicit
operator decision, logged in the connection report (active_scan_profile /
active_obfuscation).
";

/// Machine-readable rendering for `qcore legal --json`.
pub fn legal_json() -> serde_json::Value {
    serde_json::json!({
        "warp": "lawful subscription and authorized use only; no bypass of account, billing, or access controls",
        "psiphon": "authorized integration only; explicit sidecar path, never resolved from PATH by default",
        "tor": "no legal-protection claims; operator complies with local law",
        "jurisdiction_defaults": "none shipped; profiles are explicit operator-selected data, recorded in the connection report",
    })
}

pub fn run(json: bool) -> i32 {
    if json {
        println!("{}", legal_json());
    } else {
        print!("{LEGAL_TEXT}");
    }
    crate::exit::SUCCESS
}
