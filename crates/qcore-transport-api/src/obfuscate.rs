//! Shared obfuscation application helpers (US5 T070/T071).
//!
//! Both the noize junk train (wireguard direct uplinks) and the AmneziaWG
//! pre-handshake junk (wireguard `peer=awg`, direct uplinks) are random-size
//! UDP datagrams sent before the real handshake; responders drop them and
//! the handshake proceeds. This module holds the deterministic PRNG, the
//! packet builder, and the shared [`NoizeParams`] view so the two transports
//! cannot drift. Full per-message AWG transforms (initiation padding,
//! header protection) need handshake-plane access inside boringtun and are
//! explicit follow-up work — params are parsed, validated, carried, and
//! reported, never silently claimed as applied.

/// Deterministic xorshift64 PRNG (unpredictability is not load-bearing: junk
/// only needs size/shape variance).
#[derive(Debug, Clone)]
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        XorShift64 { state: seed | 1 }
    }

    pub fn seed() -> u64 {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0x9E3779B97F4A7C15);
        (t ^ ((std::process::id() as u128) << 32)) as u64
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Uniform value in `[lo, hi]` (inclusive, order-independent).
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        // Overflow-safe span in u128: `hi - lo + 1` overflows usize for the
        // full range (lo=0, hi=MAX) and would divide by zero.
        let span = (hi as u128 - lo as u128) + 1;
        (lo as u128 + (self.next_u64() as u128 % span)) as usize
    }
}

/// One random-fill junk datagram of `min..=max` bytes.
pub fn junk_packet(rng: &mut XorShift64, min: usize, max: usize) -> Vec<u8> {
    let n = rng.range(min.max(1), max.max(min.max(1))).max(1);
    let mut out = vec![0u8; n];
    for chunk in out.chunks_mut(8) {
        let w = rng.next_u64().to_le_bytes();
        let m = chunk.len().min(8);
        chunk.copy_from_slice(&w[..m]);
    }
    out
}

/// Noize profile view over factory fields (`noize_*` namespace).
#[derive(Debug, Clone)]
pub struct NoizeParams {
    pub junk_before: u32,
    pub junk_min: usize,
    pub junk_max: usize,
    /// H2 byte-stream write fragmentation (masque-aggressive).
    pub fragment: Option<usize>,
}

impl NoizeParams {
    /// `None` when no `noize_*` field is present (profile not selected).
    pub fn from_fields(fields: &std::collections::BTreeMap<String, String>) -> Option<Self> {
        if !fields.keys().any(|k| k.starts_with("noize_")) {
            return None;
        }
        let num = |k: &str| {
            fields
                .get(k)
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0)
        };
        let junk_before = num("noize_junk_before") as u32;
        let junk_min = num("noize_junk_min");
        let junk_max = num("noize_junk_max");
        let fragment = fields
            .get("noize_fragment")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|f| *f > 0);
        Some(NoizeParams {
            junk_before,
            junk_min,
            junk_max,
            fragment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn junk_sizes_stay_in_range() {
        let mut rng = XorShift64::new(42);
        for _ in 0..200 {
            let p = junk_packet(&mut rng, 32, 96);
            assert!((32..=96).contains(&p.len()));
        }
    }

    #[test]
    fn params_absent_without_fields() {
        assert!(NoizeParams::from_fields(&Default::default()).is_none());
    }
}
