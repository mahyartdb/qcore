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

/// Caps shared with the AWG path (`awg.rs`): no junk datagram exceeds a UDP
/// payload and no train exceeds 16 packets.
pub const MAX_JUNK_SIZE: usize = 65_535;
pub const MAX_JUNK_COUNT: u32 = 16;

/// One random-fill junk datagram of `min..=max` bytes, clamped to
/// `1..=MAX_JUNK_SIZE` so no input can drive a huge allocation.
pub fn junk_packet(rng: &mut XorShift64, min: usize, max: usize) -> Vec<u8> {
    let lo = min.clamp(1, MAX_JUNK_SIZE);
    let hi = max.max(lo).min(MAX_JUNK_SIZE);
    let n = rng.range(lo, hi).clamp(1, MAX_JUNK_SIZE);
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
    /// Lenient view for compat (masque fragment path): invalid values yield
    /// `None`, never silent zero-params.
    pub fn from_fields(fields: &std::collections::BTreeMap<String, String>) -> Option<Self> {
        Self::try_from_fields(fields).ok().flatten()
    }

    /// Strict parse: non-numeric values, sizes above [`MAX_JUNK_SIZE`],
    /// counts above [`MAX_JUNK_COUNT`], inverted ranges, or bad fragment
    /// values are `Err` naming the field (matching `awg_jc=many` behavior).
    pub fn try_from_fields(
        fields: &std::collections::BTreeMap<String, String>,
    ) -> Result<Option<Self>, String> {
        if !fields.keys().any(|k| k.starts_with("noize_")) {
            return Ok(None);
        }
        let num = |k: &str| -> Result<usize, String> {
            match fields.get(k) {
                None => Ok(0),
                Some(v) => v
                    .parse::<usize>()
                    .map_err(|_| format!("`{k}` value `{v}` is not a non-negative integer")),
            }
        };
        let junk_before = num("noize_junk_before")?;
        let junk_min = num("noize_junk_min")?;
        let junk_max = num("noize_junk_max")?;
        if junk_before > MAX_JUNK_COUNT as usize {
            return Err(format!(
                "`noize_junk_before` value `{junk_before}` exceeds {MAX_JUNK_COUNT}"
            ));
        }
        if junk_min > MAX_JUNK_SIZE || junk_max > MAX_JUNK_SIZE {
            let bad = if junk_min > MAX_JUNK_SIZE {
                junk_min
            } else {
                junk_max
            };
            return Err(format!("noize junk size `{bad}` exceeds {MAX_JUNK_SIZE}"));
        }
        if junk_min > 0 && junk_max > 0 && junk_min > junk_max {
            return Err(format!(
                "`noize_junk_min` value `{junk_min}` exceeds `noize_junk_max` value `{junk_max}`"
            ));
        }
        let fragment = match fields.get("noize_fragment") {
            None => None,
            Some(v) => match v.parse::<usize>() {
                Err(_) => {
                    return Err(format!(
                        "`noize_fragment` value `{v}` is not a non-negative integer"
                    ));
                }
                Ok(0) => None,
                Ok(f) => Some(f),
            },
        };
        Ok(Some(NoizeParams {
            junk_before: junk_before as u32,
            junk_min,
            junk_max,
            fragment,
        }))
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

    fn fields(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn huge_junk_max_rejected_not_allocated() {
        let f = fields(&[
            ("noize_junk_before", "16"),
            ("noize_junk_min", "1"),
            ("noize_junk_max", "200000000"),
        ]);
        let err = NoizeParams::try_from_fields(&f).expect_err("huge max must error");
        assert!(err.contains("noize"), "names the field: {err}");
        let mut rng = XorShift64::new(7);
        assert!(junk_packet(&mut rng, 32, 200_000_000).len() <= MAX_JUNK_SIZE);
    }

    #[test]
    fn non_numeric_junk_before_errors_not_silent_zero() {
        let f = fields(&[("noize_junk_before", "many")]);
        let err = NoizeParams::try_from_fields(&f).expect_err("non-numeric must error");
        assert!(err.contains("noize_junk_before"), "names the field: {err}");
        assert!(NoizeParams::from_fields(&f).is_none());
    }

    #[test]
    fn junk_count_capped_at_parse() {
        let ok = fields(&[("noize_junk_before", "16")]);
        assert!(NoizeParams::try_from_fields(&ok).unwrap().is_some());
        let over = fields(&[("noize_junk_before", "17")]);
        assert!(NoizeParams::try_from_fields(&over).is_err());
    }

    #[test]
    fn inverted_junk_range_rejected_and_builder_clamped() {
        let f = fields(&[
            ("noize_junk_before", "4"),
            ("noize_junk_min", "256"),
            ("noize_junk_max", "64"),
        ]);
        assert!(NoizeParams::try_from_fields(&f).is_err());
        let mut rng = XorShift64::new(9);
        assert!((1..=MAX_JUNK_SIZE).contains(&junk_packet(&mut rng, 256, 64).len()));
        assert!((1..=MAX_JUNK_SIZE).contains(&junk_packet(&mut rng, 0, 0).len()));
    }
}
