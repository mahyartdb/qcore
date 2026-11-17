//! AmneziaWG parameters (US2 T063 carry, US5 T071 application).
//!
//! Params arrive as `awg_*` factory fields from the import record (peer
//! credentials) and/or the obfuscation profile (chain > import > profile
//! precedence in lifecycle). FR-021 is enforced in [`modes`]: these fields
//! on any other peer mode are a build error.
//!
//! Application: the handshake-plane transforms (S1..S4 prefix padding, H1..H4
//! header types, header protection, handshake trailers, content padding)
//! ride the vendored boringtun (`QCORE_PATCHES.md`); the pre-handshake train
//! (I1..I5 signature packets, then `jc` datagrams of `jmin..=jmax` bytes) is
//! sent here because it is uplink policy, not a wire-format transform. Every
//! parsed field is applied or rejected by name — nothing is silently
//! claimed.

use qcore_transport_api::HopConfig;

/// AmneziaWG parameter set.
#[derive(Debug, Clone, Default)]
pub struct AwgParams {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
    pub s1: u32,
    pub s2: u32,
    pub s3: u32,
    pub s4: u32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    /// Server-negotiated header protection (AWG peers only, FR-021).
    pub header_protection: bool,
    /// `HeaderProtectionKey`: 32 bytes shared with the peer. Required when
    /// `header_protection` is set; S1..S4 are then also the nonce material.
    pub header_protection_key: Option<[u8; 32]>,
    pub content_padding_min: u32,
    pub content_padding_max: u32,
    pub random_trailers: bool,
    pub disable_cookies: bool,
}

fn num(cfg: &HopConfig, k: &str) -> Result<u32, String> {
    cfg.get(k)
        .map(|v| {
            v.parse::<u32>()
                .map_err(|_| format!("field `{k}` value `{v}` is not a non-negative integer"))
        })
        .transpose()
        .map(|o| o.unwrap_or(0))
}

fn flag(cfg: &HopConfig, k: &str) -> Result<bool, String> {
    cfg.get(k)
        .map(|v| {
            v.parse::<bool>()
                .map_err(|_| format!("field `{k}` value `{v}` is not a bool"))
        })
        .transpose()
        .map(|o| o.unwrap_or(false))
}

/// Parse `awg_*` factory fields. Unknown `awg_*` fields fail closed.
pub fn parse_fields(cfg: &HopConfig) -> Result<AwgParams, String> {
    const KNOWN: &[&str] = &[
        "awg_jc",
        "awg_jmin",
        "awg_jmax",
        "awg_s1",
        "awg_s2",
        "awg_s3",
        "awg_s4",
        "awg_h1",
        "awg_h2",
        "awg_h3",
        "awg_h4",
        "awg_i1",
        "awg_i2",
        "awg_i3",
        "awg_i4",
        "awg_i5",
        "awg_header_protection",
        "awg_header_protection_key",
        "awg_content_padding_min",
        "awg_content_padding_max",
        "awg_random_trailers",
        "awg_disable_cookies",
    ];
    /// Max pre-handshake junk packets per handshake.
    const MAX_JUNK_COUNT: u32 = 16;
    /// Max junk packet size (bounded framing checked before allocating).
    const MAX_JUNK_SIZE: u32 = 65535;
    if let Some(k) = cfg
        .fields
        .keys()
        .find(|k| k.starts_with("awg_") && !KNOWN.contains(&k.as_str()))
    {
        return Err(format!("unknown AmneziaWG field `{k}`"));
    }
    let jc = num(cfg, "awg_jc")?;
    let jmin = num(cfg, "awg_jmin")?;
    let jmax = num(cfg, "awg_jmax")?;
    if jc > MAX_JUNK_COUNT {
        return Err(format!(
            "field `awg_jc` value `{jc}` exceeds cap {MAX_JUNK_COUNT}"
        ));
    }
    if jmin > MAX_JUNK_SIZE {
        return Err(format!(
            "field `awg_jmin` value `{jmin}` exceeds cap {MAX_JUNK_SIZE}"
        ));
    }
    if jmax > MAX_JUNK_SIZE {
        return Err(format!(
            "field `awg_jmax` value `{jmax}` exceeds cap {MAX_JUNK_SIZE}"
        ));
    }
    if jmin > jmax {
        return Err(format!(
            "field `awg_jmin` value `{jmin}` exceeds `awg_jmax` value `{jmax}`"
        ));
    }
    // Sizes ride the wire as packet lengths: cap them like junk sizes.
    for k in ["awg_s1", "awg_s2", "awg_s3", "awg_s4"] {
        let v = num(cfg, k)?;
        if v > MAX_JUNK_SIZE {
            return Err(format!(
                "field `{k}` value `{v}` exceeds cap {MAX_JUNK_SIZE}"
            ));
        }
    }
    let (h1, h2, h3, h4) = (
        num(cfg, "awg_h1")?,
        num(cfg, "awg_h2")?,
        num(cfg, "awg_h3")?,
        num(cfg, "awg_h4")?,
    );
    // Same pairwise-distinctness rule as the import gate: overlapping
    // headers accepted here but rejected there (or vice versa) would split
    // live vs stored behavior.
    {
        let present: Vec<u32> = [h1, h2, h3, h4].into_iter().filter(|v| *v != 0).collect();
        let mut sorted = present.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != present.len() {
            return Err(
                "fields `awg_h1..awg_h4` must be non-overlapping (pairwise distinct)".to_string(),
            );
        }
    }
    // Free-form junk strings: bounded printable text, never controls or
    // megabytes (they are echoed into handshake-adjacent buffers).
    for k in ["awg_i1", "awg_i2", "awg_i3", "awg_i4", "awg_i5"] {
        if let Some(v) = cfg.get(k) {
            if v.len() > 1024 {
                return Err(format!("field `{k}` exceeds 1024 bytes"));
            }
            if !v.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
                return Err(format!("field `{k}` must be printable ASCII"));
            }
        }
    }
    let content_padding_min = num(cfg, "awg_content_padding_min")?;
    let content_padding_max = num(cfg, "awg_content_padding_max")?;
    if content_padding_min > MAX_JUNK_SIZE || content_padding_max > MAX_JUNK_SIZE {
        return Err(format!("awg content padding exceeds cap {MAX_JUNK_SIZE}"));
    }
    if content_padding_min > content_padding_max {
        return Err(format!(
            "field `awg_content_padding_min` value `{content_padding_min}` exceeds `awg_content_padding_max` value `{content_padding_max}`"
        ));
    }
    let header_protection = flag(cfg, "awg_header_protection")?;
    let header_protection_key = cfg
        .get("awg_header_protection_key")
        .map(|v| {
            crate::modes::parse_key_hex(v)
                .map_err(|e| format!("field `awg_header_protection_key` is invalid: {e}"))
        })
        .transpose()?;
    match (header_protection, header_protection_key) {
        (true, None) => return Err(
            "field `awg_header_protection` requires `awg_header_protection_key` (64 hex chars): \
                 the key cannot be derived from the peer keys"
                .to_string(),
        ),
        (false, Some(_)) => {
            return Err(
                "field `awg_header_protection_key` is set but `awg_header_protection` is false"
                    .to_string(),
            )
        }
        _ => {}
    }
    if header_protection_key.is_some() {
        // amneziawg-go `mergeWithDevice`: the S padding is the nonce source.
        for k in ["awg_s1", "awg_s2", "awg_s3", "awg_s4"] {
            let v = num(cfg, k)?;
            if v < 12 {
                return Err(format!(
                    "field `{k}` value `{v}` must be >= 12 when header protection is enabled"
                ));
            }
        }
    }
    Ok(AwgParams {
        jc,
        jmin,
        jmax,
        s1: num(cfg, "awg_s1")?,
        s2: num(cfg, "awg_s2")?,
        s3: num(cfg, "awg_s3")?,
        s4: num(cfg, "awg_s4")?,
        h1,
        h2,
        h3,
        h4,
        i1: cfg.get("awg_i1").map(str::to_string),
        i2: cfg.get("awg_i2").map(str::to_string),
        i3: cfg.get("awg_i3").map(str::to_string),
        i4: cfg.get("awg_i4").map(str::to_string),
        i5: cfg.get("awg_i5").map(str::to_string),
        header_protection,
        header_protection_key,
        content_padding_min,
        content_padding_max,
        random_trailers: flag(cfg, "awg_random_trailers")?,
        disable_cookies: flag(cfg, "awg_disable_cookies")?,
    })
}

impl AwgParams {
    /// Map onto the vendored boringtun transform parameters. Validation
    /// already happened in [`parse_fields`], so this cannot fail; the
    /// vendored side re-checks the invariants it depends on.
    pub fn to_wire(&self) -> boringtun::noise::awg::AwgParams {
        boringtun::noise::awg::AwgParams {
            s1: self.s1,
            s2: self.s2,
            s3: self.s3,
            s4: self.s4,
            h1: self.h1,
            h2: self.h2,
            h3: self.h3,
            h4: self.h4,
            header_protection_key: self.header_protection_key,
            content_padding_min: self.content_padding_min,
            content_padding_max: self.content_padding_max,
            random_trailers: self.random_trailers,
            disable_cookies: self.disable_cookies,
        }
    }
}

/// Handshake preamble datagrams: I1..I5 signature packets in order, then the
/// `jc` junk train (amneziawg-go `SendHandshakeInitiation` order).
pub fn handshake_preamble(a: &AwgParams) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = [&a.i1, &a.i2, &a.i3, &a.i4, &a.i5]
        .into_iter()
        .filter_map(|packet| packet.as_ref())
        .map(|packet| packet.as_bytes().to_vec())
        .collect();
    out.extend(junk_train(a));
    out
}

/// Junk train packet for `jc`/`jmin`/`jmax` (empty when disabled).
pub fn junk_train(a: &AwgParams) -> Vec<Vec<u8>> {
    if a.jc == 0 {
        return Vec::new();
    }
    // Defense-in-depth caps even for directly constructed params.
    let count = a.jc.min(16);
    let lo = (a.jmin.max(1) as usize).min(65535);
    let hi = (a.jmax.max(a.jmin.max(1)) as usize).min(65535);
    let mut rng = qcore_transport_api::obfuscate::XorShift64::new(
        qcore_transport_api::obfuscate::XorShift64::seed(),
    );
    (0..count)
        .map(|_| qcore_transport_api::obfuscate::junk_packet(&mut rng, lo, hi))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> HopConfig {
        let mut c = HopConfig::new("wireguard");
        for (k, v) in pairs {
            c.fields.insert(k.to_string(), v.to_string());
        }
        c
    }

    #[test]
    fn full_profile_parses() {
        let a = parse_fields(&cfg(&[
            ("awg_jc", "6"),
            ("awg_jmin", "64"),
            ("awg_jmax", "256"),
            ("awg_s1", "24"),
            ("awg_s2", "24"),
            ("awg_s3", "24"),
            ("awg_s4", "24"),
            ("awg_h1", "111"),
            ("awg_i1", "quic"),
            ("awg_header_protection", "true"),
            ("awg_header_protection_key", &"ab".repeat(32)),
            ("awg_content_padding_min", "0"),
            ("awg_content_padding_max", "96"),
            ("awg_random_trailers", "true"),
            ("awg_disable_cookies", "true"),
        ]))
        .expect("parses");
        assert_eq!((a.jc, a.jmin, a.jmax), (6, 64, 256));
        assert!(a.header_protection && a.random_trailers && a.disable_cookies);
        assert!(a.header_protection_key.is_some());
        assert_eq!(junk_train(&a).len(), 6);
    }

    #[test]
    fn header_protection_needs_key_and_nonce_material() {
        // The key cannot be derived: without it the build fails by name.
        let err =
            parse_fields(&cfg(&[("awg_header_protection", "true")])).expect_err("missing key");
        assert!(err.contains("awg_header_protection_key"), "{err}");
        // A key without the flag is a contradiction, not a silent no-op.
        let err = parse_fields(&cfg(&[("awg_header_protection_key", &"ab".repeat(32))]))
            .expect_err("key without flag");
        assert!(err.contains("awg_header_protection"), "{err}");
        // A malformed key fails by field name at the factory boundary.
        let err = parse_fields(&cfg(&[("awg_header_protection_key", "not-hex")]))
            .expect_err("malformed key");
        assert!(err.contains("awg_header_protection_key"), "{err}");
        // amneziawg-go requires S1..S4 >= 12 as the ChaCha20 nonce.
        let err = parse_fields(&cfg(&[
            ("awg_header_protection", "true"),
            ("awg_header_protection_key", &"ab".repeat(32)),
            ("awg_s1", "8"),
        ]))
        .expect_err("short nonce");
        assert!(err.contains("awg_s1") && err.contains("12"), "{err}");
    }

    #[test]
    fn preamble_orders_i_packets_before_junk() {
        let a = parse_fields(&cfg(&[
            ("awg_jc", "2"),
            ("awg_jmin", "8"),
            ("awg_jmax", "8"),
            ("awg_i1", "quic"),
            ("awg_i2", "dns"),
        ]))
        .expect("parses");
        let frames = handshake_preamble(&a);
        assert_eq!(frames.len(), 4, "I1, I2, then 2 junk packets");
        assert_eq!(frames[0], b"quic");
        assert_eq!(frames[1], b"dns");
        assert_eq!(frames[2].len(), 8);
        assert_eq!(frames[3].len(), 8);
    }

    #[test]
    fn unknown_awg_field_rejected() {
        assert!(parse_fields(&cfg(&[("awg_bogus", "1")])).is_err());
    }

    #[test]
    fn awg_param_ranges_validated() {
        // Overlapping headers rejected (same rule as the import gate).
        assert!(parse_fields(&cfg(&[("awg_h1", "5"), ("awg_h2", "5")])).is_err());
        // Oversized padding rejected.
        assert!(parse_fields(&cfg(&[("awg_content_padding_min", "70000")])).is_err());
        // Inverted padding rejected.
        assert!(parse_fields(&cfg(&[
            ("awg_content_padding_min", "100"),
            ("awg_content_padding_max", "10"),
        ]))
        .is_err());
        // Non-printable junk strings rejected; 10 KB strings rejected.
        assert!(parse_fields(&cfg(&[("awg_i1", "a\nb")])).is_err());
        assert!(parse_fields(&cfg(&[("awg_i1", &"x".repeat(2048))])).is_err());
        // Oversized sizes rejected.
        assert!(parse_fields(&cfg(&[("awg_s1", "70000")])).is_err());
    }

    #[test]
    fn disabled_means_no_junk() {
        let a = parse_fields(&cfg(&[])).unwrap();
        assert!(junk_train(&a).is_empty());
    }
}
