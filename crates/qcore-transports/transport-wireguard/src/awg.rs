//! AmneziaWG parameters (US2 T063 carry, US5 T071 application).
//!
//! Params arrive as `awg_*` factory fields from the import record (peer
//! credentials) and/or the obfuscation profile (chain > import > profile
//! precedence in lifecycle). FR-021 is enforced in [`modes`]: these fields
//! on any other peer mode are a build error.
//!
//! Application v1 (this story): pre-handshake junk train (`jc` packets of
//! `jmin..=jmax` bytes) on direct uplinks, then a plain boringtun handshake
//! carrying the negotiated `s*`/`h*`/`i*` values for reporting. Per-message
//! transforms (initiation padding, header protection on the wire, content
//! padding, trailers, cookie disabling, randomized timers) need handshake-
//! plane access inside boringtun and are explicit follow-up — every param is
//! parsed, validated, carried, and reported, never silently claimed.

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
    Ok(AwgParams {
        jc,
        jmin,
        jmax,
        s1: num(cfg, "awg_s1")?,
        s2: num(cfg, "awg_s2")?,
        s3: num(cfg, "awg_s3")?,
        s4: num(cfg, "awg_s4")?,
        h1: num(cfg, "awg_h1")?,
        h2: num(cfg, "awg_h2")?,
        h3: num(cfg, "awg_h3")?,
        h4: num(cfg, "awg_h4")?,
        i1: cfg.get("awg_i1").map(str::to_string),
        i2: cfg.get("awg_i2").map(str::to_string),
        i3: cfg.get("awg_i3").map(str::to_string),
        i4: cfg.get("awg_i4").map(str::to_string),
        i5: cfg.get("awg_i5").map(str::to_string),
        header_protection: flag(cfg, "awg_header_protection")?,
        content_padding_min: num(cfg, "awg_content_padding_min")?,
        content_padding_max: num(cfg, "awg_content_padding_max")?,
        random_trailers: flag(cfg, "awg_random_trailers")?,
        disable_cookies: flag(cfg, "awg_disable_cookies")?,
    })
}

/// Junk train packets for `jc`/`jmin`/`jmax` (empty when disabled).
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
            ("awg_h1", "111"),
            ("awg_i1", "quic"),
            ("awg_header_protection", "true"),
            ("awg_content_padding_min", "0"),
            ("awg_content_padding_max", "96"),
            ("awg_random_trailers", "true"),
            ("awg_disable_cookies", "true"),
        ]))
        .expect("parses");
        assert_eq!((a.jc, a.jmin, a.jmax), (6, 64, 256));
        assert!(a.header_protection && a.random_trailers && a.disable_cookies);
        assert_eq!(junk_train(&a).len(), 6);
    }

    #[test]
    fn unknown_awg_field_rejected() {
        assert!(parse_fields(&cfg(&[("awg_bogus", "1")])).is_err());
    }

    #[test]
    fn disabled_means_no_junk() {
        let a = parse_fields(&cfg(&[])).unwrap();
        assert!(junk_train(&a).is_empty());
    }
}
