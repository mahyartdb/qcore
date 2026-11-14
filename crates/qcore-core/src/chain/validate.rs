//! Chain validator: sole owner of depth (FR-010a).
//!
//! Total, side-effect-free validation from registry descriptors: presets
//! already expanded; `depth <= max_depth` (and always `depth <= 5`, the
//! documented hard limit) else an over-depth error naming the hop; no
//! cycles; no local port conflicts (internal listeners use ephemeral
//! ports); a hop needing carrier UDP datagrams after a TCP-only hop is
//! rejected unless a UDP-over-TCP adapter (relay-shaped capabilities:
//! accepts TCP without consuming carrier datagrams) is present. Adapter
//! recognition is purely capability-driven — no kind literals — so adding
//! a transport never requires validator edits (FR-006).

use crate::chain::ChainError;
use crate::config::HopSpec;
use qcore_transport_api::TransportDescriptor;
use std::collections::{BTreeMap, HashSet};

/// Descriptor lookup. Implemented by [`crate::registry::TransportRegistry`];
/// tests use [`TestDescriptors`].
pub trait DescriptorSource {
    fn get(&self, kind: &str) -> Option<&'static TransportDescriptor>;
}

/// Validate an expanded hop list. Index 0 = outermost carrier.
pub fn validate(
    hops: &[HopSpec],
    max_depth: u32,
    registry: &impl DescriptorSource,
) -> Result<(), ChainError> {
    if hops.is_empty() {
        return Err(ChainError::new(
            None,
            None,
            "chain is empty".to_string(),
            Some("declare at least one hop".to_string()),
        ));
    }

    // Depth = hops after preset expansion. The hard ceiling (FR-010a: 5)
    // applies regardless of the configured max_depth: embedders pass their
    // own budgets, but no chain deeper than the documented hard limit is
    // ever valid.
    if hops.len() as u32 > crate::config::chain_file::HARD_MAX_DEPTH {
        let last = hops.last().expect("nonempty checked above");
        return Err(ChainError::new(
            Some(hops.len() - 1),
            Some(last.id.clone()),
            format!(
                "chain depth {} exceeds hard limit {}",
                hops.len(),
                crate::config::chain_file::HARD_MAX_DEPTH
            ),
            Some("split into shorter chains".to_string()),
        ));
    }
    if hops.len() as u32 > max_depth {
        let last = hops.last().expect("nonempty checked above");
        return Err(ChainError::new(
            Some(hops.len() - 1),
            Some(last.id.clone()),
            format!("chain depth {} exceeds max depth {max_depth}", hops.len()),
            Some(format!("reduce to at most {max_depth} hops")),
        ));
    }

    // Duplicate ids (HopSpec id is "unique in chain; used in reports/errors").
    // Borrowed set: no per-hop clone on the happy path (errors clone once).
    let mut ids = HashSet::new();
    for (i, hop) in hops.iter().enumerate() {
        if !ids.insert(hop.id.as_str()) {
            return Err(ChainError::new(
                Some(i),
                Some(hop.id.clone()),
                format!("duplicate hop id `{}`", hop.id),
                Some("give each hop a unique id".to_string()),
            ));
        }
    }

    // Unknown transport kinds (must be registered plugins).
    for (i, hop) in hops.iter().enumerate() {
        if registry.get(hop.config.kind()).is_none() {
            return Err(ChainError::new(
                Some(i),
                Some(hop.id.clone()),
                format!("unknown transport kind `{}`", hop.config.kind()),
                Some("run `qcore ls` for registered transports".to_string()),
            ));
        }
    }

    // Sidecar requirement from descriptors: a transport that spawns a local
    // helper process (`needs_sidecar`, e.g. psiphon) needs its executable
    // path authored on the hop — an empty sidecar_path would pass preflight
    // and die at factory build (with sockets). Fail closed here instead.
    for (i, hop) in hops.iter().enumerate() {
        let Some(desc) = registry.get(hop.config.kind()) else {
            continue;
        };
        if !desc.needs_sidecar {
            continue;
        }
        let empty = match hop.config.to_factory_config().fields.get("sidecar_path") {
            None => true,
            Some(p) => p.trim().is_empty(),
        };
        if empty {
            return Err(ChainError::new(
                Some(i),
                Some(hop.id.clone()),
                format!(
                    "hop `{}` (transport `{}`) requires `sidecar_path=<executable path>`",
                    hop.id,
                    hop.config.kind()
                ),
                Some(format!(
                    "pass `sidecar_path=` pointing at the {} helper executable",
                    desc.kind
                )),
            ));
        }
    }

    // Carrier compatibility from descriptors: a hop that dials UDP datagrams
    // from its carrier needs a carrier providing UDP egress. A hop that
    // frames UDP over a TCP carrier (accepts_tcp_carrier without
    // accepts_udp_carrier — the relay adapter shape) is exempt: it consumes
    // no carrier datagrams. Any future adapter with relay-shaped
    // capabilities passes with no validator edits (FR-006).
    for (idx, pair) in hops.windows(2).enumerate() {
        let (carrier, next) = (&pair[0], &pair[1]);
        let unknown = |hop: &HopSpec| {
            ChainError::new(
                None,
                Some(hop.id.clone()),
                format!("unknown transport kind `{}`", hop.config.kind()),
                Some("run `qcore ls` for registered transports".to_string()),
            )
        };
        // No `expect` on registry lookups: a non-deterministic source (or a
        // snapshot-vs-live skew) fails closed with a typed error, never a
        // panic on user input.
        let Some(carrier_desc) = registry.get(carrier.config.kind()) else {
            return Err(unknown(carrier));
        };
        let Some(next_desc) = registry.get(next.config.kind()) else {
            return Err(unknown(next));
        };
        let carrier_provides_udp = carrier_desc.capabilities.dials_udp;
        let next_needs_udp =
            next_desc.capabilities.dials_udp && next_desc.capabilities.accepts_udp_carrier;
        if next_needs_udp && !carrier_provides_udp {
            // `next` is `pair[1]` of window `idx`, so its hop index is
            // `idx + 1` by construction — no `position` rescan, no expect.
            let idx = idx + 1;
            return Err(ChainError::new(
                Some(idx),
                Some(next.id.clone()),
                format!(
                    "hop `{}` requires a UDP carrier but carrier `{}` is TCP-only",
                    next.id, carrier.id
                ),
                Some(format!("insert `relay` after `{}`", carrier.config.kind())),
            ));
        }
    }

    // Cycles: a hop targeting its own listener rejects before starting.
    // Compare the endpoint host for equality, not substring: hop `wg-0`
    // must not reject `wg-01.example.com:51820`.
    for (i, hop) in hops.iter().enumerate() {
        let cfg = hop.config.to_factory_config();
        if let Some(ep) = cfg.get("endpoint") {
            let host = ep.rsplit_once(':').map(|(h, _)| h).unwrap_or(ep);
            if host == hop.id {
                return Err(ChainError::new(
                    Some(i),
                    Some(hop.id.clone()),
                    format!("hop `{}` targets its own listener", hop.id),
                    None,
                ));
            }
        }
    }

    // Port conflicts: internal listeners use ephemeral ports, so only explicit
    // duplicate non-ephemeral bind endpoints conflict.
    let mut binds = HashSet::new();
    for (i, hop) in hops.iter().enumerate() {
        let cfg = hop.config.to_factory_config();
        if let Some(bind) = cfg.get("bind") {
            if !bind.ends_with(":0") && !binds.insert(bind.to_string()) {
                return Err(ChainError::new(
                    Some(i),
                    Some(hop.id.clone()),
                    format!("two hops claim local endpoint `{bind}`"),
                    Some("use ephemeral :0 listeners".to_string()),
                ));
            }
        }
    }

    Ok(())
}

/// Test descriptor source.
#[derive(Default)]
pub struct TestDescriptors {
    map: BTreeMap<&'static str, &'static TransportDescriptor>,
}

impl TestDescriptors {
    pub fn with(mut self, d: &'static TransportDescriptor) -> Self {
        self.map.insert(d.kind, d);
        self
    }

    /// wireguard (UDP) + tor (TCP-only) + relay (adapter).
    pub fn standard() -> Self {
        TestDescriptors::default()
            .with(&WG_DESC)
            .with(&TOR_DESC)
            .with(&RELAY_DESC)
    }
}

impl DescriptorSource for TestDescriptors {
    fn get(&self, kind: &str) -> Option<&'static TransportDescriptor> {
        self.map.get(kind).copied()
    }
}

static WG_DESC: TransportDescriptor = TransportDescriptor {
    kind: "wireguard",
    capabilities: qcore_transport_api::Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: true,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[],
    config_schema: "test",
    needs_sidecar: false,
};

static TOR_DESC: TransportDescriptor = TransportDescriptor {
    kind: "tor",
    capabilities: qcore_transport_api::Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: true,
        dials_tcp: true,
        dials_udp: false,
    },
    obfuscation_families: &[],
    config_schema: "test",
    needs_sidecar: false,
};

static RELAY_DESC: TransportDescriptor = TransportDescriptor {
    kind: "relay",
    capabilities: qcore_transport_api::Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: false,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[],
    config_schema: "test",
    needs_sidecar: false,
};

/// Sidecar-requiring transport (the psiphon shape): needs_sidecar true.
#[cfg(test)]
static SIDECAR_DESC: TransportDescriptor = TransportDescriptor {
    kind: "sidecar-test",
    capabilities: qcore_transport_api::Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: true,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[],
    config_schema: "test",
    needs_sidecar: true,
};

/// Hypothetical second UDP-over-TCP adapter: relay-shaped capabilities under
/// a different kind. Must pass with no validator edits (FR-006).
#[cfg(test)]
static RELAY2_DESC: TransportDescriptor = TransportDescriptor {
    kind: "relay2",
    capabilities: qcore_transport_api::Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: false,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[],
    config_schema: "test",
    needs_sidecar: false,
};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{HopConfig, TorConfig, WireguardConfig};

    pub fn wg(id: &str) -> HopSpec {
        HopSpec {
            id: id.into(),
            config: HopConfig::Wireguard(WireguardConfig {
                peer: "warp".into(),
                import_ref: None,
                obfuscation: None,
                family: "dual".into(),
                endpoint: None,
            }),
        }
    }

    pub fn tor(id: &str) -> HopSpec {
        HopSpec {
            id: id.into(),
            config: HopConfig::Tor(TorConfig {
                family: "dual".into(),
            }),
        }
    }

    #[test]
    fn single_hop_valid() {
        validate(&[wg("wg0")], 3, &TestDescriptors::standard()).unwrap();
    }

    #[test]
    fn over_depth_names_the_hop() {
        let hops = vec![wg("a"), wg("b"), wg("c"), wg("d")];
        let err = validate(&hops, 3, &TestDescriptors::standard()).unwrap_err();
        assert_eq!(err.hop_index, Some(3));
        assert_eq!(err.hop_id.as_deref(), Some("d"));
        assert!(err.reason.contains("exceeds max depth 3"));
    }

    #[test]
    fn bare_tor_wireguard_rejected_naming_relay_insertion() {
        let err = validate(&[tor("t"), wg("w")], 3, &TestDescriptors::standard()).unwrap_err();
        assert_eq!(err.hop_id.as_deref(), Some("w"));
        assert!(err.fix.as_deref() == Some("insert `relay` after `tor`"));
    }

    #[test]
    fn tor_relay_wireguard_valid() {
        use crate::config::{HopConfig, RelayConfig};
        let hops = vec![
            tor("t"),
            HopSpec {
                id: "r".into(),
                config: HopConfig::Relay(RelayConfig {
                    family: "dual".into(),
                }),
            },
            wg("w"),
        ];
        validate(&hops, 3, &TestDescriptors::standard()).unwrap();
    }

    #[test]
    fn warp_then_tor_valid() {
        validate(&[wg("w"), tor("t")], 3, &TestDescriptors::standard()).unwrap();
    }

    #[test]
    fn generic_adapter_passes_without_validator_edits() {
        use crate::config::hop::PluginHopConfig;
        use std::collections::BTreeMap;
        // relay2: relay-shaped capabilities (accepts TCP, no carrier
        // datagrams, dials UDP) under another kind. tor → relay2 → wg must
        // validate with no kind literals in the validator (FR-006).
        let adapter = HopSpec {
            id: "r2".into(),
            config: HopConfig::Plugin(PluginHopConfig {
                kind: "relay2".into(),
                family: "dual".into(),
                fields: BTreeMap::new(),
            }),
        };
        let source = TestDescriptors::default()
            .with(&TOR_DESC)
            .with(&RELAY2_DESC)
            .with(&WG_DESC);
        validate(&[tor("t"), adapter, wg("w")], 3, &source).expect("generic adapter passes");
        // And the negative still holds through the same path: tor → wg
        // without an adapter rejects.
        let err = validate(&[tor("t"), wg("w")], 3, &source).unwrap_err();
        assert!(err.reason.contains("UDP carrier"), "{}", err.reason);
    }

    #[test]
    fn hard_ceiling_holds_despite_generous_budget() {
        let hops = vec![wg("a"), wg("b"), wg("c"), wg("d"), wg("e"), wg("f")];
        let err = validate(&hops, 99, &TestDescriptors::standard()).unwrap_err();
        assert!(err.reason.contains("hard limit 5"), "{}", err.reason);
    }

    #[test]
    fn flaky_source_fails_closed_not_panics() {
        // A source that answers Some then None (snapshot skew) must yield a
        // typed error, never the old `expect` panic.
        struct Flaky;
        impl DescriptorSource for Flaky {
            fn get(&self, kind: &str) -> Option<&'static TransportDescriptor> {
                if kind == "tor" {
                    Some(&TOR_DESC)
                } else {
                    None
                }
            }
        }
        let err = validate(&[tor("t"), wg("w")], 3, &Flaky).unwrap_err();
        assert!(
            err.reason.contains("unknown transport kind `wireguard`"),
            "{}",
            err.reason
        );
    }

    #[test]
    fn duplicate_id_rejected() {
        let err = validate(&[wg("a"), wg("a")], 3, &TestDescriptors::standard()).unwrap_err();
        assert!(err.reason.contains("duplicate hop id"));
    }

    #[test]
    fn unknown_kind_rejected() {
        use crate::config::MockConfig;
        let hops = vec![HopSpec {
            id: "m".into(),
            config: HopConfig::Mock(MockConfig {
                family: "dual".into(),
            }),
        }];
        let err = validate(&hops, 3, &TestDescriptors::standard()).unwrap_err();
        assert!(err.reason.contains("unknown transport kind `mock`"));
    }

    #[test]
    fn empty_chain_rejected() {
        assert!(validate(&[], 3, &TestDescriptors::standard()).is_err());
    }

    fn sidecar_hop(id: &str, sidecar_path: &str) -> HopSpec {
        use crate::config::hop::PluginHopConfig;
        use crate::config::HopConfig;
        HopSpec {
            id: id.into(),
            config: HopConfig::Plugin(PluginHopConfig {
                kind: "sidecar-test".into(),
                family: "dual".into(),
                fields: if sidecar_path.is_empty() {
                    std::collections::BTreeMap::new()
                } else {
                    std::collections::BTreeMap::from([(
                        "sidecar_path".to_string(),
                        sidecar_path.to_string(),
                    )])
                },
            }),
        }
    }

    #[test]
    fn sidecar_transport_without_sidecar_path_rejected_at_validation() {
        // Descriptor says needs_sidecar: an empty/absent sidecar_path must
        // fail at validation (zero sockets), not at factory build.
        let source = TestDescriptors::default().with(&SIDECAR_DESC);
        for id in ["psi-0", "psi-1"] {
            let err = validate(&[sidecar_hop(id, "")], 3, &source).unwrap_err();
            assert!(
                err.reason.contains("sidecar_path") && err.reason.contains("sidecar-test"),
                "names field and transport: {err}"
            );
            assert_eq!(err.hop_id.as_deref(), Some(id));
        }
    }

    #[test]
    fn sidecar_transport_with_sidecar_path_valid() {
        let source = TestDescriptors::default().with(&SIDECAR_DESC);
        validate(
            &[sidecar_hop("psi-0", "/usr/local/bin/psiphon")],
            3,
            &source,
        )
        .expect("authored sidecar_path validates");
    }

    #[test]
    fn non_sidecar_transports_unaffected_by_sidecar_gate() {
        // needs_sidecar=false kinds pass with no sidecar_path (regression
        // guard: the gate must key off the descriptor, not the kind).
        validate(&[wg("w")], 3, &TestDescriptors::standard()).expect("no sidecar needed");
    }

    #[test]
    fn similar_endpoint_prefix_is_not_a_cycle() {
        use crate::config::HopSpec;
        let spec = HopSpec {
            id: "wg-0".into(),
            config: crate::config::HopConfig::Wireguard(WireguardConfig {
                peer: "warp".into(),
                import_ref: None,
                obfuscation: None,
                family: "dual".into(),
                endpoint: Some("wg-01.example.com:51820".into()),
            }),
        };
        validate(std::slice::from_ref(&spec), 3, &TestDescriptors::standard())
            .expect("prefix match is not self-targeting");
    }
}
