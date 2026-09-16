//! Chain validator: sole owner of depth (FR-010a).
//!
//! Total, side-effect-free validation from registry descriptors: presets
//! already expanded; `depth <= max_depth` else an over-depth error naming the
//! hop; no cycles; no local port conflicts (internal listeners use ephemeral
//! ports); a hop needing a UDP carrier after a TCP-only hop is rejected unless
//! the `relay` hop is present — relay recognized from descriptors, so the
//! validator has no build dependency on the relay crate.

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

    // Depth = hops after preset expansion.
    if hops.len() as u32 > max_depth {
        let last = hops.last().unwrap();
        return Err(ChainError::new(
            Some(hops.len() - 1),
            Some(last.id.clone()),
            format!("chain depth {} exceeds max depth {max_depth}", hops.len()),
            Some(format!("reduce to at most {max_depth} hops")),
        ));
    }

    // Duplicate ids (HopSpec id is "unique in chain; used in reports/errors").
    let mut ids = HashSet::new();
    for (i, hop) in hops.iter().enumerate() {
        if !ids.insert(hop.id.clone()) {
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

    // Carrier compatibility from descriptors: a hop that dials UDP needs a
    // carrier providing UDP egress (descriptor dials_udp, or the relay
    // adapter between). The relay itself accepts a TCP carrier and provides
    // UDP-over-TCP framing upward, so it never triggers this rule.
    for pair in hops.windows(2) {
        let (carrier, next) = (&pair[0], &pair[1]);
        let carrier_desc = registry.get(carrier.config.kind()).unwrap();
        let next_desc = registry.get(next.config.kind()).unwrap();
        let carrier_provides_udp =
            carrier_desc.capabilities.dials_udp || carrier.config.kind() == "relay";
        let next_needs_udp = next_desc.capabilities.dials_udp && next.config.kind() != "relay";
        if next_needs_udp && !carrier_provides_udp {
            let idx = hops.iter().position(|h| h.id == next.id).unwrap();
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
    for (i, hop) in hops.iter().enumerate() {
        let cfg = hop.config.to_factory_config();
        if let Some(ep) = cfg.get("endpoint") {
            if ep.contains(&hop.id) {
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
}
