//! Transport registry built from `inventory` (plan: Plugin registration).
//!
//! Validation, the scanner, profiles, help text and the conformance matrix all
//! read from this registry — never from a `match kind`. Adding a transport is
//! one crate + one `HopFactory` impl + one feature line (FR-006, SC-002c).

use qcore_transport_api::{PluginEntry, TransportDescriptor};
use std::collections::BTreeMap;

/// Owned view of the registered transports.
#[derive(Default)]
pub struct TransportRegistry {
    kinds: BTreeMap<&'static str, &'static TransportDescriptor>,
    factories: BTreeMap<&'static str, &'static dyn qcore_transport_api::HopFactory>,
    /// Kinds submitted more than once (copy-paste `register_plugin!`): kept
    /// visible instead of silently diverging. `get` and `factory` must agree:
    /// last-wins in one but first-match in the other would let validation
    /// and build disagree on the same kind.
    duplicates: Vec<&'static str>,
}

impl std::fmt::Debug for TransportRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportRegistry")
            .field("kinds", &self.kinds.keys().collect::<Vec<_>>())
            .field("duplicates", &self.duplicates)
            .finish()
    }
}

impl TransportRegistry {
    /// Collect every `register_plugin!` submission linked into this binary.
    /// First submission wins for both descriptor and factory; repeats are
    /// recorded in [`TransportRegistry::duplicates`] instead of silently
    /// splitting validation from build.
    pub fn global() -> Self {
        let mut kinds = BTreeMap::new();
        let mut factories = BTreeMap::new();
        let mut duplicates = Vec::new();
        for PluginEntry(factory) in inventory::iter::<PluginEntry> {
            let d = factory.descriptor();
            if kinds.contains_key(d.kind) {
                if !duplicates.contains(&d.kind) {
                    duplicates.push(d.kind);
                }
                continue;
            }
            kinds.insert(d.kind, d);
            factories.insert(d.kind, *factory);
        }
        TransportRegistry {
            kinds,
            factories,
            duplicates,
        }
    }

    pub fn get(&self, kind: &str) -> Option<&'static TransportDescriptor> {
        self.kinds.get(kind).copied()
    }

    /// Kinds registered more than once. Empty in a healthy binary; non-empty
    /// means two crates claimed one kind and only the first is live.
    pub fn duplicates(&self) -> &[&'static str] {
        &self.duplicates
    }

    pub fn kinds(&self) -> Vec<&'static str> {
        self.kinds.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    pub fn factory(&self, kind: &str) -> Option<&'static dyn qcore_transport_api::HopFactory> {
        // Same snapshot as `get`: validation and build can never disagree,
        // including for `TransportRegistry::default()` (empty means unknown
        // in both, not "unknown here, buildable there").
        self.factories.get(kind).copied()
    }
}

impl crate::chain::validate::DescriptorSource for TransportRegistry {
    fn get(&self, kind: &str) -> Option<&'static TransportDescriptor> {
        TransportRegistry::get(self, kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFactory;
    static TEST_FACTORY: TestFactory = TestFactory;

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for TestFactory {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &TEST_DESCRIPTOR
        }

        async fn build(
            &self,
            _cfg: qcore_transport_api::HopConfig,
            _carrier: std::sync::Arc<dyn qcore_transport_api::Dialer>,
        ) -> Result<
            std::sync::Arc<dyn qcore_transport_api::RunningHop>,
            qcore_transport_api::HopError,
        > {
            Err(qcore_transport_api::HopError::validation("test-only"))
        }
    }

    static TEST_DESCRIPTOR: TransportDescriptor = TransportDescriptor {
        kind: "registry-test",
        capabilities: qcore_transport_api::Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        },
        obfuscation_families: &[],
        config_schema: "registry-test/v1",
        needs_sidecar: false,
    };

    qcore_transport_api::register_plugin!(&TEST_FACTORY);

    struct DupFactoryA;
    static DUP_FACTORY_A: DupFactoryA = DupFactoryA;

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for DupFactoryA {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &DUP_DESCRIPTOR_A
        }

        async fn build(
            &self,
            _cfg: qcore_transport_api::HopConfig,
            _carrier: std::sync::Arc<dyn qcore_transport_api::Dialer>,
        ) -> Result<
            std::sync::Arc<dyn qcore_transport_api::RunningHop>,
            qcore_transport_api::HopError,
        > {
            Err(qcore_transport_api::HopError::validation("dup-a"))
        }
    }

    static DUP_DESCRIPTOR_A: TransportDescriptor = TransportDescriptor {
        kind: "registry-dup-kind",
        capabilities: qcore_transport_api::Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        },
        obfuscation_families: &[],
        config_schema: "registry-dup-a/v1",
        needs_sidecar: false,
    };

    struct DupFactoryB;
    static DUP_FACTORY_B: DupFactoryB = DupFactoryB;

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for DupFactoryB {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &DUP_DESCRIPTOR_B
        }

        async fn build(
            &self,
            _cfg: qcore_transport_api::HopConfig,
            _carrier: std::sync::Arc<dyn qcore_transport_api::Dialer>,
        ) -> Result<
            std::sync::Arc<dyn qcore_transport_api::RunningHop>,
            qcore_transport_api::HopError,
        > {
            Err(qcore_transport_api::HopError::validation("dup-b"))
        }
    }

    static DUP_DESCRIPTOR_B: TransportDescriptor = TransportDescriptor {
        kind: "registry-dup-kind",
        capabilities: qcore_transport_api::Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        },
        obfuscation_families: &[],
        config_schema: "registry-dup-b/v1",
        needs_sidecar: false,
    };

    qcore_transport_api::register_plugin!(&DUP_FACTORY_A);
    qcore_transport_api::register_plugin!(&DUP_FACTORY_B);

    #[test]
    fn registry_collects_inventory_plugins() {
        let reg = TransportRegistry::global();
        assert!(reg.get("registry-test").is_some());
        assert!(reg.factory("registry-test").is_some());
        assert!(reg.get("no-such-kind").is_none());
        // An empty registry is unknown in BOTH views (the old `factory`
        // re-iterated global inventory and disagreed with `get`).
        let empty = TransportRegistry::default();
        assert!(empty.get("wireguard").is_none());
        assert!(empty.factory("wireguard").is_none());
    }

    #[test]
    fn duplicate_kind_first_wins_and_is_visible() {
        let reg = TransportRegistry::global();
        assert!(
            reg.duplicates().contains(&"registry-dup-kind"),
            "dup reported: {:?}",
            reg.duplicates()
        );
        // Descriptor and factory agree (same first submission), and the
        // winner is one of the two submissions — never a mix.
        let live = reg.get("registry-dup-kind").expect("dup kind present");
        assert!(reg.factory("registry-dup-kind").is_some());
        assert!(
            live.config_schema == "registry-dup-a/v1" || live.config_schema == "registry-dup-b/v1"
        );
    }
}
