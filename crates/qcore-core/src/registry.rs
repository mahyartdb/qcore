//! Transport registry built from `inventory` (plan: Plugin registration).
//!
//! Validation, the scanner, profiles, help text and the conformance matrix all
//! read from this registry — never from a `match kind`. Adding a transport is
//! one crate + one `HopFactory` impl + one feature line (FR-006, SC-002c).

use qcore_transport_api::{PluginEntry, TransportDescriptor};
use std::collections::BTreeMap;

/// Owned view of the registered transports.
#[derive(Debug, Default)]
pub struct TransportRegistry {
    kinds: BTreeMap<&'static str, &'static TransportDescriptor>,
}

impl TransportRegistry {
    /// Collect every `register_plugin!` submission linked into this binary.
    pub fn global() -> Self {
        let mut kinds = BTreeMap::new();
        for PluginEntry(factory) in inventory::iter::<PluginEntry> {
            let d = factory.descriptor();
            kinds.insert(d.kind, d);
        }
        TransportRegistry { kinds }
    }

    pub fn get(&self, kind: &str) -> Option<&'static TransportDescriptor> {
        self.kinds.get(kind).copied()
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
        inventory::iter::<PluginEntry>
            .into_iter()
            .find(|e| e.0.descriptor().kind == kind)
            .map(|e| e.0)
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

    #[test]
    fn registry_collects_inventory_plugins() {
        let reg = TransportRegistry::global();
        assert!(reg.get("registry-test").is_some());
        assert!(reg.factory("registry-test").is_some());
        assert!(reg.get("no-such-kind").is_none());
    }
}
