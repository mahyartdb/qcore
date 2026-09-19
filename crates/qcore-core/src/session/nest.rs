//! Nested-hop bring-up support (US3 T058).
//!
//! Inner hops ride outer hops through the abstract [`Dialer`]: a nested hop
//! drives its data plane over carrier flows/streams instead of OS sockets.
//! Per-layer inner-MTU shrink: each encapsulation layer budgets 80 bytes of
//! headers (outer IP/UDP + tunnel framing), floored at the IPv6 minimum.
//! [`PmtuProber`] tracks RFC 4821-style packetization probing per nested
//! uplink: consecutive timeout/IO failures decay the reported MTU and the
//! decay is reported in the failure cause.
//!
//! Runtime nesting matrix (US3): mock and relay are transparent/framing
//! carriers; wireguard and masque-h2 ride nested carriers; masque-h3 (QUIC),
//! tor (arti circuits) and psiphon (sidecar SOCKS) use direct egress in US3
//! and report `nested: false`. Their descriptors still validate in any
//! order; full virtualization is explicit future work, never silently
//! claimed.

/// Base path MTU for a direct hop.
pub const DIRECT_MTU: u16 = 1500;
/// Per encapsulation layer overhead budget (outer IP/UDP + tunnel headers).
pub const LAYER_OVERHEAD: u16 = 80;
/// Floor: IPv6 minimum MTU (never black-hole by shrinking past it).
pub const MIN_MTU: u16 = 1280;

/// Inner MTU at `depth` (0 = outermost): shrink per layer, floored.
pub fn layer_mtu(depth: u32) -> u16 {
    DIRECT_MTU
        .saturating_sub(LAYER_OVERHEAD.saturating_mul(depth.min(3) as u16))
        .max(MIN_MTU)
}

/// RFC 4821-style prober for one nested uplink. Starts at the layered MTU;
/// two consecutive timeout/IO losses step down through the probe sizes;
/// a success recovers one step. Cross-session memory is future work
/// (US4 endpoints cache); within one bring-up the decay is reported.
#[derive(Debug, Clone)]
pub struct PmtuProber {
    sizes: Vec<u16>,
    index: usize,
    consecutive_losses: u32,
}

impl PmtuProber {
    pub fn new(layered_mtu: u16) -> Self {
        let mut sizes = vec![layered_mtu];
        let mut next = layered_mtu;
        // Probe steps down toward the floor.
        for step in [128u16, 192, 256] {
            if next > MIN_MTU + step {
                next -= step;
                sizes.push(next);
            }
        }
        if *sizes
            .last()
            .expect("sizes starts with one entry and only grows")
            != MIN_MTU
        {
            sizes.push(MIN_MTU);
        }
        PmtuProber {
            sizes,
            index: 0,
            consecutive_losses: 0,
        }
    }

    /// Currently probed-good MTU.
    pub fn current_mtu(&self) -> u16 {
        self.sizes[self.index]
    }

    /// A nested build attempt failed with timeout/IO. Returns the new MTU
    /// when the prober stepped down (caller reports it), else `None`.
    pub fn report_loss(&mut self) -> Option<u16> {
        self.consecutive_losses += 1;
        if self.consecutive_losses >= 2 && self.index + 1 < self.sizes.len() {
            self.index += 1;
            self.consecutive_losses = 0;
            Some(self.sizes[self.index])
        } else {
            None
        }
    }

    pub fn report_success(&mut self) {
        self.consecutive_losses = 0;
        if self.index > 0 {
            self.index -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_shrinks_per_layer_with_floor() {
        assert_eq!(layer_mtu(0), 1500);
        assert_eq!(layer_mtu(1), 1420);
        assert_eq!(layer_mtu(2), 1340);
        assert_eq!(layer_mtu(3), 1280);
        assert_eq!(layer_mtu(9), 1280);
    }

    #[test]
    fn prober_decays_on_repeated_loss_and_recovers() {
        let mut p = PmtuProber::new(1420);
        assert_eq!(p.current_mtu(), 1420);
        assert_eq!(p.report_loss(), None);
        let down = p.report_loss().expect("steps down");
        assert!(down < 1420);
        let at = p.current_mtu();
        p.report_success();
        // One success recovers one step toward the layered ceiling.
        assert!(p.current_mtu() >= at);
        // Success recovers toward the layered ceiling.
        for _ in 0..8 {
            p.report_success();
        }
        assert_eq!(p.current_mtu(), 1420);
    }

    #[test]
    fn prober_never_below_floor() {
        let mut p = PmtuProber::new(1500);
        for _ in 0..20 {
            p.report_loss();
        }
        assert!(p.current_mtu() >= MIN_MTU);
    }
}
