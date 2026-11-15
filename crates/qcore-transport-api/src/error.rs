//! Error, health, event and failure-report types (data-model FailureReport).

use std::fmt;

/// Layer that failed (FR-025, SC-007): validation, transport, chain, scan, config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FailureLayer {
    Validation,
    Transport,
    Chain,
    Scan,
    Config,
    Sidecar,
}

impl fmt::Display for FailureLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            FailureLayer::Validation => "validation",
            FailureLayer::Transport => "transport",
            FailureLayer::Chain => "chain",
            FailureLayer::Scan => "scan",
            FailureLayer::Config => "config",
            FailureLayer::Sidecar => "sidecar",
        };
        write!(f, "{s}")
    }
}

/// Typed failure kind driving a static remedy table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HopErrorKind {
    Validation,
    Transport,
    Chain,
    Scan,
    Config,
    Sidecar,
    Timeout,
    Io,
    Shutdown,
}

/// Hop failure. `message` must already be redacted or redaction-safe:
/// constructors take plain causes and the diag layer re-checks before emit.
#[derive(Debug, Clone)]
pub struct HopError {
    pub kind: HopErrorKind,
    pub hop_id: Option<String>,
    pub message: String,
    /// Retry-vs-terminal verdict (H1.2): `true` only for backpressure
    /// ([`HopError::overloaded`]) — the frame was NOT sent and NOT dropped,
    /// so the caller must retry. Every other failure is terminal (`false`).
    /// Production retry branches read the flag via [`HopError::is_backpressure`];
    /// message wording is free-form, never a contract.
    retryable: bool,
}

impl HopError {
    pub fn new(kind: HopErrorKind, hop_id: Option<String>, message: impl Into<String>) -> Self {
        HopError {
            kind,
            hop_id,
            message: message.into(),
            retryable: false,
        }
    }

    pub fn transport(hop_id: impl Into<String>, message: impl Into<String>) -> Self {
        HopError::new(HopErrorKind::Transport, Some(hop_id.into()), message)
    }

    /// Backpressure signal: the per-hop bounded egress queue is full. The
    /// frame was NOT sent and NOT dropped — the caller must retry (async
    /// senders `await` queue space; `poll_write` parks on a waker). Kind
    /// stays `Transport` (never a new `HopErrorKind` variant) so downstream
    /// exhaustive matches keep compiling: a dedicated kind needs a major
    /// version window (map #7 enum windows). The message prefix stays for
    /// human diagnostics; the machine-readable marker is the `retryable`
    /// flag — see [`HopError::is_backpressure`].
    pub fn overloaded(hop_id: impl Into<String>, message: impl Into<String>) -> Self {
        let mut e = HopError::new(
            HopErrorKind::Transport,
            Some(hop_id.into()),
            format!("egress congested (backpressure; retry): {}", message.into()),
        );
        e.retryable = true;
        e
    }

    /// True for [`HopError::overloaded`] backpressure (retry), false for all
    /// other transport failures (fail). Reads the typed `retryable` flag —
    /// never the message: wording is a human diagnostic, not a contract.
    pub fn is_backpressure(&self) -> bool {
        self.retryable
    }

    pub fn validation(message: impl Into<String>) -> Self {
        HopError::new(HopErrorKind::Validation, None, message)
    }
}

impl fmt::Display for HopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.hop_id {
            Some(id) => write!(f, "[{:?} hop={id}] {}", self.kind, self.message),
            None => write!(f, "[{:?}] {}", self.kind, self.message),
        }
    }
}

impl std::error::Error for HopError {}

impl From<std::io::Error> for HopError {
    fn from(e: std::io::Error) -> Self {
        HopError::new(HopErrorKind::Io, None, e.to_string())
    }
}

/// Hop health snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HopHealth {
    Starting,
    Healthy,
    Degraded,
    Failed,
    Stopped,
}

/// Push-based hop events (engine subscribes; never polls).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum HopEvent {
    Started {
        hop_id: String,
    },
    HealthChanged {
        hop_id: String,
        health: HopHealth,
    },
    EndpointSelected {
        hop_id: String,
        endpoint: String,
    },
    Failed {
        hop_id: String,
        cause: String,
    },
    Stopped {
        hop_id: String,
    },
    /// Congestion accounting (#12 queue decision): `dropped` is the
    /// hop-local cumulative count of frames/events discarded under
    /// congestion (stream-queue overflow, datagram lag, forwarder lag).
    /// Numeric-only payload by construction, so diag redaction passes it
    /// through untouched. Monotonic per hop: a receiver that itself lagged
    /// can still observe the total. New variant (map #7): downstream
    /// exhaustive matches must add a wildcard arm.
    Congested {
        hop_id: String,
        dropped: u64,
    },
}

/// Machine-readable failure record: failing layer + cause (SC-007).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FailureReport {
    pub layer: FailureLayer,
    pub hop_id: String,
    pub cause: String,
    /// Typed failure kind driving a static remedy table.
    pub kind: String,
}

impl FailureReport {
    pub fn new(
        layer: FailureLayer,
        hop_id: impl Into<String>,
        cause: impl Into<String>,
        kind: impl Into<String>,
    ) -> Self {
        FailureReport {
            layer,
            hop_id: hop_id.into(),
            cause: cause.into(),
            kind: kind.into(),
        }
    }
}

impl fmt::Display for FailureReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "layer={} hop={} kind={} cause={}",
            self.layer, self.hop_id, self.kind, self.cause
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overloaded_is_retryable_without_new_kind() {
        // #12/#15: backpressure rides the existing `Transport` kind (a new
        // `HopErrorKind` variant would break downstream exhaustive matches —
        // version-window rule). The typed `retryable` flag is the contract.
        let e = HopError::overloaded("wg-0", "egress queue full");
        assert_eq!(e.kind, HopErrorKind::Transport);
        assert!(e.is_backpressure());
        assert!(e.message.contains("egress queue full"));
        // Ordinary transport failures are NOT backpressure.
        let closed = HopError::transport("wg-0", "egress queue closed");
        assert!(!closed.is_backpressure());
        let other = HopError::transport("wg-0", "encapsulate: NoiseProtocol");
        assert!(!other.is_backpressure());
    }

    #[test]
    fn backpressure_verdict_reads_the_flag_not_the_wording() {
        // H1.2: production retry-vs-terminal branches on the typed flag. A
        // transport error with a DIFFERENT message but retryable=true is
        // backpressure; a same-prefix message without the flag is not.
        let mut flagged = HopError::transport("wg-0", "carrier congestion, retry soon");
        flagged.retryable = true;
        assert!(
            flagged.is_backpressure(),
            "any transport error flagged retryable is backpressure, whatever its wording"
        );

        let wording_only = HopError::transport(
            "wg-0",
            "egress congested (backpressure; retry): forged wording, flag never set",
        );
        assert!(
            !wording_only.is_backpressure(),
            "matching message wording without the flag is terminal"
        );

        let mut unflagged_overload = HopError::new(
            HopErrorKind::Transport,
            Some("wg-0".to_string()),
            "egress congested (backpressure; retry): forged",
        );
        assert!(!unflagged_overload.is_backpressure());
        // The only sanctioned setter is the `overloaded` constructor; direct
        // flag pokes are test-scope (field is private outside this crate).
        unflagged_overload.retryable = true;
        assert!(unflagged_overload.is_backpressure());

        // Non-transport kinds stay terminal even if a caller flagged them.
        let mut chain_flagged = HopError::new(HopErrorKind::Chain, None, "boom");
        chain_flagged.retryable = true;
        assert!(
            chain_flagged.is_backpressure(),
            "flag is authoritative; kind is diagnostic metadata only"
        );

        // The overloaded constructor sets kind + flag together.
        let over = HopError::overloaded("wg-0", "full");
        assert_eq!(over.kind, HopErrorKind::Transport);
        assert!(over.retryable);
    }
}
