// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>
//!
//! qcore vendors this crate to carry AmneziaWG wire transforms inside the
//! handshake plane. Only the `noise` module is retained; `device`, `ffi` and
//! `jni` (and their dependencies) are removed. Every deviation is listed in
//! `QCORE_PATCHES.md`.

// qcore vends this crate to carry AmneziaWG wire transforms. Trivial lint
// fixes are applied in place; everything else is allowed here and recorded in
// QCORE_PATCHES.md rather than rewriting upstream code.
#![allow(deprecated)] // ring's const-time helper API is deprecated upstream
#![allow(clippy::all)] // upstream style; see QCORE_PATCHES.md

pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
