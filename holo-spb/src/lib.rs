//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! Shortest Path Bridging (IEEE 802.1aq) computation for IS-IS.
//!
//! This crate holds the algorithmic half of RFC 6329: ECT tie-breaking,
//! per-B-VID shortest path tree computation, agreement digests, multicast
//! tree derivation and forwarding database generation. It is a plain library
//! with no protocol instance of its own — `holo-isis` owns the wire format
//! and the LSDB, builds a [`TopologyView`] from it, and calls in here.
//!
//! [`TopologyView`]: topology::TopologyView

pub mod dataplane;
pub mod digest;
pub mod ect;
pub mod fdb;
pub mod mcast;
pub mod node;
pub mod topology;
pub mod tree;
