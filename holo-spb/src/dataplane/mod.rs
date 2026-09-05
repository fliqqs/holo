//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! The client that programs an external SPB dataplane.
//!
//! Forwarding state is pushed over a long-lived gRPC session on a Unix
//! socket. Both ends carry a generation number, so either can restart and
//! resynchronise: on connect the dataplane reports the generation it last
//! committed, and anything older than the control plane's is refreshed with a
//! full snapshot.

mod client;

use std::collections::BTreeMap;

pub use client::{Client, run};
use holo_utils::mac_addr::MacAddr;

use crate::fdb::FdbDelta;
use crate::node::NodeId;

/// A forwarding update, with everything the dataplane needs to act on it.
///
/// The computation itself is interface-free: `holo-spb` names next hops by
/// node, not by port. Resolving those to local interfaces needs the adjacency
/// database, which only `holo-isis` has, so the resolution travels alongside
/// the delta rather than being baked into it.
#[derive(Clone, Debug)]
pub struct DataplaneUpdate {
    pub delta: FdbDelta,
    /// This node's backbone identity.
    pub node: NodeIdentity,
    /// Adjacent node to the local interface reaching it.
    pub nexthops: BTreeMap<NodeId, String>,
    /// Customer-facing interfaces of each service, by I-SID.
    pub uni_ports: BTreeMap<u32, Vec<String>>,
    /// Backbone-facing interfaces.
    pub nni_ports: Vec<String>,
}

/// This node's backbone identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NodeIdentity {
    pub b_mac: MacAddr,
    pub spsource_id: u32,
}

// ===== impl DataplaneUpdate =====

impl DataplaneUpdate {
    /// Returns the interface reaching an adjacent node.
    pub fn nexthop_ifname(&self, node: NodeId) -> Option<&str> {
        self.nexthops.get(&node).map(String::as_str)
    }
}

pub(crate) mod proto {
    #![allow(unreachable_pub, clippy::all)]
    tonic::include_proto!("spb.dataplane");
}
