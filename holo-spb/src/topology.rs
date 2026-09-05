//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! The SPB topology view: the boundary between `holo-isis` and `holo-spb`.
//!
//! `holo-isis` owns the LSDB. It builds a [`TopologyView`] — a flat, owned
//! snapshot of everything RFC 6329 computation needs — and hands it over.
//! Nothing in this crate ever sees an LSP.

use std::collections::{BTreeMap, BTreeSet};

use holo_utils::mac_addr::MacAddr;
use serde::{Deserialize, Serialize};

use crate::ect::{BridgeId, EctAlgorithm};
use crate::node::NodeId;

/// The I-SID reserved for SPBM control traffic.
///
/// RFC 6329, Section 4.4.
pub const ISID_CONTROL: u32 = 0x00_0f_ff;

/// Largest valid I-SID (24-bit).
pub const ISID_MAX: u32 = 0x00ff_ffff;

/// Largest valid SPSourceID (20-bit).
pub const SPSOURCE_ID_MAX: u32 = 0x000f_ffff;

/// The SPSourceID value meaning "dynamic assignment has not yet completed".
///
/// RFC 6329, Section 4.4: it is advertised by a node configured to assign its
/// SPSourceID dynamically, which requires LSDB synchronization, before that
/// assignment has finished.
pub const SPSOURCE_ID_UNASSIGNED: u32 = 0;

/// A complete snapshot of the SPB-relevant topology for one IS-IS level.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct TopologyView {
    /// The local node.
    pub local: NodeId,
    /// SPB instances, keyed by MT-ID.
    ///
    /// MT-IDs are carried as raw `u16` because SPB instances are not confined
    /// to the two topologies IS-IS itself models.
    pub instances: BTreeMap<u16, SpbInstanceView>,
    /// Every node advertising SPB capability, keyed by System ID.
    pub nodes: BTreeMap<NodeId, NodeView>,
    /// Directed link advertisements. Each node's view of a link appears as
    /// its own entry, so an asymmetric advertisement is visible rather than
    /// silently reconciled.
    pub links: Vec<LinkView>,
}

/// Per-instance parameters shared across the region.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct SpbInstanceView {
    pub mt_id: u16,
    /// The (algorithm, Base VID) pairs this instance operates on, as
    /// configured locally.
    pub ect_vids: Vec<EctVid>,
}

/// A B-VID and the ECT algorithm that builds its tree set.
///
/// Derived from the VLAN-ID tuples of the SPB-Inst sub-TLV.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct EctVid {
    pub base_vid: u16,
    pub algorithm: EctAlgorithm,
    /// SPBV Shortest Path VID; `None` in SPBM mode.
    pub spvid: Option<u16>,
    /// The M bit: whether this B-VID carries multicast.
    pub multicast: bool,
}

/// One node's SPB advertisement.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct NodeView {
    /// Bridge Priority, the high-order half of the BridgeID.
    pub bridge_priority: u16,
    /// 20-bit SPSourceID used to build multicast destination addresses.
    pub spsource_id: u32,
    /// The V bit: the SPSourceID was auto-allocated rather than configured.
    pub spsource_id_auto: bool,
    /// The SPB overload bit, scoped to SPB adjacencies.
    pub overload: bool,
    /// (algorithm, Base VID) pairs this node advertises support for.
    pub ect_vids: Vec<EctVid>,
    /// SPBM services: a B-MAC with its Base VID and I-SID memberships.
    pub services: Vec<ServiceView>,
}

/// An SPBM-SI advertisement: one B-MAC and the I-SIDs reachable through it.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct ServiceView {
    pub bmac: MacAddr,
    pub base_vid: u16,
    pub isids: Vec<IsidMembership>,
}

/// I-SID membership, with the transmit and receive bits.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct IsidMembership {
    pub isid: u32,
    /// The T bit: this node transmits into the service, so it roots a
    /// multicast distribution tree for it.
    pub transmit: bool,
    /// The R bit: this node receives from the service.
    pub receive: bool,
}

/// One node's advertisement of one link.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct LinkView {
    pub from: NodeId,
    pub to: NodeId,
    /// The 24-bit SPB-LINK-METRIC. `None` when the SPB-Metric sub-TLV was
    /// absent, in which case the adjacency must not carry SPB traffic.
    pub metric: Option<u32>,
    /// Port identifiers from the SPB-Metric sub-TLV.
    pub port_ids: Vec<u16>,
}

// ===== impl TopologyView =====

impl TopologyView {
    /// Returns a node's BridgeID, or `None` if the node is not in the view.
    pub fn bridge_id(&self, node: NodeId) -> Option<BridgeId> {
        self.nodes
            .get(&node)
            .map(|n| BridgeId::new(n.bridge_priority, node.as_bytes()))
    }

    /// Returns the SPB cost of the link between `a` and `b`, or `None` if the
    /// link cannot carry SPB traffic.
    ///
    /// Both directions must be advertised, and the cost is the **maximum** of
    /// the two advertised metrics. RFC 6329, Section 11: "SPB shortest path
    /// calculations Must use the maximum value of the two nodes' advertised
    /// SPB-LINK-METRICs when accumulating and minimizing the (sub)path
    /// costs."
    ///
    /// Resolving the cost symmetrically here, once, is what guarantees that
    /// every tree computed downstream is forward/reverse symmetric even when
    /// the two ends are misconfigured with different metrics.
    pub fn edge_cost(&self, a: NodeId, b: NodeId) -> Option<u32> {
        let fwd = self.link_metric(a, b)?;
        let rev = self.link_metric(b, a)?;
        Some(fwd.max(rev))
    }

    /// Returns the metric `from` advertises for its link to `to`.
    ///
    /// When a node advertises several parallel links to the same neighbor,
    /// the lowest metric wins — it is the best path that node offers.
    fn link_metric(&self, from: NodeId, to: NodeId) -> Option<u32> {
        self.links
            .iter()
            .filter(|link| link.from == from && link.to == to)
            .filter_map(|link| link.metric)
            .min()
    }

    /// Returns whether a node participates in a given (algorithm, B-VID)
    /// tree set.
    pub fn participates(&self, node: NodeId, ect_vid: &EctVid) -> bool {
        self.nodes.get(&node).is_some_and(|n| {
            n.ect_vids.iter().any(|advertised| {
                advertised.base_vid == ect_vid.base_vid
                    && advertised.algorithm == ect_vid.algorithm
            })
        })
    }

    /// Returns whether any node in the region uses a given (algorithm,
    /// Base VID) pair.
    ///
    /// RFC 6329, Section 13.3: the Use-Flag of the SPB-B-VID sub-TLV "is set
    /// if this bridge, or any bridge in the LSDB, is currently using this
    /// ECT-ALGORITHM and Base VID". The local node is part of this view, so
    /// local usage is covered too.
    pub fn ect_vid_in_use(&self, ect_vid: &EctVid) -> bool {
        self.nodes
            .keys()
            .any(|node| self.participates(*node, ect_vid))
    }

    /// Returns the SPB-usable neighbors of `node` within a tree set, with
    /// their resolved costs.
    pub fn neighbors(
        &self,
        node: NodeId,
        ect_vid: &EctVid,
    ) -> Vec<(NodeId, u32)> {
        let mut seen = BTreeMap::new();
        for link in self.links.iter().filter(|link| link.from == node) {
            if !self.participates(link.to, ect_vid) {
                continue;
            }
            let Some(cost) = self.edge_cost(node, link.to) else {
                continue;
            };
            seen.insert(link.to, cost);
        }
        seen.into_iter().collect()
    }

    /// Returns every node that roots a multicast distribution tree for
    /// `isid` — that is, every node advertising it with the T bit set.
    ///
    /// This is what bounds multicast tree computation: per-source trees are
    /// only needed for transmitting sources, not for every node in the
    /// region.
    pub fn transmitters(&self, isid: u32) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|(_, node)| {
                node.services.iter().any(|svc| {
                    svc.isids.iter().any(|m| m.isid == isid && m.transmit)
                })
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Returns every node that roots a multicast distribution tree for
    /// `isid` **on a given Base VID**.
    ///
    /// The SPBM-SI sub-TLV binds a B-MAC and its I-SIDs to one Base VID, so a
    /// service's distribution tree exists only on that Base VID. Ignoring the
    /// binding would create multicast state on every configured B-VID.
    pub fn transmitters_on(&self, isid: u32, base_vid: u16) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|(_, node)| {
                node.services.iter().any(|svc| {
                    svc.base_vid == base_vid
                        && svc
                            .isids
                            .iter()
                            .any(|m| m.isid == isid && m.transmit)
                })
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Returns the (I-SID, Base VID) pairs advertised anywhere in the region.
    pub fn isid_bindings(&self) -> BTreeSet<(u32, u16)> {
        self.nodes
            .values()
            .flat_map(|node| {
                node.services.iter().flat_map(|svc| {
                    svc.isids.iter().map(move |m| (m.isid, svc.base_vid))
                })
            })
            .collect()
    }

    /// Returns every I-SID advertised anywhere in the region.
    pub fn isids(&self) -> BTreeMap<u32, Vec<NodeId>> {
        let mut map: BTreeMap<u32, Vec<NodeId>> = BTreeMap::new();
        for (id, node) in &self.nodes {
            for svc in &node.services {
                for membership in &svc.isids {
                    map.entry(membership.isid).or_default().push(*id);
                }
            }
        }
        for members in map.values_mut() {
            members.dedup();
        }
        map
    }

    /// Detects SPSourceID collisions.
    ///
    /// RFC 6329, Section 14.1: an explicitly configured SPSourceID must be
    /// unique, and on collision "the bridge with the highest priority Bridge
    /// Identifier will win conflicts". The returned map gives, per colliding
    /// SPSourceID, the nodes that lose the conflict and must reallocate.
    pub fn spsource_id_conflicts(&self) -> BTreeMap<u32, Vec<NodeId>> {
        let mut by_id: BTreeMap<u32, Vec<NodeId>> = BTreeMap::new();
        for (id, node) in &self.nodes {
            if node.spsource_id == SPSOURCE_ID_UNASSIGNED {
                // Not yet assigned, so it cannot collide.
                continue;
            }
            by_id.entry(node.spsource_id).or_default().push(*id);
        }

        by_id
            .into_iter()
            .filter(|(_, nodes)| nodes.len() > 1)
            .map(|(spsource_id, mut nodes)| {
                // The highest-priority Bridge Identifier is the numerically
                // lowest BridgeID, so it sorts first and keeps the value.
                nodes.sort_by_key(|node| self.bridge_id(*node));
                nodes.remove(0);
                (spsource_id, nodes)
            })
            .collect()
    }
}
