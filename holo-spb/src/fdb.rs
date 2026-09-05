//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! Forwarding database generation.
//!
//! This is the output of SPB computation: the unicast and multicast tables
//! the dataplane programs into hardware or eBPF maps.
//!
//! Entries name a **next-hop node**, not an interface. Resolving a node to a
//! local interface needs the adjacency database, which lives in `holo-isis`;
//! keeping that resolution at the boundary means nothing here has to model
//! interfaces.

use std::collections::{BTreeMap, BTreeSet};

use holo_utils::mac_addr::MacAddr;
use serde::{Deserialize, Serialize};

use crate::mcast::group_bmac;
use crate::node::NodeId;
use crate::topology::{EctVid, TopologyView};
use crate::tree::{SpbTree, TreeKey, TreeSet};

/// Identifies a unicast forwarding entry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct UnicastKey {
    pub base_vid: u16,
    pub bmac: MacAddr,
}

/// A unicast forwarding entry.
///
/// The same table answers the mandatory ingress check: a frame arriving with
/// `{B-SA, B-VID}` must have come from the node this entry points at.
/// RFC 6329, Section 4.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct UnicastEntry {
    /// The node that owns this B-MAC.
    pub owner: NodeId,
    /// The adjacent node to forward through; `None` when the B-MAC is local.
    pub nexthop: Option<NodeId>,
    pub cost: u32,
}

/// Identifies a multicast forwarding entry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct MulticastKey {
    pub base_vid: u16,
    pub group_bmac: MacAddr,
}

/// A multicast forwarding entry for one `(S, G)` tree.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct MulticastEntry {
    /// The source that roots this distribution tree.
    pub source: NodeId,
    pub isid: u32,
    /// Whether the local node must decapsulate and deliver to its own UNI
    /// ports, i.e. whether it advertised the R bit for this I-SID.
    pub local_deliver: bool,
    /// The downstream branches to replicate onto: the local node's children
    /// on the tree rooted at `source`.
    pub branches: BTreeSet<NodeId>,
}

/// A service instance and the ports/nodes participating in it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ServiceEntry {
    pub base_vid: u16,
    /// Whether the local node transmits into this service.
    pub transmit: bool,
    /// Whether the local node receives from this service.
    pub receive: bool,
    /// Remote nodes participating in the service, with their B-MACs.
    pub members: BTreeMap<NodeId, MacAddr>,
}

/// The complete forwarding state derived from one topology view.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct Fdb {
    pub unicast: BTreeMap<UnicastKey, UnicastEntry>,
    pub multicast: BTreeMap<MulticastKey, MulticastEntry>,
    pub services: BTreeMap<u32, ServiceEntry>,
}

/// An incremental change to the forwarding state.
///
/// This type is what crosses the boundary to the dataplane. It is
/// `Serialize`/`Deserialize` so it can pass through Holo's event recorder,
/// which means FDB changes are captured in conformance-test golden files and
/// can be replayed without a live IS-IS instance.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct FdbDelta {
    /// Monotonic generation, used to reconcile after either side restarts.
    pub generation: u64,
    /// Whether this delta replaces all previous state rather than amending
    /// it.
    pub snapshot: bool,
    pub unicast_added: Vec<(UnicastKey, UnicastEntry)>,
    pub unicast_removed: Vec<UnicastKey>,
    pub multicast_added: Vec<(MulticastKey, MulticastEntry)>,
    pub multicast_removed: Vec<MulticastKey>,
    pub services_added: Vec<(u32, ServiceEntry)>,
    pub services_removed: Vec<u32>,
}

// ===== impl Fdb =====

impl Fdb {
    /// Derives forwarding state from a topology view and its computed trees.
    pub fn build(
        view: &TopologyView,
        trees: &TreeSet,
        mt_id: u16,
        ect_vids: &[EctVid],
    ) -> Self {
        let mut fdb = Fdb::default();

        for ect_vid in ect_vids {
            let local_key = TreeKey {
                mt_id,
                base_vid: ect_vid.base_vid,
                algorithm: ect_vid.algorithm,
                root: view.local,
            };
            let Some(local_tree) = trees.get(&local_key) else {
                continue;
            };

            fdb.build_unicast(view, local_tree, ect_vid);
            fdb.build_multicast(view, trees, mt_id, ect_vid);
        }

        fdb.build_services(view);
        fdb
    }

    /// Populates unicast entries for every B-MAC advertised in the region.
    ///
    /// A node may advertise several B-MACs — a nodal address plus per-port or
    /// per-service ones — so entries are keyed by the advertised B-MAC rather
    /// than derived from the System ID.
    fn build_unicast(
        &mut self,
        view: &TopologyView,
        local_tree: &SpbTree,
        ect_vid: &EctVid,
    ) {
        for (id, node) in &view.nodes {
            if !local_tree.contains(*id) {
                continue;
            }
            let cost = local_tree.cost(*id).unwrap_or(0);
            let nexthop = local_tree.first_hop(*id);

            for svc in &node.services {
                if svc.base_vid != ect_vid.base_vid {
                    continue;
                }
                self.unicast.insert(
                    UnicastKey {
                        base_vid: ect_vid.base_vid,
                        bmac: svc.bmac,
                    },
                    UnicastEntry {
                        owner: *id,
                        nexthop,
                        cost,
                    },
                );
            }
        }
    }

    /// Populates multicast entries for every `(S, G)` tree the local node
    /// participates in.
    ///
    /// The local node's branches on the tree rooted at a source are its
    /// children on that tree — valid because congruence guarantees the tree
    /// computed locally is the one the source computed.
    fn build_multicast(
        &mut self,
        view: &TopologyView,
        trees: &TreeSet,
        mt_id: u16,
        ect_vid: &EctVid,
    ) {
        if !ect_vid.multicast {
            return;
        }

        // A service is bound to one Base VID by its SPBM-SI advertisement, so
        // only the bindings for this Base VID contribute state here.
        for (isid, base_vid) in view.isid_bindings() {
            if base_vid != ect_vid.base_vid {
                continue;
            }

            let local_receives = view
                .nodes
                .get(&view.local)
                .is_some_and(|node| membership(node, isid, base_vid, false));

            for source in view.transmitters_on(isid, base_vid) {
                let Some(source_node) = view.nodes.get(&source) else {
                    continue;
                };
                let key = TreeKey {
                    mt_id,
                    base_vid: ect_vid.base_vid,
                    algorithm: ect_vid.algorithm,
                    root: source,
                };
                let Some(tree) = trees.get(&key) else {
                    continue;
                };
                if !tree.contains(view.local) {
                    continue;
                }

                // Prune each branch to the receivers below it. Without this
                // a node replicates onto every child in the tree, including
                // subtrees holding no member of the service — the copies are
                // carried across the backbone only to be discarded by the
                // far end for want of a matching group address.
                let branches: BTreeSet<NodeId> = tree
                    .children(view.local)
                    .into_iter()
                    .filter(|child| {
                        tree.subtree(*child).iter().any(|node| {
                            view.nodes.get(node).is_some_and(|node| {
                                membership(node, isid, base_vid, false)
                            })
                        })
                    })
                    .collect();
                // A node with no branches and no local delivery has no
                // reason to hold state for this tree.
                if branches.is_empty() && !local_receives {
                    continue;
                }

                self.multicast.insert(
                    MulticastKey {
                        base_vid: ect_vid.base_vid,
                        group_bmac: group_bmac(source_node.spsource_id, isid),
                    },
                    MulticastEntry {
                        source,
                        isid,
                        local_deliver: local_receives,
                        branches,
                    },
                );
            }
        }
    }

    /// Populates per-service state: the local transmit/receive bits and the
    /// remote members reachable in each service.
    fn build_services(&mut self, view: &TopologyView) {
        for (isid, members) in view.isids() {
            let mut entry = ServiceEntry::default();
            for member in members {
                let Some(node) = view.nodes.get(&member) else {
                    continue;
                };
                for svc in &node.services {
                    if !svc.isids.iter().any(|m| m.isid == isid) {
                        continue;
                    }
                    entry.base_vid = svc.base_vid;
                    if member == view.local {
                        entry.transmit |=
                            membership(node, isid, svc.base_vid, true);
                        entry.receive |=
                            membership(node, isid, svc.base_vid, false);
                    } else {
                        entry.members.insert(member, svc.bmac);
                    }
                }
            }
            self.services.insert(isid, entry);
        }
    }

    /// Returns the node a frame with this `{B-SA, B-VID}` must have arrived
    /// from, for the mandatory ingress check.
    pub fn ingress_check(&self, base_vid: u16, bsa: MacAddr) -> Option<NodeId> {
        self.unicast
            .get(&UnicastKey {
                base_vid,
                bmac: bsa,
            })
            .and_then(|entry| entry.nexthop)
    }

    /// Computes the delta from `previous` to `self`.
    pub fn delta(&self, previous: &Fdb, generation: u64) -> FdbDelta {
        let mut delta = FdbDelta {
            generation,
            ..Default::default()
        };

        for (key, entry) in &self.unicast {
            if previous.unicast.get(key) != Some(entry) {
                delta.unicast_added.push((*key, *entry));
            }
        }
        for key in previous.unicast.keys() {
            if !self.unicast.contains_key(key) {
                delta.unicast_removed.push(*key);
            }
        }

        for (key, entry) in &self.multicast {
            if previous.multicast.get(key) != Some(entry) {
                delta.multicast_added.push((*key, entry.clone()));
            }
        }
        for key in previous.multicast.keys() {
            if !self.multicast.contains_key(key) {
                delta.multicast_removed.push(*key);
            }
        }

        for (isid, entry) in &self.services {
            if previous.services.get(isid) != Some(entry) {
                delta.services_added.push((*isid, entry.clone()));
            }
        }
        for isid in previous.services.keys() {
            if !self.services.contains_key(isid) {
                delta.services_removed.push(*isid);
            }
        }

        delta
    }

    /// Returns a delta that installs this state from scratch.
    pub fn snapshot(&self, generation: u64) -> FdbDelta {
        let mut delta = self.delta(&Fdb::default(), generation);
        delta.snapshot = true;
        delta
    }
}

// ===== impl FdbDelta =====

impl FdbDelta {
    /// Returns whether the delta changes anything.
    pub fn is_empty(&self) -> bool {
        self.unicast_added.is_empty()
            && self.unicast_removed.is_empty()
            && self.multicast_added.is_empty()
            && self.multicast_removed.is_empty()
            && self.services_added.is_empty()
            && self.services_removed.is_empty()
    }

    /// Total number of changed entries.
    pub fn len(&self) -> usize {
        self.unicast_added.len()
            + self.unicast_removed.len()
            + self.multicast_added.len()
            + self.multicast_removed.len()
            + self.services_added.len()
            + self.services_removed.len()
    }

    /// Applies this delta to a forwarding table, mirroring what the dataplane
    /// does. Used by tests and by the replay tooling.
    pub fn apply(&self, fdb: &mut Fdb) {
        if self.snapshot {
            *fdb = Fdb::default();
        }
        for key in &self.unicast_removed {
            fdb.unicast.remove(key);
        }
        for (key, entry) in &self.unicast_added {
            fdb.unicast.insert(*key, *entry);
        }
        for key in &self.multicast_removed {
            fdb.multicast.remove(key);
        }
        for (key, entry) in &self.multicast_added {
            fdb.multicast.insert(*key, entry.clone());
        }
        for isid in &self.services_removed {
            fdb.services.remove(isid);
        }
        for (isid, entry) in &self.services_added {
            fdb.services.insert(*isid, entry.clone());
        }
    }
}

/// Returns whether a node advertises `isid` on `base_vid` with the transmit or
/// receive bit set.
fn membership(
    node: &crate::topology::NodeView,
    isid: u32,
    base_vid: u16,
    transmit: bool,
) -> bool {
    node.services.iter().any(|svc| {
        svc.base_vid == base_vid
            && svc.isids.iter().any(|m| {
                m.isid == isid && if transmit { m.transmit } else { m.receive }
            })
    })
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ect::EctAlgorithm;
    use crate::mcast::parse_group_bmac;
    use crate::topology::{IsidMembership, LinkView, NodeView, ServiceView};

    const BVID: u16 = 4000;
    const ISID: u32 = 100;

    fn node(last: u8) -> NodeId {
        NodeId::new([0, 0, 0, 0, 0, last])
    }

    fn bmac(last: u8) -> MacAddr {
        MacAddr::from([0xaa, 0xbb, 0xcc, 0, 0, last])
    }

    fn ect_vid() -> EctVid {
        EctVid {
            base_vid: BVID,
            algorithm: EctAlgorithm::from_index(1).unwrap(),
            spvid: None,
            multicast: true,
        }
    }

    /// A three-node chain rt1 -- rt2 -- rt3, with rt1 and rt3 acting as BEBs
    /// for I-SID 100 and rt2 as a transit BCB.
    ///
    /// `local` selects which node's perspective the view is built from.
    fn chain(local: u8) -> TopologyView {
        let mut view = TopologyView {
            local: node(local),
            ..Default::default()
        };
        for id in [1u8, 2, 3] {
            let services = if id == 2 {
                // The BCB carries no service, only transit.
                vec![]
            } else {
                vec![ServiceView {
                    bmac: bmac(id),
                    base_vid: BVID,
                    isids: vec![IsidMembership {
                        isid: ISID,
                        transmit: true,
                        receive: true,
                    }],
                }]
            };
            view.nodes.insert(
                node(id),
                NodeView {
                    spsource_id: 0x10 + id as u32,
                    ect_vids: vec![ect_vid()],
                    services,
                    ..Default::default()
                },
            );
        }
        for (a, b) in [(1u8, 2u8), (2, 3)] {
            for (from, to) in [(a, b), (b, a)] {
                view.links.push(LinkView {
                    from: node(from),
                    to: node(to),
                    metric: Some(10),
                    port_ids: vec![],
                });
            }
        }
        view
    }

    fn build(local: u8) -> (TopologyView, Fdb) {
        let view = chain(local);
        let (trees, _) = TreeSet::compute(&view, 0, &[ect_vid()], usize::MAX);
        let fdb = Fdb::build(&view, &trees, 0, &[ect_vid()]);
        (view, fdb)
    }

    #[test]
    fn unicast_entries_point_at_the_first_hop() {
        let (_, fdb) = build(1);

        // rt1's own B-MAC is local: no next hop.
        let local = fdb
            .unicast
            .get(&UnicastKey {
                base_vid: BVID,
                bmac: bmac(1),
            })
            .unwrap();
        assert_eq!(local.owner, node(1));
        assert_eq!(local.nexthop, None);
        assert_eq!(local.cost, 0);

        // rt3's B-MAC is two hops away through rt2.
        let remote = fdb
            .unicast
            .get(&UnicastKey {
                base_vid: BVID,
                bmac: bmac(3),
            })
            .unwrap();
        assert_eq!(remote.owner, node(3));
        assert_eq!(remote.nexthop, Some(node(2)));
        assert_eq!(remote.cost, 20);

        // rt2 advertises no B-MAC, so it contributes no unicast entry even
        // though it is on the tree.
        assert!(!fdb.unicast.keys().any(|key| key.bmac == bmac(2)));
    }

    #[test]
    fn ingress_check_uses_the_unicast_table() {
        // On the transit node, a frame from rt1 must arrive from rt1 and a
        // frame from rt3 must arrive from rt3. RFC 6329, Section 4.2.
        let (_, fdb) = build(2);
        assert_eq!(fdb.ingress_check(BVID, bmac(1)), Some(node(1)));
        assert_eq!(fdb.ingress_check(BVID, bmac(3)), Some(node(3)));
        // An unknown B-SA has no expected arrival node.
        assert_eq!(fdb.ingress_check(BVID, bmac(9)), None);
    }

    #[test]
    fn multicast_entry_per_source_tree() {
        let (view, fdb) = build(1);

        // rt1 holds one entry per remote transmitter plus its own head-end
        // tree: sources rt1 and rt3 both transmit into I-SID 100.
        let mut sources: Vec<_> =
            fdb.multicast.values().map(|entry| entry.source).collect();
        sources.sort_unstable();
        assert_eq!(sources, vec![node(1), node(3)]);

        // The group B-MAC encodes the source's SPSourceID and the I-SID.
        let key = MulticastKey {
            base_vid: BVID,
            group_bmac: crate::mcast::group_bmac(0x13, ISID),
        };
        let from_rt3 = fdb.multicast.get(&key).unwrap();
        assert_eq!(from_rt3.source, node(3));
        assert_eq!(from_rt3.isid, ISID);
        assert_eq!(parse_group_bmac(key.group_bmac), Some((0x13, ISID)));

        // rt1 receives from the service and is a leaf on rt3's tree.
        assert!(from_rt3.local_deliver);
        assert!(from_rt3.branches.is_empty());
        assert_eq!(view.local, node(1));
    }

    #[test]
    fn transit_node_replicates_downstream_but_does_not_deliver() {
        let (_, fdb) = build(2);

        let key = MulticastKey {
            base_vid: BVID,
            group_bmac: crate::mcast::group_bmac(0x11, ISID),
        };
        let from_rt1 = fdb.multicast.get(&key).unwrap();
        assert_eq!(from_rt1.source, node(1));
        // rt2 is on rt1's tree with rt3 downstream, so it replicates towards
        // rt3 but has no local receiver of its own.
        assert_eq!(
            from_rt1.branches,
            [node(3)].into_iter().collect::<BTreeSet<_>>()
        );
        assert!(!from_rt1.local_deliver);
    }

    #[test]
    fn service_entry_records_local_bits_and_remote_members() {
        let (_, fdb) = build(1);
        let svc = fdb.services.get(&ISID).unwrap();
        assert_eq!(svc.base_vid, BVID);
        assert!(svc.transmit);
        assert!(svc.receive);
        // Only remote members are listed; rt2 carries no service.
        assert_eq!(svc.members.len(), 1);
        assert_eq!(svc.members.get(&node(3)), Some(&bmac(3)));
    }

    /// rt1 at the centre of a star, with rt2 a member of the service and
    /// rt3 and rt4 not. `local` selects whose view is built.
    fn star(local: u8) -> TopologyView {
        let mut view = TopologyView {
            local: node(local),
            ..Default::default()
        };
        for id in [1u8, 2, 3, 4] {
            // Only rt1 and rt2 belong to the service; rt3 and rt4 are in the
            // region but carry no member of it.
            let services = if matches!(id, 1 | 2) {
                vec![ServiceView {
                    bmac: bmac(id),
                    base_vid: BVID,
                    isids: vec![IsidMembership {
                        isid: ISID,
                        transmit: true,
                        receive: true,
                    }],
                }]
            } else {
                vec![]
            };
            view.nodes.insert(
                node(id),
                NodeView {
                    spsource_id: 0x10 + id as u32,
                    ect_vids: vec![ect_vid()],
                    services,
                    ..Default::default()
                },
            );
        }
        for (a, b) in [(1u8, 2u8), (1, 3), (1, 4)] {
            for (from, to) in [(a, b), (b, a)] {
                view.links.push(LinkView {
                    from: node(from),
                    to: node(to),
                    metric: Some(10),
                    port_ids: vec![],
                });
            }
        }
        view
    }

    /// A branch is only installed if a receiver sits below it.
    ///
    /// Without pruning, rt1 would replicate onto all three of its children
    /// and two of the copies would cross the backbone only to be discarded
    /// by nodes holding no state for the group.
    #[test]
    fn branches_are_pruned_to_subtrees_holding_receivers() {
        let view = star(1);
        let (trees, _) = TreeSet::compute(&view, 0, &[ect_vid()], usize::MAX);
        let fdb = Fdb::build(&view, &trees, 0, &[ect_vid()]);

        let key = MulticastKey {
            base_vid: BVID,
            group_bmac: crate::mcast::group_bmac(0x11, ISID),
        };
        let own_tree = fdb.multicast.get(&key).unwrap();
        assert_eq!(
            own_tree.branches,
            [node(2)].into_iter().collect::<BTreeSet<_>>(),
            "rt3 and rt4 hold no member and must be pruned"
        );
    }

    /// A node with neither a receiver of its own nor one below it holds no
    /// state for the tree at all.
    #[test]
    fn a_node_outside_the_service_holds_no_multicast_state() {
        let view = star(3);
        let (trees, _) = TreeSet::compute(&view, 0, &[ect_vid()], usize::MAX);
        let fdb = Fdb::build(&view, &trees, 0, &[ect_vid()]);
        assert!(
            fdb.multicast.is_empty(),
            "rt3 is a leaf outside the service: {:?}",
            fdb.multicast
        );
    }

    #[test]
    fn multicast_is_skipped_when_the_bvid_carries_none() {
        let view = chain(1);
        let mut vid = ect_vid();
        vid.multicast = false;
        let (trees, _) = TreeSet::compute(&view, 0, &[vid], usize::MAX);
        let fdb = Fdb::build(&view, &trees, 0, &[vid]);
        assert!(!fdb.unicast.is_empty());
        assert!(fdb.multicast.is_empty());
    }

    #[test]
    fn multicast_state_is_confined_to_the_service_base_vid() {
        // Regression: a service is bound to one Base VID by its SPBM-SI
        // advertisement, so a second B-VID configured for a different ECT
        // algorithm must carry trees but no multicast state for that
        // service. Found on a live four-node topology, where I-SID 100 bound
        // to B-VID 4000 also produced entries on B-VID 4001.
        let view = chain(1);
        let second = EctVid {
            base_vid: 4001,
            algorithm: EctAlgorithm::from_index(2).unwrap(),
            spvid: None,
            multicast: true,
        };
        // Every node participates in both tree sets, as it would when two
        // B-VIDs are configured region-wide.
        let mut view = view;
        for node in view.nodes.values_mut() {
            node.ect_vids.push(second);
        }

        let vids = [ect_vid(), second];
        let (trees, _) = TreeSet::compute(&view, 0, &vids, usize::MAX);
        let fdb = Fdb::build(&view, &trees, 0, &vids);

        // Both tree sets exist...
        assert!(trees.iter().any(|(key, _)| key.base_vid == BVID));
        assert!(trees.iter().any(|(key, _)| key.base_vid == 4001));

        // ...but the service's state lives only on its own Base VID.
        assert!(fdb.multicast.keys().all(|key| key.base_vid == BVID));
        assert!(fdb.unicast.keys().all(|key| key.base_vid == BVID));
        assert!(!fdb.multicast.is_empty());
    }

    #[test]
    fn delta_round_trips_through_apply() {
        let (_, fdb) = build(1);

        // A snapshot installs the whole table.
        let mut applied = Fdb::default();
        let snapshot = fdb.snapshot(1);
        assert!(snapshot.snapshot);
        assert_eq!(
            snapshot.len(),
            fdb.unicast.len() + fdb.multicast.len() + fdb.services.len()
        );
        snapshot.apply(&mut applied);
        assert_eq!(applied, fdb);

        // Re-deriving against the same state yields nothing to do.
        let noop = fdb.delta(&applied, 2);
        assert!(noop.is_empty());
        assert_eq!(noop.len(), 0);
    }

    #[test]
    fn delta_reports_additions_and_removals() {
        let (_, before) = build(1);

        // Break the rt2--rt3 link so rt3 becomes unreachable.
        let mut view = chain(1);
        view.links
            .retain(|link| link.from != node(3) && link.to != node(3));
        let (trees, _) = TreeSet::compute(&view, 0, &[ect_vid()], usize::MAX);
        let after = Fdb::build(&view, &trees, 0, &[ect_vid()]);

        let delta = after.delta(&before, 7);
        assert_eq!(delta.generation, 7);
        assert!(!delta.snapshot);
        assert!(
            delta.unicast_removed.contains(&UnicastKey {
                base_vid: BVID,
                bmac: bmac(3)
            }),
            "rt3's B-MAC must be withdrawn"
        );

        // Applying the delta to the old table reproduces the new one.
        let mut applied = before.clone();
        delta.apply(&mut applied);
        assert_eq!(applied, after);
    }

    #[test]
    fn unicast_entries_are_symmetric_across_the_region() {
        // rt1's next hop to rt3 and rt3's next hop to rt1 must both be rt2,
        // which is the forwarding-level consequence of path symmetry.
        let (_, from_rt1) = build(1);
        let (_, from_rt3) = build(3);
        assert_eq!(
            from_rt1
                .unicast
                .get(&UnicastKey {
                    base_vid: BVID,
                    bmac: bmac(3)
                })
                .unwrap()
                .nexthop,
            Some(node(2))
        );
        assert_eq!(
            from_rt3
                .unicast
                .get(&UnicastKey {
                    base_vid: BVID,
                    bmac: bmac(1)
                })
                .unwrap()
                .nexthop,
            Some(node(2))
        );
    }
}
