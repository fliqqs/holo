//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! Shortest path tree computation for SPB.
//!
//! SPB needs trees that IS-IS's own SPF does not produce: a *single*
//! deterministic path per destination chosen by an ECT algorithm (rather than
//! an ECMP set), rooted at an arbitrary node, and keyed by (B-VID,
//! algorithm). RFC 6329, Section 4 requires the result to be shortest-path,
//! forward/reverse symmetric for any source/destination pair, and congruent
//! between unicast and multicast.
//!
//! Symmetry and congruence are not extra passes over the result; they follow
//! from two properties established elsewhere:
//!
//! - link costs are resolved symmetrically at view construction time
//!   ([`TopologyView::edge_cost`]), and
//! - the tie-break is a total order that is symmetric and transitive
//!   ([`PathId`]).
//!
//! Together these mean the tree rooted at a node is identical no matter which
//! node in the region computes it, so a node can derive its own position in a
//! remote source's distribution tree without any coordination.
//!
//! [`TopologyView::edge_cost`]: crate::topology::TopologyView::edge_cost
//! [`PathId`]: crate::ect::PathId

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ect::{EctAlgorithm, PathId, PathRank};
use crate::node::NodeId;
use crate::topology::{EctVid, TopologyView};

/// A shortest path tree rooted at one node, for one (B-VID, algorithm) pair.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct SpbTree {
    pub root: NodeId,
    pub base_vid: u16,
    pub algorithm: EctAlgorithm,
    /// Every reachable node, including the root at zero cost.
    pub nodes: BTreeMap<NodeId, TreeNode>,
}

/// One node's position in a tree.
#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct TreeNode {
    /// Accumulated SPB cost from the root.
    pub cost: u32,
    /// Hop count from the root.
    pub hops: u16,
    /// The node one hop closer to the root; `None` for the root itself.
    ///
    /// There is exactly one parent: SPB selects a single path, not an ECMP
    /// set.
    pub parent: Option<NodeId>,
    /// The neighbor of the root on the path to this node; `None` for the
    /// root.
    pub first_hop: Option<NodeId>,
    /// The tie-breaking identity of the selected path.
    pub path_id: PathId,
}

/// A candidate in the Dijkstra frontier.
///
/// `BTreeMap` is used as the priority queue so that the ordering is exactly
/// the SPB total order — cost, then hops, then PATHID, with the node ID as a
/// final disambiguator so distinct nodes never collide as keys.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CandidateKey {
    cost: u32,
    hops: u16,
    path_id: PathId,
    node: NodeId,
}

#[derive(Clone, Debug)]
struct Candidate {
    parent: Option<NodeId>,
    first_hop: Option<NodeId>,
}

// ===== impl SpbTree =====

impl SpbTree {
    /// Computes the shortest path tree rooted at `root`.
    ///
    /// Nodes that do not advertise support for `ect_vid`, and links whose two
    /// ends do not both advertise an SPB metric, are excluded. A node with
    /// the SPB overload bit set is reachable but is not used for transit,
    /// except when it is the root.
    pub fn compute(
        view: &TopologyView,
        root: NodeId,
        ect_vid: &EctVid,
    ) -> Self {
        let mut tree = SpbTree {
            root,
            base_vid: ect_vid.base_vid,
            algorithm: ect_vid.algorithm,
            nodes: BTreeMap::new(),
        };

        if !view.participates(root, ect_vid) {
            return tree;
        }

        let mut cand: BTreeMap<CandidateKey, Candidate> = BTreeMap::new();
        cand.insert(
            CandidateKey {
                cost: 0,
                hops: 0,
                path_id: PathId::empty(),
                node: root,
            },
            Candidate {
                parent: None,
                first_hop: None,
            },
        );

        while let Some((key, entry)) = cand.pop_first() {
            // The first time a node is popped, its path is the best one: the
            // ordering is a total order and every extension is monotone in
            // it, so no later candidate can beat it.
            if tree.nodes.contains_key(&key.node) {
                continue;
            }
            tree.nodes.insert(
                key.node,
                TreeNode {
                    cost: key.cost,
                    hops: key.hops,
                    parent: entry.parent,
                    first_hop: entry.first_hop,
                    path_id: key.path_id.clone(),
                },
            );

            // An overloaded node is reachable but must not be transited.
            let overloaded =
                view.nodes.get(&key.node).is_some_and(|node| node.overload);
            if overloaded && key.node != root {
                continue;
            }

            // Extending the path through `key.node` makes it an intermediate
            // node, so it joins the PATHID. The root is an endpoint, not an
            // intermediate node, and never contributes.
            let extended_path_id = if key.node == root {
                PathId::empty()
            } else {
                let Some(bridge_id) = view.bridge_id(key.node) else {
                    continue;
                };
                key.path_id.with_node(bridge_id, ect_vid.algorithm)
            };

            for (neighbor, edge_cost) in view.neighbors(key.node, ect_vid) {
                if tree.nodes.contains_key(&neighbor) {
                    continue;
                }
                let Some(cost) = key.cost.checked_add(edge_cost) else {
                    continue;
                };
                let hops = key.hops.saturating_add(1);
                let first_hop = entry.first_hop.or(Some(neighbor));

                let new_key = CandidateKey {
                    cost,
                    hops,
                    path_id: extended_path_id.clone(),
                    node: neighbor,
                };

                // Keep only the best candidate per node, so the frontier
                // cannot grow without bound on dense topologies.
                let existing =
                    cand.keys().find(|k| k.node == neighbor).cloned();
                if let Some(existing) = existing {
                    let new_rank = PathRank {
                        cost: new_key.cost,
                        hops: new_key.hops,
                        path_id: &new_key.path_id,
                    };
                    let old_rank = PathRank {
                        cost: existing.cost,
                        hops: existing.hops,
                        path_id: &existing.path_id,
                    };
                    if new_rank >= old_rank {
                        continue;
                    }
                    cand.remove(&existing);
                }

                cand.insert(
                    new_key,
                    Candidate {
                        parent: Some(key.node),
                        first_hop,
                    },
                );
            }
        }

        tree
    }

    /// Returns whether a node is on this tree.
    pub fn contains(&self, node: NodeId) -> bool {
        self.nodes.contains_key(&node)
    }

    /// Returns the cost from the root to a node.
    pub fn cost(&self, node: NodeId) -> Option<u32> {
        self.nodes.get(&node).map(|entry| entry.cost)
    }

    /// Returns the root's neighbor on the path to a node — the next hop when
    /// this tree is rooted locally.
    pub fn first_hop(&self, node: NodeId) -> Option<NodeId> {
        self.nodes.get(&node).and_then(|entry| entry.first_hop)
    }

    /// Returns the direct children of a node on this tree.
    ///
    /// For a tree rooted at a multicast source, the children of the local
    /// node are exactly the branches it must replicate onto. Congruence is
    /// what makes this valid: the tree computed here is the same one the
    /// source computes.
    pub fn children(&self, node: NodeId) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|(_, entry)| entry.parent == Some(node))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Returns every node at or below `node` on this tree.
    ///
    /// Used to prune a multicast branch: a branch is only worth installing if
    /// the subtree beneath it holds a receiver for the service. Walking down
    /// from each child is cheap because a tree gives every node exactly one
    /// parent, so the descent visits each node at most once.
    pub fn subtree(&self, node: NodeId) -> BTreeSet<NodeId> {
        let mut found = BTreeSet::new();
        let mut pending = vec![node];
        while let Some(current) = pending.pop() {
            if !found.insert(current) {
                continue;
            }
            pending.extend(self.children(current));
        }
        found
    }

    /// Returns the path from the root to a node, root first.
    pub fn path_to(&self, node: NodeId) -> Option<Vec<NodeId>> {
        let mut path = Vec::new();
        let mut current = node;
        loop {
            let entry = self.nodes.get(&current)?;
            path.push(current);
            match entry.parent {
                Some(parent) => current = parent,
                None => break,
            }
            // Defend against a malformed tree rather than looping forever.
            if path.len() > self.nodes.len() {
                return None;
            }
        }
        path.reverse();
        Some(path)
    }

    /// Returns the set of nodes reachable on this tree.
    pub fn reachable(&self) -> BTreeSet<NodeId> {
        self.nodes.keys().copied().collect()
    }
}

/// A cache of computed trees, keyed by (MT-ID, B-VID, algorithm, root).
///
/// Per-source trees are only needed for nodes that actually root a multicast
/// distribution tree, which is what keeps this from being an all-pairs
/// computation on every topology change.
#[derive(Clone, Debug, Default)]
pub struct TreeSet {
    trees: BTreeMap<TreeKey, SpbTree>,
}

/// Identifies one tree within a region.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub struct TreeKey {
    pub mt_id: u16,
    pub base_vid: u16,
    pub algorithm: EctAlgorithm,
    pub root: NodeId,
}

// ===== impl TreeSet =====

impl TreeSet {
    /// Computes the trees needed for one instance: the locally rooted tree
    /// per (algorithm, B-VID), plus one tree per multicast transmitter.
    ///
    /// `max_trees` bounds the work; when the bound is hit, computation stops
    /// and the number of trees that were skipped is returned so it can be
    /// surfaced as state rather than silently degrading forwarding.
    pub fn compute(
        view: &TopologyView,
        mt_id: u16,
        ect_vids: &[EctVid],
        max_trees: usize,
    ) -> (Self, usize) {
        let mut set = TreeSet::default();
        let mut skipped = 0;

        // Every multicast source needs its own tree, since a node must know
        // its position in each source's distribution tree to replicate.
        let mut roots = BTreeSet::new();
        roots.insert(view.local);
        for (isid, _) in view.isids() {
            for transmitter in view.transmitters(isid) {
                roots.insert(transmitter);
            }
        }

        for ect_vid in ect_vids {
            for root in &roots {
                let key = TreeKey {
                    mt_id,
                    base_vid: ect_vid.base_vid,
                    algorithm: ect_vid.algorithm,
                    root: *root,
                };
                if set.trees.len() >= max_trees {
                    skipped += 1;
                    continue;
                }
                set.trees
                    .insert(key, SpbTree::compute(view, *root, ect_vid));
            }
        }

        (set, skipped)
    }

    pub fn get(&self, key: &TreeKey) -> Option<&SpbTree> {
        self.trees.get(key)
    }

    pub fn insert(&mut self, key: TreeKey, tree: SpbTree) {
        self.trees.insert(key, tree);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&TreeKey, &SpbTree)> {
        self.trees.iter()
    }

    pub fn len(&self) -> usize {
        self.trees.len()
    }

    pub fn is_empty(&self) -> bool {
        self.trees.is_empty()
    }
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ect::ECT_ALG_DEFAULT;
    use crate::topology::{LinkView, NodeView};

    fn node(last: u8) -> NodeId {
        NodeId::new([0, 0, 0, 0, 0, last])
    }

    fn ect_vid(algo_index: u8) -> EctVid {
        EctVid {
            base_vid: 4000,
            algorithm: EctAlgorithm::from_index(algo_index).unwrap(),
            spvid: None,
            multicast: true,
        }
    }

    /// Builds a view from an undirected edge list, with every node
    /// participating in both algorithm 1 and algorithm 2 on B-VID 4000.
    fn view(local: u8, edges: &[(u8, u8, u32)]) -> TopologyView {
        let mut view = TopologyView {
            local: node(local),
            ..Default::default()
        };
        let ect_vids = vec![ect_vid(1), ect_vid(2)];
        for (a, b, metric) in edges {
            for id in [*a, *b] {
                view.nodes.entry(node(id)).or_insert_with(|| NodeView {
                    ect_vids: ect_vids.clone(),
                    ..Default::default()
                });
            }
            view.links.push(LinkView {
                from: node(*a),
                to: node(*b),
                metric: Some(*metric),
                port_ids: vec![],
            });
            view.links.push(LinkView {
                from: node(*b),
                to: node(*a),
                metric: Some(*metric),
                port_ids: vec![],
            });
        }
        view
    }

    /// The RFC 6329 Section 11 example topology: from node :1, two
    /// equal-cost sub-paths to :7 fork at :1 and join at :7, one via :2 and
    /// one via :6.
    fn rfc_fig2() -> TopologyView {
        view(1, &[(1, 2, 10), (1, 6, 10), (2, 7, 10), (6, 7, 10)])
    }

    #[test]
    fn link_cost_is_max_of_the_two_advertisements() {
        // RFC 6329, Section 11: the maximum of the two advertised
        // SPB-LINK-METRICs must be used.
        let mut v = view(1, &[(1, 2, 10)]);
        for link in &mut v.links {
            if link.from == node(1) {
                link.metric = Some(30);
            }
        }
        assert_eq!(v.edge_cost(node(1), node(2)), Some(30));
        // The cost is the same in both directions, which is what forces
        // symmetric paths despite the asymmetric configuration.
        assert_eq!(v.edge_cost(node(2), node(1)), Some(30));
    }

    #[test]
    fn link_without_spb_metric_is_unusable() {
        // "If this sub-TLV is not present for an IS-IS adjacency, then that
        // adjacency Must not carry SPB traffic."
        let mut v = view(1, &[(1, 2, 10), (2, 3, 10)]);
        for link in &mut v.links {
            if link.from == node(2) && link.to == node(3) {
                link.metric = None;
            }
        }
        assert_eq!(v.edge_cost(node(2), node(3)), None);
        let tree = SpbTree::compute(&v, node(1), &ect_vid(1));
        assert!(tree.contains(node(2)));
        assert!(!tree.contains(node(3)), "must not transit a non-SPB link");
    }

    #[test]
    fn default_algorithm_breaks_the_rfc_tie_via_node_2() {
        let v = rfc_fig2();
        let tree = SpbTree::compute(&v, node(1), &ect_vid(1));
        assert_eq!(tree.cost(node(7)), Some(20));
        // "the default tie-breaking rule causes the path traversing node :2
        // to be selected since it has a lower BridgeID."
        assert_eq!(tree.first_hop(node(7)), Some(node(2)));
        assert_eq!(
            tree.path_to(node(7)),
            Some(vec![node(1), node(2), node(7)])
        );
    }

    #[test]
    fn algorithm_two_breaks_the_same_tie_the_other_way() {
        let v = rfc_fig2();
        let tree = SpbTree::compute(&v, node(1), &ect_vid(2));
        assert_eq!(tree.cost(node(7)), Some(20));
        // ECT-MASK{2} inverts the BridgeID, so the higher one wins.
        assert_eq!(tree.first_hop(node(7)), Some(node(6)));
    }

    #[test]
    fn bridge_priority_overrides_the_tie_break() {
        // RFC 6329, Section 11: "the operator may cause the tie-breaking
        // logic to pick the alternate path by raising the Bridge Priority of
        // node :2 above that of :6."
        let mut v = rfc_fig2();
        v.nodes.get_mut(&node(2)).unwrap().bridge_priority = 100;
        let tree = SpbTree::compute(&v, node(1), &ect_vid(1));
        assert_eq!(tree.first_hop(node(7)), Some(node(6)));
    }

    #[test]
    fn every_node_has_exactly_one_parent() {
        // SPB selects a single path per destination, never an ECMP set.
        let v = rfc_fig2();
        let tree = SpbTree::compute(&v, node(1), &ect_vid(1));
        for (id, entry) in &tree.nodes {
            if *id == tree.root {
                assert!(entry.parent.is_none());
            } else {
                assert!(entry.parent.is_some());
            }
        }
    }

    #[test]
    fn trees_are_forward_and_reverse_symmetric() {
        // RFC 6329, Section 4: routes must be forward- and reverse-path
        // symmetric with respect to any source/destination pair.
        let v = rfc_fig2();
        let ids: Vec<_> = v.nodes.keys().copied().collect();
        for algo in [1u8, 2u8] {
            let vid = ect_vid(algo);
            for a in &ids {
                for b in &ids {
                    let ta = SpbTree::compute(&v, *a, &vid);
                    let tb = SpbTree::compute(&v, *b, &vid);
                    assert_eq!(
                        ta.cost(*b),
                        tb.cost(*a),
                        "cost {a}->{b} must equal {b}->{a}"
                    );
                    let (Some(mut pa), Some(mut pb)) =
                        (ta.path_to(*b), tb.path_to(*a))
                    else {
                        continue;
                    };
                    pb.reverse();
                    assert_eq!(
                        pa, pb,
                        "path {a}->{b} must be the reverse of {b}->{a}"
                    );
                    pa.sort_unstable();
                    assert!(pa.windows(2).all(|w| w[0] != w[1]));
                }
            }
        }
    }

    #[test]
    fn trees_are_identical_regardless_of_who_computes_them() {
        // Congruence depends on this: a node derives its position in a
        // remote source's distribution tree by computing that source's tree
        // locally, which is only valid if the result is identical.
        let v = rfc_fig2();
        let vid = ect_vid(1);
        let from_1 = SpbTree::compute(&v, node(7), &vid);

        let mut v_other = v.clone();
        v_other.local = node(6);
        let from_6 = SpbTree::compute(&v_other, node(7), &vid);

        for id in v.nodes.keys() {
            assert_eq!(from_1.cost(*id), from_6.cost(*id));
            assert_eq!(from_1.path_to(*id), from_6.path_to(*id));
        }
    }

    #[test]
    fn multicast_branches_are_congruent_with_the_unicast_tree() {
        // RFC 6329, Section 4: the SPT to a given node is congruent with the
        // MDT from that node, so the branches a node replicates onto for
        // source S are exactly its children in SPT(S).
        let v = rfc_fig2();
        let vid = ect_vid(1);
        let from_7 = SpbTree::compute(&v, node(7), &vid);

        // On the tree rooted at :7, node :2 is on the path to :1, so :2
        // replicates towards :1.
        assert_eq!(from_7.children(node(2)), vec![node(1)]);
        assert_eq!(from_7.first_hop(node(1)), Some(node(2)));

        // Every child's path to the root goes through its parent.
        for (id, entry) in &from_7.nodes {
            if let Some(parent) = entry.parent {
                let path = from_7.path_to(*id).unwrap();
                assert_eq!(path[path.len() - 2], parent);
            }
        }
    }

    #[test]
    fn overloaded_node_is_reachable_but_not_transited() {
        let mut v = view(1, &[(1, 2, 10), (2, 3, 10)]);
        v.nodes.get_mut(&node(2)).unwrap().overload = true;
        let tree = SpbTree::compute(&v, node(1), &ect_vid(1));
        assert!(tree.contains(node(2)));
        assert!(!tree.contains(node(3)));
    }

    #[test]
    fn node_not_advertising_the_bvid_is_excluded() {
        let mut v = view(1, &[(1, 2, 10), (2, 3, 10)]);
        v.nodes.get_mut(&node(2)).unwrap().ect_vids.clear();
        let tree = SpbTree::compute(&v, node(1), &ect_vid(1));
        assert!(!tree.contains(node(2)));
        assert!(!tree.contains(node(3)));
    }

    #[test]
    fn hop_count_breaks_ties_before_path_id() {
        // Two paths of equal cost but different hop counts: the shorter must
        // win regardless of BridgeIDs. :1 reaches :5 either directly at cost
        // 20, or via the cheap two-hop chain through :2 and :3.
        let v = view(1, &[(1, 5, 20), (1, 2, 5), (2, 3, 5), (3, 5, 10)]);
        let tree = SpbTree::compute(&v, node(1), &ect_vid(1));
        assert_eq!(tree.cost(node(5)), Some(20));
        assert_eq!(tree.first_hop(node(5)), Some(node(5)));
        assert_eq!(tree.nodes[&node(5)].hops, 1);
    }

    #[test]
    fn tree_set_computes_local_and_transmitter_roots() {
        use holo_utils::mac_addr::MacAddr;

        use crate::topology::{IsidMembership, ServiceView};

        let mut v = rfc_fig2();
        // :7 transmits into I-SID 100; :1 only receives.
        v.nodes.get_mut(&node(7)).unwrap().services = vec![ServiceView {
            bmac: MacAddr::from([0xaa, 0, 0, 0, 0, 7]),
            base_vid: 4000,
            isids: vec![IsidMembership {
                isid: 100,
                transmit: true,
                receive: true,
            }],
        }];
        v.nodes.get_mut(&node(1)).unwrap().services = vec![ServiceView {
            bmac: MacAddr::from([0xaa, 0, 0, 0, 0, 1]),
            base_vid: 4000,
            isids: vec![IsidMembership {
                isid: 100,
                transmit: false,
                receive: true,
            }],
        }];

        assert_eq!(v.transmitters(100), vec![node(7)]);

        let (set, skipped) = TreeSet::compute(&v, 0, &[ect_vid(1)], usize::MAX);
        assert_eq!(skipped, 0);
        // One tree rooted locally at :1, one rooted at the transmitter :7.
        assert_eq!(set.len(), 2);
        assert!(
            set.get(&TreeKey {
                mt_id: 0,
                base_vid: 4000,
                algorithm: ECT_ALG_DEFAULT,
                root: node(7),
            })
            .is_some()
        );

        // The bound is honoured and the shortfall reported.
        let (bounded, skipped) = TreeSet::compute(&v, 0, &[ect_vid(1)], 1);
        assert_eq!(bounded.len(), 1);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn ect_vid_use_flag_reflects_any_participant() {
        let mut v = rfc_fig2();
        assert!(v.ect_vid_in_use(&ect_vid(1)));

        // Nobody advertising the pair means the Use-Flag must be clear.
        for node in v.nodes.values_mut() {
            node.ect_vids.clear();
        }
        assert!(!v.ect_vid_in_use(&ect_vid(1)));

        // A single remote participant is enough to set it.
        v.nodes.get_mut(&node(6)).unwrap().ect_vids = vec![ect_vid(1)];
        assert!(v.ect_vid_in_use(&ect_vid(1)));
        assert!(!v.ect_vid_in_use(&ect_vid(2)));
    }

    #[test]
    fn spsource_id_conflict_loser_is_the_lower_priority_bridge() {
        // RFC 6329, Section 14.1: "the bridge with the highest priority
        // Bridge Identifier will win conflicts."
        let mut v = rfc_fig2();
        v.nodes.get_mut(&node(2)).unwrap().spsource_id = 0x12345;
        v.nodes.get_mut(&node(6)).unwrap().spsource_id = 0x12345;
        let conflicts = v.spsource_id_conflicts();
        // :2 has the numerically lower BridgeID, i.e. the higher priority,
        // so it keeps the value and :6 must reallocate.
        assert_eq!(conflicts.get(&0x12345), Some(&vec![node(6)]));

        // An unassigned SPSourceID cannot collide.
        v.nodes.get_mut(&node(2)).unwrap().spsource_id = 0;
        v.nodes.get_mut(&node(6)).unwrap().spsource_id = 0;
        assert!(v.spsource_id_conflicts().is_empty());
    }
}
