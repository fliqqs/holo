//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! The agreement digest and its state machine.
//!
//! Neighbours exchange a digest of their view of the SPB topology in Hellos.
//! Matching digests mean the two nodes agree on the topology, which is what
//! makes it safe to update multicast forwarding: a tree whose shape is still
//! being argued about can forward a frame back where it came from.
//!
//! RFC 6329, Section 13.2 defines how the digest is *carried* but not how it
//! is *computed* — that is IEEE 802.1aq §28.4, which was not available. The
//! computation here is therefore Holo's own, defined precisely below and
//! placed behind [`AgreementDigest`] so the normative one can replace it
//! without disturbing anything else.
//!
//! **Interoperability: Holo to Holo only. Interop with a vendor implementing
//! 802.1aq §28.4 is unverified and will not work until that computation is
//! implemented.**

use hmac::digest::Mac;
use hmac::{Hmac, KeyInit};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::node::NodeId;
use crate::topology::TopologyView;

/// Length of the digest carried in the SPB-Digest sub-TLV.
pub const DIGEST_LEN: usize = 32;

/// Agreement and Discarded Agreement Numbers are two bits wide.
const AGREEMENT_MODULUS: u8 = 4;

/// Computes a digest of the SPB topology.
///
/// Implemented as a trait so the normative 802.1aq computation can be
/// dropped in later without touching the state machine or the wire code.
pub trait AgreementDigest {
    /// Returns the digest of one SPB instance's topology.
    fn compute(&self, view: &TopologyView, mt_id: u16) -> Vec<u8>;

    /// A short name for the computation, so a mismatch caused by two nodes
    /// running different algorithms can be told from a genuine topology
    /// disagreement.
    fn id(&self) -> &'static str;
}

/// Holo's own digest computation.
///
/// The digest is `HMAC-SHA256` over a canonical serialization of everything
/// that determines the shape of the trees, and nothing else:
///
/// ```text
///   "holo-spb-digest-v1"
///   mt_id                                        (2 bytes, big endian)
///   node count                                   (4 bytes)
///   for each node, ordered by System ID:
///       system id                                (6 bytes)
///       bridge priority                          (2 bytes)
///       spsource id                              (4 bytes)
///       overload                                 (1 byte)
///       ect-vid count                            (2 bytes)
///       for each (algorithm, base vid), ordered:
///           algorithm                            (4 bytes)
///           base vid                             (2 bytes)
///   edge count                                   (4 bytes)
///   for each edge, ordered by (lower id, higher id):
///       lower system id                          (6 bytes)
///       higher system id                         (6 bytes)
///       resolved cost                            (4 bytes)
/// ```
///
/// Everything is fixed width and length-prefixed, so no two distinct
/// topologies can serialise identically. Service membership is deliberately
/// excluded: it changes which trees carry which I-SIDs, not the trees
/// themselves, and including it would make the digest churn on every
/// service edit.
#[derive(Clone, Copy, Debug, Default)]
pub struct HoloLocalDigest;

// ===== impl HoloLocalDigest =====

impl AgreementDigest for HoloLocalDigest {
    fn compute(&self, view: &TopologyView, mt_id: u16) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"holo-spb-digest-v1");
        buf.extend_from_slice(&mt_id.to_be_bytes());

        buf.extend_from_slice(&(view.nodes.len() as u32).to_be_bytes());
        // BTreeMap iteration is ordered by System ID, which is what makes
        // the serialization canonical across nodes.
        for (id, node) in &view.nodes {
            buf.extend_from_slice(&id.as_bytes());
            buf.extend_from_slice(&node.bridge_priority.to_be_bytes());
            buf.extend_from_slice(&node.spsource_id.to_be_bytes());
            buf.push(node.overload as u8);

            let mut ect_vids: Vec<_> = node
                .ect_vids
                .iter()
                .map(|vid| (vid.algorithm.0, vid.base_vid))
                .collect();
            ect_vids.sort_unstable();
            ect_vids.dedup();
            buf.extend_from_slice(&(ect_vids.len() as u16).to_be_bytes());
            for (algorithm, base_vid) in ect_vids {
                buf.extend_from_slice(&algorithm.to_be_bytes());
                buf.extend_from_slice(&base_vid.to_be_bytes());
            }
        }

        // Each link contributes once, under the ordered pair of its ends and
        // the cost both ends will actually use.
        let mut edges = Vec::new();
        for link in &view.links {
            let (lo, hi) = if link.from <= link.to {
                (link.from, link.to)
            } else {
                (link.to, link.from)
            };
            if let Some(cost) = view.edge_cost(lo, hi) {
                edges.push((lo, hi, cost));
            }
        }
        edges.sort_unstable();
        edges.dedup();

        buf.extend_from_slice(&(edges.len() as u32).to_be_bytes());
        for (lo, hi, cost) in edges {
            buf.extend_from_slice(&lo.as_bytes());
            buf.extend_from_slice(&hi.as_bytes());
            buf.extend_from_slice(&cost.to_be_bytes());
        }

        // A fixed key: the digest authenticates nothing, it only has to be a
        // collision-resistant summary that both ends compute identically.
        let mut mac = Hmac::<Sha256>::new_from_slice(b"holo-spb")
            .expect("HMAC accepts a key of any length");
        mac.update(&buf);
        mac.finalize().into_bytes().to_vec()
    }

    fn id(&self) -> &'static str {
        "holo-spb-digest-v1"
    }
}

/// This node's side of the agreement exchange.
#[derive(Clone, Debug, Default)]
#[derive(Deserialize, Serialize)]
pub struct LocalAgreement {
    /// The digest of our current view.
    pub digest: Vec<u8>,
    /// Agreement Number, incremented whenever our digest changes.
    pub agreement: u8,
    /// The most recent Agreement Number we have discarded, i.e. superseded.
    pub discarded: u8,
    /// The V bit: whether our digest is meaningful yet.
    pub valid: bool,
}

// ===== impl LocalAgreement =====

impl LocalAgreement {
    /// Records a newly computed digest.
    ///
    /// A change means everything previously agreed is stale, so the
    /// Agreement Number advances and the old one becomes the discarded one.
    /// Returns whether the digest actually changed.
    pub fn update(&mut self, digest: Vec<u8>) -> bool {
        if self.valid && self.digest == digest {
            return false;
        }
        if self.valid {
            self.discarded = self.agreement;
            self.agreement = (self.agreement + 1) % AGREEMENT_MODULUS;
        }
        self.digest = digest;
        self.valid = true;
        true
    }
}

/// What a neighbour told us in its SPB-Digest sub-TLV.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct NeighborAgreement {
    pub digest: Vec<u8>,
    pub agreement: u8,
    pub discarded: u8,
    pub valid: bool,
}

/// Why a neighbour is or is not in agreement with us.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum Agreement {
    /// Digests match and our Agreement Number has been acknowledged.
    Agreed,
    /// Nothing has been received from this neighbour yet.
    NoDigest,
    /// One side's digest is not yet valid.
    NotValid,
    /// Both sides have a valid digest but they differ: the two nodes see
    /// different topologies, usually because an LSP is still propagating.
    DigestMismatch,
    /// Reserved for the Agreement Number handling of IEEE 802.1aq §28.2,
    /// which Holo carries but does not gate on. See [`evaluate`].
    Outstanding,
}

// ===== impl Agreement =====

impl Agreement {
    /// Returns whether forwarding may be updated on the strength of this.
    pub fn is_agreed(&self) -> bool {
        matches!(self, Agreement::Agreed)
    }
}

/// Evaluates agreement with one neighbour.
///
/// Agreement is digest equality. That is sufficient, and the reasoning is
/// worth stating because it is not obvious: a neighbour echoing a *stale*
/// view cannot produce our current digest, since the digest is a function of
/// the topology and a stale topology hashes differently. A match therefore
/// means the neighbour is looking at the same topology we are, which is
/// exactly the question multicast forwarding needs answered.
///
/// RFC 6329, Section 13.2 also describes an Agreement Number that stays
/// *outstanding* until a matching or more recent Discarded Agreement Number
/// returns. Holo carries and reports both numbers but does not gate on them.
/// The precise state machine is IEEE 802.1aq §28.2, which was not available,
/// and the obvious reading — requiring the neighbour's Discarded number to
/// catch up with our Agreement number — **never converges**: the numbers
/// count each node's *own* digest changes, so two nodes that have
/// re-converged a different number of times hold permanently different
/// numbers while agreeing perfectly about the topology. That was observed on
/// a live four-node region where every node computed an identical digest and
/// no adjacency ever reached agreement.
pub fn evaluate(
    local: &LocalAgreement,
    neighbor: Option<&NeighborAgreement>,
) -> Agreement {
    let Some(neighbor) = neighbor else {
        return Agreement::NoDigest;
    };
    if !local.valid || !neighbor.valid {
        return Agreement::NotValid;
    }
    if local.digest != neighbor.digest {
        return Agreement::DigestMismatch;
    }
    Agreement::Agreed
}

/// Trees whose multicast forwarding must not be updated yet.
///
/// RFC 6329, Section 13.2 blocks *unsafe* multicast forwarding until digests
/// match, where §28.2 of 802.1aq defines precisely what is unsafe. That text
/// was not available, so this errs the only safe way: a tree is unsafe if the
/// local node's distance to its root changed in the last computation. That is
/// a superset of the standard's condition, so it cannot loop — it can only
/// converge more slowly than a fully conformant implementation.
#[derive(Clone, Debug, Default)]
pub struct UnsafeTrees {
    roots: std::collections::BTreeSet<(u16, NodeId)>,
}

// ===== impl UnsafeTrees =====

impl UnsafeTrees {
    /// Marks a tree unsafe because the distance to its root changed.
    pub fn mark(&mut self, base_vid: u16, root: NodeId) {
        self.roots.insert((base_vid, root));
    }

    /// Returns whether a tree's multicast state may be programmed.
    pub fn is_safe(&self, base_vid: u16, root: NodeId) -> bool {
        !self.roots.contains(&(base_vid, root))
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Clears every mark, once agreement has been reached.
    pub fn clear(&mut self) {
        self.roots.clear();
    }
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ect::EctAlgorithm;
    use crate::topology::{EctVid, LinkView, NodeView};

    fn node(last: u8) -> NodeId {
        NodeId::new([0, 0, 0, 0, 0, last])
    }

    fn ect_vid() -> EctVid {
        EctVid {
            base_vid: 4000,
            algorithm: EctAlgorithm::from_index(1).unwrap(),
            spvid: None,
            multicast: true,
        }
    }

    fn view(local: u8, edges: &[(u8, u8, u32)]) -> TopologyView {
        let mut view = TopologyView {
            local: node(local),
            ..Default::default()
        };
        for (a, b, metric) in edges {
            for id in [*a, *b] {
                view.nodes.entry(node(id)).or_insert_with(|| NodeView {
                    ect_vids: vec![ect_vid()],
                    ..Default::default()
                });
            }
            for (from, to) in [(a, b), (b, a)] {
                view.links.push(LinkView {
                    from: node(*from),
                    to: node(*to),
                    metric: Some(*metric),
                    port_ids: vec![],
                });
            }
        }
        view
    }

    #[test]
    fn the_digest_is_the_expected_width() {
        let d = HoloLocalDigest.compute(&view(1, &[(1, 2, 10)]), 0);
        assert_eq!(d.len(), DIGEST_LEN);
        assert_eq!(HoloLocalDigest.id(), "holo-spb-digest-v1");
    }

    #[test]
    fn two_nodes_seeing_the_same_topology_agree() {
        // The whole mechanism rests on this: the digest must not depend on
        // which node computed it, only on what it sees.
        let edges = [(1u8, 2u8, 10u32), (2, 3, 10), (1, 3, 20)];
        let from_1 = HoloLocalDigest.compute(&view(1, &edges), 0);
        let from_3 = HoloLocalDigest.compute(&view(3, &edges), 0);
        assert_eq!(from_1, from_3);
    }

    #[test]
    fn link_order_does_not_change_the_digest() {
        let a = HoloLocalDigest.compute(&view(1, &[(1, 2, 10), (2, 3, 10)]), 0);
        let b = HoloLocalDigest.compute(&view(1, &[(2, 3, 10), (1, 2, 10)]), 0);
        assert_eq!(a, b);
    }

    #[test]
    fn the_digest_changes_when_the_topology_does() {
        let base = HoloLocalDigest.compute(&view(1, &[(1, 2, 10)]), 0);

        // A different cost.
        assert_ne!(base, HoloLocalDigest.compute(&view(1, &[(1, 2, 20)]), 0));
        // An extra link.
        assert_ne!(
            base,
            HoloLocalDigest.compute(&view(1, &[(1, 2, 10), (2, 3, 10)]), 0)
        );
        // A different MT instance.
        assert_ne!(base, HoloLocalDigest.compute(&view(1, &[(1, 2, 10)]), 2));

        // A bridge priority change alters tie-breaking, so it must count.
        let mut v = view(1, &[(1, 2, 10)]);
        v.nodes.get_mut(&node(2)).unwrap().bridge_priority = 100;
        assert_ne!(base, HoloLocalDigest.compute(&v, 0));

        // So must the overload bit, which changes which nodes are transited.
        let mut v = view(1, &[(1, 2, 10)]);
        v.nodes.get_mut(&node(2)).unwrap().overload = true;
        assert_ne!(base, HoloLocalDigest.compute(&v, 0));
    }

    #[test]
    fn a_link_only_one_end_advertises_is_not_in_the_digest() {
        // An unusable link must not contribute, or two nodes would disagree
        // purely over a half-formed adjacency.
        let mut v = view(1, &[(1, 2, 10)]);
        let base = HoloLocalDigest.compute(&v, 0);
        v.links.push(LinkView {
            from: node(1),
            to: node(2),
            metric: None,
            port_ids: vec![],
        });
        assert_eq!(base, HoloLocalDigest.compute(&v, 0));
    }

    #[test]
    fn the_agreement_number_advances_only_on_a_real_change() {
        let mut local = LocalAgreement::default();

        // The first digest makes us valid but does not count as a change to
        // agree about.
        assert!(local.update(vec![1, 2, 3]));
        assert!(local.valid);
        assert_eq!(local.agreement, 0);

        // Recomputing the same view changes nothing.
        assert!(!local.update(vec![1, 2, 3]));
        assert_eq!(local.agreement, 0);

        // A real change advances the number and retires the old one.
        assert!(local.update(vec![4, 5, 6]));
        assert_eq!(local.agreement, 1);
        assert_eq!(local.discarded, 0);
    }

    #[test]
    fn agreement_requires_a_match_and_an_acknowledgement() {
        let mut local = LocalAgreement::default();
        local.update(vec![0xaa; DIGEST_LEN]);

        assert_eq!(evaluate(&local, None), Agreement::NoDigest);

        let mut neighbor = NeighborAgreement {
            digest: vec![0xbb; DIGEST_LEN],
            agreement: 0,
            discarded: 0,
            valid: false,
        };
        assert_eq!(evaluate(&local, Some(&neighbor)), Agreement::NotValid);

        neighbor.valid = true;
        assert_eq!(
            evaluate(&local, Some(&neighbor)),
            Agreement::DigestMismatch
        );

        neighbor.digest = local.digest.clone();
        assert_eq!(evaluate(&local, Some(&neighbor)), Agreement::Agreed);
        assert!(evaluate(&local, Some(&neighbor)).is_agreed());
    }

    #[test]
    fn a_neighbour_echoing_a_stale_view_is_a_mismatch() {
        // We move on to a new view while the neighbour still advertises the
        // old one. Its digest is a function of the topology it sees, so a
        // stale view cannot match ours: no extra sequencing is needed to
        // detect it.
        let mut local = LocalAgreement::default();
        local.update(vec![0xaa; DIGEST_LEN]);
        let stale = NeighborAgreement {
            digest: local.digest.clone(),
            agreement: 0,
            discarded: 0,
            valid: true,
        };
        assert_eq!(evaluate(&local, Some(&stale)), Agreement::Agreed);

        local.update(vec![0xcc; DIGEST_LEN]);
        assert_eq!(evaluate(&local, Some(&stale)), Agreement::DigestMismatch);
    }

    #[test]
    fn differing_agreement_numbers_do_not_block_agreement() {
        // Regression: the numbers count each node's own digest changes, so
        // two nodes that have re-converged a different number of times hold
        // different numbers while agreeing perfectly. Gating on them left a
        // live four-node region permanently un-agreed despite every node
        // computing an identical digest.
        let mut local = LocalAgreement::default();
        for d in 1..=4u8 {
            local.update(vec![d; DIGEST_LEN]);
        }
        assert_eq!(local.agreement, 3);

        let neighbor = NeighborAgreement {
            digest: local.digest.clone(),
            agreement: 2,
            discarded: 1,
            valid: true,
        };
        assert_eq!(evaluate(&local, Some(&neighbor)), Agreement::Agreed);
    }

    #[test]
    fn unsafe_trees_gate_only_what_was_marked() {
        let mut unsafe_trees = UnsafeTrees::default();
        assert!(unsafe_trees.is_empty());
        assert!(unsafe_trees.is_safe(4000, node(1)));

        unsafe_trees.mark(4000, node(1));
        assert!(!unsafe_trees.is_safe(4000, node(1)));
        // A different tree is unaffected.
        assert!(unsafe_trees.is_safe(4001, node(1)));
        assert!(unsafe_trees.is_safe(4000, node(2)));
        assert_eq!(unsafe_trees.len(), 1);

        unsafe_trees.clear();
        assert!(unsafe_trees.is_safe(4000, node(1)));
    }
}
