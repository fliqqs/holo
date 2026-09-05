//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! Equal Cost Tree (ECT) algorithms and path tie-breaking.
//!
//! RFC 6329, Sections 11 and 12.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// Byte-wise masks used to derive the 16 standard ECT algorithms from the
/// default tie-breaking rule.
///
/// Indexed by the low byte of the ECT-ALGORITHM (`0x00..=0x10`). Each entry is
/// a single byte that is XORed into *every* byte of a BridgeID.
///
/// `ECT_MASK[1]` is all zeros, yielding the default algorithm (lowest
/// BridgeID wins); `ECT_MASK[2]` is all ones, inverting the BridgeID so that
/// the highest BridgeID wins.
///
/// RFC 6329, Section 12.
pub const ECT_MASK: [u8; 17] = [
    0x00, 0x00, 0xFF, 0x88, 0x77, 0x44, 0x33, 0xCC, 0xBB, 0x22, 0x11, 0x66,
    0x55, 0xAA, 0x99, 0xDD, 0xEE,
];

/// IEEE 802.1 OUI, occupying the top 24 bits of a standard ECT-ALGORITHM.
pub const ECT_OUI_IEEE8021: u32 = 0x00_80_c2;

/// Lowest standard ECT-ALGORITHM index.
pub const ECT_INDEX_MIN: u8 = 0x01;

/// Highest standard ECT-ALGORITHM index.
pub const ECT_INDEX_MAX: u8 = 0x10;

/// A 32-bit ECT-ALGORITHM identifier: a 24-bit OUI followed by an 8-bit index.
///
/// The 16 standard SPB algorithms are `00-80-C2-01` through `00-80-C2-10`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct EctAlgorithm(pub u32);

/// The default ECT-ALGORITHM, `00-80-C2-01`.
pub const ECT_ALG_DEFAULT: EctAlgorithm = EctAlgorithm(0x0080_c201);

// ===== impl EctAlgorithm =====

impl EctAlgorithm {
    /// Builds a standard IEEE 802.1 ECT-ALGORITHM from its index.
    ///
    /// Returns `None` unless the index is within `0x01..=0x10`.
    pub fn from_index(index: u8) -> Option<Self> {
        if !(ECT_INDEX_MIN..=ECT_INDEX_MAX).contains(&index) {
            return None;
        }
        Some(EctAlgorithm((ECT_OUI_IEEE8021 << 8) | index as u32))
    }

    /// Returns the 24-bit OUI.
    pub fn oui(self) -> u32 {
        self.0 >> 8
    }

    /// Returns the algorithm index (the low byte).
    pub fn index(self) -> u8 {
        self.0 as u8
    }

    /// Returns whether this is one of the 16 standard IEEE 802.1 algorithms.
    pub fn is_standard(self) -> bool {
        self.oui() == ECT_OUI_IEEE8021
            && (ECT_INDEX_MIN..=ECT_INDEX_MAX).contains(&self.index())
    }

    /// Returns the tie-breaking mask for this algorithm.
    ///
    /// Non-standard (opaque) algorithms fall back to the default mask, since
    /// their tie-breaking is defined by the advertiser rather than by
    /// RFC 6329.
    pub fn mask(self) -> u8 {
        if self.is_standard() {
            ECT_MASK[self.index() as usize]
        } else {
            ECT_MASK[ECT_ALG_DEFAULT.index() as usize]
        }
    }
}

impl std::fmt::Display for EctAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0.to_be_bytes();
        write!(f, "{:02x}-{:02x}-{:02x}-{:02x}", b[0], b[1], b[2], b[3])
    }
}

/// An 802.1 Bridge Identifier: a 16-bit Bridge Priority followed by the
/// 48-bit IS-IS System ID.
///
/// Ordering is by the raw 8-byte value, so the Bridge Priority dominates and
/// gives the operator control over ECT path selection.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct BridgeId(pub [u8; 8]);

// ===== impl BridgeId =====

impl BridgeId {
    pub fn new(priority: u16, system_id: [u8; 6]) -> Self {
        let mut bytes = [0u8; 8];
        bytes[..2].copy_from_slice(&priority.to_be_bytes());
        bytes[2..].copy_from_slice(&system_id);
        BridgeId(bytes)
    }

    pub fn priority(&self) -> u16 {
        u16::from_be_bytes([self.0[0], self.0[1]])
    }

    pub fn system_id(&self) -> [u8; 6] {
        let mut sysid = [0u8; 6];
        sysid.copy_from_slice(&self.0[2..]);
        sysid
    }

    /// Returns this BridgeID XORed byte-by-byte with an algorithm's mask.
    ///
    /// RFC 6329, Section 12:
    /// `XOR BYTE BY BYTE(ECT-MASK{ECT-ALGORITHM.index}, BridgeID)`.
    pub fn masked(&self, algo: EctAlgorithm) -> [u8; 8] {
        let mask = algo.mask();
        self.0.map(|byte| byte ^ mask)
    }
}

impl std::fmt::Display for BridgeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
        )
    }
}

/// The identity of a path, used as the final tie-breaker between two
/// equal-cost, equal-hop-count paths.
///
/// RFC 6329, Section 11, states the tie-break as "the (sub)path traversing the
/// intermediate node with the lower BridgeID". Comparing only the immediate
/// intermediate node is not transitive, yet transitivity is explicitly
/// required ("shortest path is made up of sub-shortest paths"). This type
/// therefore implements the tie-break the way IEEE 802.1aq does, as a PATHID:
/// the *sorted* set of masked BridgeIDs of the nodes the path traverses,
/// compared lexicographically.
///
/// Sorting rather than preserving path order is what makes the comparison
/// symmetric — a path and its reverse produce an identical PATHID — and
/// lexicographic comparison of sorted sets is transitive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct PathId(Vec<[u8; 8]>);

// ===== impl PathId =====

impl PathId {
    /// An empty PATHID, for a path that traverses no intermediate nodes.
    pub fn empty() -> Self {
        PathId(Vec::new())
    }

    /// Builds a PATHID from the masked BridgeIDs of the traversed nodes.
    pub fn from_masked(mut masked: Vec<[u8; 8]>) -> Self {
        masked.sort_unstable();
        PathId(masked)
    }

    /// Returns a new PATHID with `bridge_id` added to the traversed set.
    pub fn with_node(&self, bridge_id: BridgeId, algo: EctAlgorithm) -> Self {
        let mut masked = self.0.clone();
        let entry = bridge_id.masked(algo);
        // Keep the vector sorted on insertion; paths are built incrementally,
        // so this is cheaper than re-sorting the whole set each time.
        let pos = masked.partition_point(|item| item < &entry);
        masked.insert(pos, entry);
        PathId(masked)
    }

    /// Returns the number of traversed nodes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[[u8; 8]] {
        &self.0
    }
}

impl Ord for PathId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for PathId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (idx, masked) in self.0.iter().enumerate() {
            if idx != 0 {
                f.write_str(":")?;
            }
            for byte in masked {
                write!(f, "{byte:02x}")?;
            }
        }
        Ok(())
    }
}

/// A candidate path to a destination, ordered by the SPB tie-breaking rules.
///
/// The total order is: lowest cost, then fewest hops, then lowest PATHID.
/// It is deterministic, symmetric and transitive, which is what lets every
/// node in the region independently compute identical trees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathRank<'a> {
    pub cost: u32,
    pub hops: u16,
    pub path_id: &'a PathId,
}

impl Ord for PathRank<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cost
            .cmp(&other.cost)
            .then_with(|| self.hops.cmp(&other.hops))
            .then_with(|| self.path_id.cmp(other.path_id))
    }
}

impl PartialOrd for PathRank<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use super::*;

    fn bid(priority: u16, last: u8) -> BridgeId {
        BridgeId::new(priority, [0, 0, 0, 0, 0, last])
    }

    #[test]
    fn ect_mask_matches_rfc6329() {
        // RFC 6329, Section 12.
        assert_eq!(
            ECT_MASK,
            [
                0x00, 0x00, 0xFF, 0x88, 0x77, 0x44, 0x33, 0xCC, 0xBB, 0x22,
                0x11, 0x66, 0x55, 0xAA, 0x99, 0xDD, 0xEE
            ]
        );
    }

    #[test]
    fn ect_algorithm_range() {
        assert_eq!(EctAlgorithm::from_index(1), Some(ECT_ALG_DEFAULT));
        assert_eq!(
            EctAlgorithm::from_index(0x10),
            Some(EctAlgorithm(0x0080_c210))
        );
        // Index 0 and 0x11 are outside the 16 standard algorithms.
        assert_eq!(EctAlgorithm::from_index(0x00), None);
        assert_eq!(EctAlgorithm::from_index(0x11), None);

        assert!(ECT_ALG_DEFAULT.is_standard());
        assert_eq!(ECT_ALG_DEFAULT.to_string(), "00-80-c2-01");
        assert_eq!(ECT_ALG_DEFAULT.oui(), ECT_OUI_IEEE8021);
        assert_eq!(ECT_ALG_DEFAULT.index(), 1);

        // A vendor-opaque algorithm is not standard and falls back to the
        // default mask.
        let opaque = EctAlgorithm(0x00aa_bb01);
        assert!(!opaque.is_standard());
        assert_eq!(opaque.mask(), ECT_MASK[1]);
    }

    #[test]
    fn bridge_id_layout() {
        let id = BridgeId::new(0x8000, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(id.0, [0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(id.priority(), 0x8000);
        assert_eq!(id.system_id(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn default_algorithm_picks_lowest_bridge_id() {
        // ECT_MASK[1] is all zeros, so masking is the identity and the lowest
        // BridgeID wins. This is the RFC 6329 Section 11 example: computing
        // from node :1, the competing sub-paths via :2 and via :6 tie, and
        // the path through :2 is selected because {0...:2} < {0...:6}.
        let algo = ECT_ALG_DEFAULT;
        let via2 = bid(0, 2).masked(algo);
        let via6 = bid(0, 6).masked(algo);
        assert_eq!(via2, bid(0, 2).0);
        assert!(via2 < via6);
    }

    #[test]
    fn algorithm_two_inverts_the_selection() {
        // ECT_MASK[2] is all ones, so the highest BridgeID wins instead.
        let algo = EctAlgorithm::from_index(2).unwrap();
        assert_eq!(algo.mask(), 0xFF);
        let via2 = bid(0, 2).masked(algo);
        let via6 = bid(0, 6).masked(algo);
        assert!(via6 < via2, "algorithm 2 must prefer the higher BridgeID");
    }

    #[test]
    fn bridge_priority_overrides_system_id() {
        // RFC 6329, Section 11: raising the Bridge Priority of :2 above that
        // of :6 makes the tie-break pick the alternate path.
        let algo = ECT_ALG_DEFAULT;
        let via2 = bid(100, 2).masked(algo);
        let via6 = bid(0, 6).masked(algo);
        assert!(via6 < via2);
    }

    #[test]
    fn path_id_is_order_independent() {
        // A path and its reverse must produce the same PATHID, which is what
        // makes tie-breaking symmetric.
        let algo = ECT_ALG_DEFAULT;
        let fwd = PathId::empty()
            .with_node(bid(0, 2), algo)
            .with_node(bid(0, 3), algo)
            .with_node(bid(0, 4), algo);
        let rev = PathId::empty()
            .with_node(bid(0, 4), algo)
            .with_node(bid(0, 3), algo)
            .with_node(bid(0, 2), algo);
        assert_eq!(fwd, rev);
        assert_eq!(fwd.len(), 3);
    }

    #[test]
    fn path_id_stays_sorted_on_incremental_build() {
        let algo = ECT_ALG_DEFAULT;
        let built = PathId::empty()
            .with_node(bid(0, 9), algo)
            .with_node(bid(0, 1), algo)
            .with_node(bid(0, 5), algo);
        let sorted = PathId::from_masked(vec![
            bid(0, 9).masked(algo),
            bid(0, 1).masked(algo),
            bid(0, 5).masked(algo),
        ]);
        assert_eq!(built, sorted);
        assert!(built.as_slice().windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn path_id_ordering_is_transitive() {
        let algo = ECT_ALG_DEFAULT;
        let a = PathId::empty().with_node(bid(0, 1), algo);
        let b = PathId::empty().with_node(bid(0, 2), algo);
        let c = PathId::empty().with_node(bid(0, 3), algo);
        assert!(a < b && b < c && a < c);
    }

    #[test]
    fn path_rank_orders_cost_then_hops_then_path_id() {
        let algo = ECT_ALG_DEFAULT;
        let low = PathId::empty().with_node(bid(0, 2), algo);
        let high = PathId::empty().with_node(bid(0, 6), algo);

        // Cost dominates.
        let cheap = PathRank {
            cost: 10,
            hops: 9,
            path_id: &high,
        };
        let dear = PathRank {
            cost: 20,
            hops: 1,
            path_id: &low,
        };
        assert!(cheap < dear);

        // Then hop count: the (sub)path with the fewest hops between the
        // fork and join points wins.
        let short = PathRank {
            cost: 10,
            hops: 2,
            path_id: &high,
        };
        let long = PathRank {
            cost: 10,
            hops: 3,
            path_id: &low,
        };
        assert!(short < long);

        // Then PATHID.
        let a = PathRank {
            cost: 10,
            hops: 2,
            path_id: &low,
        };
        let b = PathRank {
            cost: 10,
            hops: 2,
            path_id: &high,
        };
        assert!(a < b);
    }
}
