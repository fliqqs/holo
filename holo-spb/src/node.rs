//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! Node identity within an SPB region.

use serde::{Deserialize, Serialize};

/// A 48-bit node identifier, equal to the advertising router's IS-IS System
/// ID.
///
/// This crate keeps its own identifier type rather than borrowing IS-IS's
/// `SystemId`, since `holo-isis` depends on `holo-spb` and not the other way
/// round.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct NodeId([u8; 6]);

// ===== impl NodeId =====

impl NodeId {
    pub const LENGTH: usize = 6;

    pub fn new(bytes: [u8; 6]) -> Self {
        NodeId(bytes)
    }

    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }
}

impl From<[u8; 6]> for NodeId {
    fn from(bytes: [u8; 6]) -> Self {
        NodeId(bytes)
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}
