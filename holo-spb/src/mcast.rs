//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! SPBM multicast addressing and replication.
//!
//! RFC 6329, Sections 4.3 and 4.4.

use holo_utils::mac_addr::MacAddr;

use crate::topology::{ISID_MAX, SPSOURCE_ID_MAX};

/// The four fixed high-order bits of an SPBM multicast B-DA: the multicast
/// bit, the local bit, and a two-bit SPSourceID type of `00`.
///
/// RFC 6329 numbers bits from least to most significant within an octet
/// (the reverse of the IEEE convention), which is why M and L land in the low
/// two bits of the first octet.
const MCAST_BDA_PREFIX: u8 = 0x03;

/// Builds the multicast B-DA that identifies the `(S, G)` tree for a source's
/// SPSourceID and an I-SID.
///
/// RFC 6329, Section 4.4: the address concatenates the 20-bit SPSourceID with
/// the 24-bit I-SID, written `DA=<A',M>`, and uniquely identifies the tree.
///
/// ```text
///  M L TYP
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |1|1|0|0|SPSrcMS|  SPSrc [8:15] |  SPSrc [0:7]  | I-SID [16:23] |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | I-SID [8:15]  |  I-SID [0:7]  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn group_bmac(spsource_id: u32, isid: u32) -> MacAddr {
    let spsource_id = spsource_id & SPSOURCE_ID_MAX;
    let isid = isid & ISID_MAX;
    MacAddr::from([
        MCAST_BDA_PREFIX | (((spsource_id >> 16) & 0x0f) as u8) << 4,
        (spsource_id >> 8) as u8,
        spsource_id as u8,
        (isid >> 16) as u8,
        (isid >> 8) as u8,
        isid as u8,
    ])
}

/// Recovers the SPSourceID and I-SID from a multicast B-DA.
///
/// Returns `None` unless the address is a well-formed SPBM multicast address
/// with an SPSourceID type of `00`.
pub fn parse_group_bmac(bmac: MacAddr) -> Option<(u32, u32)> {
    let bytes = bmac.as_bytes();
    if bytes[0] & 0x0f != MCAST_BDA_PREFIX {
        return None;
    }
    let spsource_id = (((bytes[0] >> 4) as u32) << 16)
        | ((bytes[1] as u32) << 8)
        | bytes[2] as u32;
    let isid =
        ((bytes[3] as u32) << 16) | ((bytes[4] as u32) << 8) | bytes[5] as u32;
    Some((spsource_id, isid))
}

/// Returns whether a MAC address is an SPBM-constructed multicast address.
pub fn is_group_bmac(bmac: MacAddr) -> bool {
    bmac.as_bytes()[0] & 0x0f == MCAST_BDA_PREFIX
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_bmac_layout() {
        // SPSourceID 0x12345, I-SID 0xabcdef.
        //   byte0 = 0x03 | (0x1 << 4) = 0x13
        //   byte1 = 0x23, byte2 = 0x45
        //   bytes 3..6 = ab cd ef
        let bmac = group_bmac(0x12345, 0xabcdef);
        assert_eq!(bmac.as_bytes(), [0x13, 0x23, 0x45, 0xab, 0xcd, 0xef]);
        assert_eq!(bmac.to_string(), "13:23:45:ab:cd:ef");
    }

    #[test]
    fn group_bmac_sets_multicast_and_local_bits() {
        let bmac = group_bmac(0, 100);
        // The multicast bit is the low bit of the first octet on the wire,
        // and the local bit is next to it.
        assert_eq!(bmac.as_bytes()[0] & 0x01, 0x01, "multicast bit");
        assert_eq!(bmac.as_bytes()[0] & 0x02, 0x02, "local bit");
        assert_eq!(bmac.as_bytes()[0] & 0x0c, 0x00, "SPSourceID type 00");
    }

    #[test]
    fn group_bmac_round_trips() {
        for (spsource_id, isid) in [
            (0x00000, 0x000064),
            (0x12345, 0xabcdef),
            (0xfffff, 0xffffff),
            (0x0000f, 0x000fff),
        ] {
            let bmac = group_bmac(spsource_id, isid);
            assert!(is_group_bmac(bmac));
            assert_eq!(parse_group_bmac(bmac), Some((spsource_id, isid)));
        }
    }

    #[test]
    fn out_of_range_inputs_are_masked_to_their_field_widths() {
        // A 20-bit SPSourceID and a 24-bit I-SID cannot overflow into the
        // fixed prefix bits.
        let bmac = group_bmac(0xffff_ffff, 0xffff_ffff);
        assert_eq!(bmac.as_bytes()[0] & 0x0f, MCAST_BDA_PREFIX);
        assert_eq!(parse_group_bmac(bmac), Some((0xfffff, 0xffffff)));
    }

    #[test]
    fn unicast_bmac_is_not_a_group_address() {
        let unicast = MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        assert!(!is_group_bmac(unicast));
        assert_eq!(parse_group_bmac(unicast), None);
    }
}
