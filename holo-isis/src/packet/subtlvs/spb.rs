//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
//! SPB (Shortest Path Bridging) Sub-TLVs for IS-IS.
//!
//! This module implements Sub-TLVs carried within the MT-Capability TLV (144)
//! as defined in RFC 6329.

use bitflags::bitflags;
use derive_new::new;
use holo_utils::bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::packet::error::{TlvDecodeError, TlvDecodeResult};
use crate::packet::iana::{MtCapStlvType, MtPortCapStlvType, NeighborStlvType};
use crate::packet::tlv::{TLV_HDR_SIZE, tlv_encode_end, tlv_encode_start};

/// SPBM Service Identifier and Unicast Address (SPBM-SI) Sub-TLV.
///
/// This Sub-TLV is defined in RFC 6329 Section 16.1 and carries:
/// - B-MAC Address: Unicast MAC address of the node
/// - Base VID: Links this B-MAC to corresponding ECT-ALGORITHM
/// - I-SID entries: Service identifiers with T/R membership bits
///
/// Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |         B-MAC Address        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    B-MAC Address (continued)                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Resv | Base VID              |T|R|  Resv   |     I-SID      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          I-SID (continued)    | ... more I-SID entries ...   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SpbmSiStlv {
    /// B-MAC Address (6 bytes) - Unicast MAC address.
    pub bmac: [u8; 6],
    /// Base VID (12 bits) - Links to ECT-ALGORITHM in SPB-Inst Sub-TLV.
    pub base_vid: u16,
    /// List of I-SID entries with T/R flags.
    pub isid_entries: Vec<IsidEntry>,
}

/// I-SID (Service Identifier) entry within SPBM-SI Sub-TLV.
///
/// Format (4 bytes):
/// ```text
/// |T|R|  Reserved (6 bits) |     I-SID (24 bits)           |
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct IsidEntry {
    /// T bit: Transmit - indicates transmit membership.
    /// R bit: Receive - indicates receive membership.
    pub flags: IsidFlags,
    /// 24-bit Service Identifier.
    pub isid: u32,
}

bitflags! {
    /// Flags for I-SID entries.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct IsidFlags: u8 {
        /// Transmit bit - indicates transmit membership.
        const T = 0x80;
        /// Receive bit - indicates receive membership.
        const R = 0x40;
    }
}

/// SPB Instance (SPB-Inst) Sub-TLV.
///
/// Defined in RFC 6329, Section 14.1. It carries this node's SPSourceID —
/// the 20-bit value used to build multicast destination addresses — along
/// with its Bridge Priority and the ECT-ALGORITHM/Base VID tuples that define
/// its tree sets.
///
/// This Sub-TLV MUST be carried within the MT-Capability TLV in the fragment
/// ZERO LSP, and each additional SPB instance MUST be declared under a
/// separate MT-Capability TLV that is also carried in fragment zero.
///
/// Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               CIST Root Identifier  (8 bytes)                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           CIST External Root Path Cost     (4 bytes)          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Bridge Priority        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R R R R R R R R R R R|V|              SPSourceID               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Num of Trees  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  VLAN-ID Tuples    (8 bytes each)             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SpbInstStlv {
    /// CIST Root Identifier (8 bytes).
    pub cist_root_id: u64,
    /// CIST External Root Path Cost.
    pub cist_ext_root_path_cost: u32,
    /// Bridge Priority, the high-order half of the BridgeID.
    pub bridge_priority: u16,
    /// The V bit: the SPSourceID was auto-allocated rather than configured.
    pub spsource_id_auto: bool,
    /// 20-bit SPSourceID. The value 0 means dynamic assignment has been
    /// requested but has not yet completed.
    pub spsource_id: u32,
    /// VLAN-ID tuples, one per tree set.
    pub vlan_id_tuples: Vec<VlanIdTuple>,
}

/// A VLAN-ID tuple within the SPB-Inst Sub-TLV.
///
/// Format (8 bytes):
/// ```text
/// |U|M|A|  Res    |                                (1 byte)
/// |                ECT-ALGORITHM (32 bits)         (4 bytes)
/// | Base VID (12 bits)    |   SPVID (12 bits)      (3 bytes)
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct VlanIdTuple {
    /// U (Use), M (Multicast) and A (SPVID Allocated) bits.
    pub flags: VlanIdTupleFlags,
    /// ECT-ALGORITHM: an OUI in the top 24 bits and an index in the low 8.
    pub ect_algorithm: u32,
    /// Base VID associated with this SPT Set.
    pub base_vid: u16,
    /// Shortest Path VID, used in SPBV mode.
    pub spvid: u16,
}

bitflags! {
    /// Flags for VLAN-ID tuples.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct VlanIdTupleFlags: u8 {
        /// Use bit - this ECT-ALGORITHM and Base VID pair is in use.
        const U = 0x80;
        /// Multicast bit - this Base VID carries multicast.
        const M = 0x40;
        /// SPVID Allocated bit - SPBV mode.
        const A = 0x20;
    }
}

/// SPB Link Metric (SPB-Metric) Sub-TLV.
///
/// Defined in RFC 6329, Section 15.1. It occurs within the Extended IS
/// Reachability TLV (type 22) or the MT-ISN TLV (type 222).
///
/// If this Sub-TLV is not present for an IS-IS adjacency, then that adjacency
/// must not carry SPB traffic for the topology instance. SPB path computation
/// uses the *maximum* of the two nodes' advertised metrics, which is what
/// makes paths symmetric when the two ends are configured differently.
///
/// Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       SPB-LINK-METRIC                         |   (3 bytes)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Num of Ports    |     (1 byte)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Port Identifier          |   (2 bytes each)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SpbMetricStlv {
    /// 24-bit SPB link metric.
    pub metric: u32,
    /// Port identifiers associated with this adjacency.
    pub port_ids: Vec<u16>,
}

/// SPB Base VLAN Identifiers (SPB-B-VID) Sub-TLV.
///
/// Defined in RFC 6329, Section 13.3. Carried in an MT-Port-Cap TLV in IIH
/// PDUs to advertise the mappings between ECT algorithms and Base VIDs that
/// are in use. Under stable conditions this should be identical on every
/// bridge in the topology, so a mismatch is a configuration error worth
/// surfacing.
///
/// Format: a sequence of 6-byte ECT-VID tuples.
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       ECT-ALGORITHM (32 bits)                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Base VID (12 bits)    |U|M|RES|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Note that the ASCII art in the RFC mislabels the Sub-TLV type as 68; both
/// the normative text and the IANA table give 6.
#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SpbBVidStlv {
    /// ECT algorithm and Base VID pairs supported on this port.
    pub ect_vid_tuples: Vec<EctVidTuple>,
}

/// An ECT-VID tuple within the SPB-B-VID Sub-TLV.
#[derive(Clone, Copy, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct EctVidTuple {
    /// ECT-ALGORITHM: an OUI in the top 24 bits, an index in the low 8.
    pub ect_algorithm: u32,
    /// Base VID associated with the SPT Set.
    pub base_vid: u16,
    /// U (Use) and M (Multicast) bits.
    pub flags: EctVidFlags,
}

bitflags! {
    /// Flags for ECT-VID tuples.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct EctVidFlags: u8 {
        /// Use bit - this bridge, or any bridge in the LSDB, is currently
        /// using this ECT-ALGORITHM and Base VID.
        const U = 0x08;
        /// Multicast bit - this Base VID carries multicast.
        const M = 0x04;
    }
}

/// SPB Multiple Spanning Tree Configuration Identifier (SPB-MCID) Sub-TLV.
///
/// Defined in RFC 6329, Section 13.1 and carried in an MT-Port-Cap TLV in
/// IIH PDUs. It identifies the SPT Region by its VID allocation, and must be
/// identical on every bridge in a region.
///
/// Two MCIDs are carried so that a change which does not affect forwarding
/// can be rolled through a region without disrupting it: a bridge advertises
/// the new one as its MCID and the old one as the auxiliary, and neighbours
/// accept either.
///
/// The 51-byte MCID structure is defined in IEEE 802.1Q, not in RFC 6329, so
/// it is carried here as opaque bytes.
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SpbMcidStlv {
    /// The region's configuration identifier.
    // serde has no blanket impl for arrays this long; the literal must match
    // `MCID_LEN`.
    #[serde_as(as = "[_; 51]")]
    pub mcid: [u8; SpbMcidStlv::MCID_LEN],
    /// The identifier being migrated away from.
    #[serde_as(as = "[_; 51]")]
    pub aux_mcid: [u8; SpbMcidStlv::MCID_LEN],
}

// ===== impl SpbMcidStlv =====

impl SpbMcidStlv {
    /// Length of one MCID, per IEEE 802.1Q.
    pub const MCID_LEN: usize = 51;
    /// The Sub-TLV carries exactly two of them and nothing else.
    const SIZE: usize = Self::MCID_LEN * 2;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // The length is fixed, so anything else is a malformed Sub-TLV
        // rather than an extension to skip over.
        if stlv_len as usize != Self::SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let mut mcid = [0u8; Self::MCID_LEN];
        let mut aux_mcid = [0u8; Self::MCID_LEN];
        buf.try_copy_to_slice(&mut mcid)?;
        buf.try_copy_to_slice(&mut aux_mcid)?;

        Ok(SpbMcidStlv { mcid, aux_mcid })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, MtPortCapStlvType::SpbMcid);
        buf.put_slice(&self.mcid);
        buf.put_slice(&self.aux_mcid);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::SIZE
    }

    /// Builds an MCID from an MST Configuration Identifier's parts.
    ///
    /// IEEE 802.1Q lays the 51 bytes out as a one-byte format selector, a
    /// 32-byte configuration name, a two-byte revision level and a 16-byte
    /// configuration digest. A name shorter than the field is padded with
    /// zeroes and a longer one is truncated, so that two bridges configured
    /// with the same name always produce the same bytes.
    pub fn from_parts(name: &str, revision: u16, digest: &[u8; 16]) -> Self {
        let mut mcid = [0u8; Self::MCID_LEN];
        // Byte 0 is the format selector, which is 0.
        let name = name.as_bytes();
        let len = name.len().min(32);
        mcid[1..1 + len].copy_from_slice(&name[..len]);
        mcid[33..35].copy_from_slice(&revision.to_be_bytes());
        mcid[35..51].copy_from_slice(digest);
        SpbMcidStlv {
            mcid,
            aux_mcid: mcid,
        }
    }

    /// Returns whether this identifies the same region as `other`.
    ///
    /// Either identifier matching is enough, which is what lets a region be
    /// reconfigured without every bridge changing at the same instant.
    pub fn matches(&self, other: &SpbMcidStlv) -> bool {
        self.mcid == other.mcid
            || self.mcid == other.aux_mcid
            || self.aux_mcid == other.mcid
    }
}

/// SPB Agreement Digest (SPB-Digest) Sub-TLV.
///
/// Defined in RFC 6329, Section 13.2 and carried in an MT-Port-Cap TLV in
/// IIH PDUs. Matching digests mean the two ends of an adjacency agree on the
/// topology, which is what gates updates to multicast forwarding.
///
/// Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-----+-+---+---+
/// | Res |V| A | D | (1 byte)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+...+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               Agreement Digest (Length - 1)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+...+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, PartialEq)]
#[derive(new)]
#[derive(Deserialize, Serialize)]
pub struct SpbDigestStlv {
    /// V bit: the advertised digest is meaningful.
    pub valid: bool,
    /// Agreement Number (2 bits).
    pub agreement: u8,
    /// Discarded Agreement Number (2 bits).
    pub discarded: u8,
    /// The digest itself. Its length is not fixed by the RFC, since the
    /// computation is defined by IEEE 802.1aq.
    pub digest: Vec<u8>,
}

// ===== impl SpbDigestStlv =====

impl SpbDigestStlv {
    /// The flags byte; the digest follows it.
    const MIN_SIZE: usize = 1;
    const VALID_BIT: u8 = 0x10;
    const AGREEMENT_MASK: u8 = 0x0c;
    const AGREEMENT_SHIFT: u8 = 2;
    const DISCARDED_MASK: u8 = 0x03;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if (stlv_len as usize) < Self::MIN_SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let flags = buf.try_get_u8()?;
        let digest_len = (stlv_len as usize) - Self::MIN_SIZE;
        let digest = buf.try_copy_to_bytes(digest_len)?.to_vec();

        Ok(SpbDigestStlv {
            valid: flags & Self::VALID_BIT != 0,
            agreement: (flags & Self::AGREEMENT_MASK) >> Self::AGREEMENT_SHIFT,
            discarded: flags & Self::DISCARDED_MASK,
            digest,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, MtPortCapStlvType::SpbDigest);

        let mut flags = 0u8;
        if self.valid {
            flags |= Self::VALID_BIT;
        }
        flags |=
            (self.agreement << Self::AGREEMENT_SHIFT) & Self::AGREEMENT_MASK;
        flags |= self.discarded & Self::DISCARDED_MASK;
        buf.put_u8(flags);
        buf.put_slice(&self.digest);

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::MIN_SIZE + self.digest.len()
    }
}

// ===== impl SpbBVidStlv =====

impl SpbBVidStlv {
    /// Each ECT-VID tuple is 6 bytes.
    const TUPLE_SIZE: usize = 6;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if !(stlv_len as usize).is_multiple_of(Self::TUPLE_SIZE) {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let num_tuples = (stlv_len as usize) / Self::TUPLE_SIZE;
        let mut ect_vid_tuples = Vec::with_capacity(num_tuples);
        for _ in 0..num_tuples {
            ect_vid_tuples.push(EctVidTuple::decode(buf)?);
        }

        Ok(SpbBVidStlv { ect_vid_tuples })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, MtPortCapStlvType::SpbBVid);

        for tuple in &self.ect_vid_tuples {
            tuple.encode(buf);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + self.ect_vid_tuples.len() * Self::TUPLE_SIZE
    }
}

// ===== impl EctVidTuple =====

impl EctVidTuple {
    pub(crate) fn decode(buf: &mut Bytes) -> TlvDecodeResult<Self> {
        let ect_algorithm = buf.try_get_u32()?;

        // Base VID (12 bits) + U + M + Reserved (2 bits).
        let raw = buf.try_get_u16()?;
        let base_vid = raw >> 4;
        let flags = EctVidFlags::from_bits_truncate((raw & 0x000f) as u8);

        Ok(EctVidTuple {
            ect_algorithm,
            base_vid,
            flags,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.ect_algorithm);
        buf.put_u16(((self.base_vid & 0x0fff) << 4) | self.flags.bits() as u16);
    }
}

// ===== impl SpbMetricStlv =====

impl SpbMetricStlv {
    /// Metric (3) + Num of Ports (1) = 4 bytes minimum.
    const MIN_SIZE: usize = 4;
    /// Each port identifier is 2 bytes.
    const PORT_ID_SIZE: usize = 2;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if (stlv_len as usize) < Self::MIN_SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let port_bytes = (stlv_len as usize) - Self::MIN_SIZE;
        if !port_bytes.is_multiple_of(Self::PORT_ID_SIZE) {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let metric = buf.try_get_u24()?;

        // As with the tree count in SPB-Inst, a declared count that
        // disagrees with the length means the layout is not understood, so
        // the Sub-TLV is rejected rather than partially believed.
        let num_ports = buf.try_get_u8()?;
        let num_port_ids = port_bytes / Self::PORT_ID_SIZE;
        if num_ports as usize != num_port_ids {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let mut port_ids = Vec::with_capacity(num_port_ids);
        for _ in 0..num_port_ids {
            port_ids.push(buf.try_get_u16()?);
        }

        Ok(SpbMetricStlv { metric, port_ids })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, NeighborStlvType::SpbMetric);

        buf.put_u24(self.metric);
        buf.put_u8(self.port_ids.len() as u8);
        for port_id in &self.port_ids {
            buf.put_u16(*port_id);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + Self::MIN_SIZE + self.port_ids.len() * Self::PORT_ID_SIZE
    }
}

// ===== impl SpbInstStlv =====

impl SpbInstStlv {
    /// The V bit within the 32-bit reserved/V/SPSourceID field.
    const SPSOURCE_ID_AUTO: u32 = 0x0010_0000;
    /// SPSourceID is 20 bits wide.
    const SPSOURCE_ID_MASK: u32 = 0x000f_ffff;
    /// CIST Root Id (8) + CIST cost (4) + priority (2) + SPSourceID word (4)
    /// + Num of Trees (1) = 19 bytes minimum.
    const MIN_SIZE: usize = 19;
    /// Each VLAN-ID tuple is 8 bytes.
    const TUPLE_SIZE: usize = 8;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate minimum length.
        if (stlv_len as usize) < Self::MIN_SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        // Validate VLAN-ID tuple alignment.
        let tuple_bytes = (stlv_len as usize) - Self::MIN_SIZE;
        if !tuple_bytes.is_multiple_of(Self::TUPLE_SIZE) {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let cist_root_id = buf.try_get_u64()?;
        let cist_ext_root_path_cost = buf.try_get_u32()?;
        let bridge_priority = buf.try_get_u16()?;

        // Reserved (11 bits) + V bit + SPSourceID (20 bits).
        let spsource_word = buf.try_get_u32()?;
        let spsource_id_auto = (spsource_word & Self::SPSOURCE_ID_AUTO) != 0;
        let spsource_id = spsource_word & Self::SPSOURCE_ID_MASK;

        // The advertised tuple count must agree with the TLV length; a
        // mismatch means the sender and receiver disagree on the layout, so
        // the Sub-TLV is rejected rather than partially believed.
        let num_trees = buf.try_get_u8()?;
        let num_tuples = tuple_bytes / Self::TUPLE_SIZE;
        if num_trees as usize != num_tuples {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let mut vlan_id_tuples = Vec::with_capacity(num_tuples);
        for _ in 0..num_tuples {
            vlan_id_tuples.push(VlanIdTuple::decode(buf)?);
        }

        Ok(SpbInstStlv {
            cist_root_id,
            cist_ext_root_path_cost,
            bridge_priority,
            spsource_id_auto,
            spsource_id,
            vlan_id_tuples,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, MtCapStlvType::SpbInstance);

        buf.put_u64(self.cist_root_id);
        buf.put_u32(self.cist_ext_root_path_cost);
        buf.put_u16(self.bridge_priority);

        // Reserved (11 bits) + V bit + SPSourceID (20 bits).
        let mut spsource_word = self.spsource_id & Self::SPSOURCE_ID_MASK;
        if self.spsource_id_auto {
            spsource_word |= Self::SPSOURCE_ID_AUTO;
        }
        buf.put_u32(spsource_word);

        buf.put_u8(self.vlan_id_tuples.len() as u8);
        for tuple in &self.vlan_id_tuples {
            tuple.encode(buf);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE
            + Self::MIN_SIZE
            + self.vlan_id_tuples.len() * Self::TUPLE_SIZE
    }
}

// ===== impl VlanIdTuple =====

impl VlanIdTuple {
    pub(crate) fn decode(buf: &mut Bytes) -> TlvDecodeResult<Self> {
        // U|M|A|Reserved(5 bits).
        let flags = VlanIdTupleFlags::from_bits_truncate(buf.try_get_u8()?);

        let ect_algorithm = buf.try_get_u32()?;

        // Base VID (12 bits) + SPVID (12 bits).
        let vids = buf.try_get_u24()?;
        let base_vid = ((vids >> 12) & 0x0fff) as u16;
        let spvid = (vids & 0x0fff) as u16;

        Ok(VlanIdTuple {
            flags,
            ect_algorithm,
            base_vid,
            spvid,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.bits());
        buf.put_u32(self.ect_algorithm);
        let vids = (((self.base_vid & 0x0fff) as u32) << 12)
            | (self.spvid & 0x0fff) as u32;
        buf.put_u24(vids);
    }
}

// ===== impl SpbmSiStlv =====

impl SpbmSiStlv {
    /// B-MAC (6) + Reserved/BaseVID (2) = 8 bytes minimum.
    const MIN_SIZE: usize = 8;
    /// Each I-SID entry is 4 bytes.
    const ISID_ENTRY_SIZE: usize = 4;

    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate minimum length.
        if (stlv_len as usize) < Self::MIN_SIZE {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        // Validate I-SID entries alignment.
        let isid_bytes = (stlv_len as usize) - Self::MIN_SIZE;
        if !isid_bytes.is_multiple_of(Self::ISID_ENTRY_SIZE) {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        // Parse B-MAC Address (6 bytes).
        let mut bmac = [0u8; 6];
        buf.try_copy_to_slice(&mut bmac)?;

        // Parse Reserved (4 bits) + Base VID (12 bits).
        let base_vid_raw = buf.try_get_u16()?;
        let base_vid = base_vid_raw & 0x0FFF;

        // Parse I-SID entries.
        let num_entries = isid_bytes / Self::ISID_ENTRY_SIZE;
        let mut isid_entries = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            let entry = IsidEntry::decode(buf)?;
            isid_entries.push(entry);
        }

        Ok(SpbmSiStlv {
            bmac,
            base_vid,
            isid_entries,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, MtCapStlvType::SpbmSi);

        // B-MAC Address (6 bytes).
        buf.put_slice(&self.bmac);

        // Reserved (4 bits) + Base VID (12 bits).
        buf.put_u16(self.base_vid & 0x0FFF);

        // I-SID entries.
        for entry in &self.isid_entries {
            entry.encode(buf);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE
            + Self::MIN_SIZE
            + self.isid_entries.len() * Self::ISID_ENTRY_SIZE
    }
}

// ===== impl IsidEntry =====

impl IsidEntry {
    pub(crate) fn decode(buf: &mut Bytes) -> TlvDecodeResult<Self> {
        // First byte: T|R|Reserved(6 bits).
        let flags_byte = buf.try_get_u8()?;
        let flags = IsidFlags::from_bits_truncate(flags_byte);

        // Next 3 bytes: I-SID (24 bits).
        let isid = buf.try_get_u24()?;

        Ok(IsidEntry { flags, isid })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        // T|R|Reserved(6 bits).
        buf.put_u8(self.flags.bits());

        // I-SID (24 bits).
        buf.put_u24(self.isid);
    }
}
