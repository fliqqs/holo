//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! SPB (Shortest Path Bridging) Sub-TLVs - RFC 6329

use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use holo_utils::mac_addr::MacAddr;
use serde::{Deserialize, Serialize};

use crate::packet::consts::{
    MtCapabilityStlvType, MtPortCapStlvType, NeighborStlvType,
};
use crate::packet::error::{TlvDecodeError, TlvDecodeResult};
use crate::packet::tlv::{tlv_encode_end, tlv_encode_start, TLV_HDR_SIZE};

// Constants for SPB
pub const SPB_MCID_LEN: usize = 51;
pub const SPB_BRIDGE_PRIORITY_LEN: usize = 2;
pub const SPB_SPSOURCEID_BITS: u32 = 20;

// ===== SPB-MCID Sub-TLV (used in IIH) =====

/// SPB-MCID Sub-TLV
///
/// RFC 6329 Section 13.1
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbMcidStlv {
    pub mcid: Vec<u8>,
    pub aux_mcid: Vec<u8>,
}

impl SpbMcidStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        // Validate length (2 * 51 bytes = 102 bytes)
        if stlv_len != 102 {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let mut mcid = vec![0u8; SPB_MCID_LEN];
        let mut aux_mcid = vec![0u8; SPB_MCID_LEN];

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
        TLV_HDR_SIZE + SPB_MCID_LEN * 2
    }
}

// ===== SPB-Digest Sub-TLV (used in IIH) =====

/// SPB-Digest Sub-TLV
///
/// RFC 6329 Section 13.2
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbDigestStlv {
    pub v_bit: bool,
    pub a: u8,                   // Agreement Number (2 bits)
    pub d: u8,                   // Discarded Agreement Number (2 bits)
    pub agreement_digest: Vec<u8>,
}

impl SpbDigestStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len < 1 {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let flags = buf.try_get_u8()?;
        let v_bit = (flags & 0x04) != 0;
        let a = flags & 0x03;
        let d = (flags >> 3) & 0x03;

        let digest_len = stlv_len - 1;
        let mut agreement_digest = vec![0u8; digest_len as usize];
        buf.try_copy_to_slice(&mut agreement_digest)?;

        Ok(SpbDigestStlv {
            v_bit,
            a,
            d,
            agreement_digest,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, MtPortCapStlvType::SpbDigest);

        let mut flags = self.a & 0x03;
        if self.v_bit {
            flags |= 0x04;
        }
        flags |= (self.d & 0x03) << 3;
        buf.put_u8(flags);

        buf.put_slice(&self.agreement_digest);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + 1 + self.agreement_digest.len()
    }
}

// ===== SPB-Base-VID Sub-TLV (used in IIH) =====

/// ECT-VID Tuple for SPB Base-VID
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct EctVidTuple {
    pub ect_algorithm: u32,
    pub base_vid: u16, // 12 bits
}

/// SPB-Base-VID Sub-TLV
///
/// RFC 6329 Section 13.3
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbBaseVidStlv {
    pub ect_vid_tuples: Vec<EctVidTuple>,
}

impl SpbBaseVidStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if !stlv_len.is_multiple_of(6) {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let mut ect_vid_tuples = Vec::new();
        while buf.remaining() >= 6 {
            let ect_algorithm = buf.try_get_u32()?;
            let base_vid = buf.try_get_u16()? & 0x0FFF;

            ect_vid_tuples.push(EctVidTuple {
                ect_algorithm,
                base_vid,
            });
        }

        Ok(SpbBaseVidStlv { ect_vid_tuples })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, MtPortCapStlvType::SpbBaseVid);

        for tuple in &self.ect_vid_tuples {
            buf.put_u32(tuple.ect_algorithm);
            buf.put_u16(tuple.base_vid & 0x0FFF);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + (self.ect_vid_tuples.len() * 6)
    }
}

// ===== SPB Instance Sub-TLV (used in LSP) =====

/// VLAN-ID Tuple for SPB Instance
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct VlanIdTuple {
    pub u_bit: bool,     // Use flag
    pub m_bit: bool,     // SPBM mode
    pub a_bit: bool,     // Auto-allocation
    pub ect_algorithm: u32,
    pub base_vid: u16,   // 12 bits
    pub spvid: u16,      // 12 bits (for SPBV mode)
}

/// SPB Instance Sub-TLV
///
/// RFC 6329 Section 14.1
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbInstanceStlv {
    pub cist_root_id: u64,
    pub cist_external_root_path_cost: u32,
    pub bridge_priority: u16,
    pub v_bit: bool,       // Auto-allocated SPSourceID
    pub sp_source_id: u32, // 20 bits
    pub vlan_id_tuples: Vec<VlanIdTuple>,
}

impl SpbInstanceStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len < 19 {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let cist_root_id = buf.try_get_u64()?;
        let cist_external_root_path_cost = buf.try_get_u32()?;
        let bridge_priority = buf.try_get_u16()?;

        let sp_source_flags = buf.try_get_u32()?;
        let v_bit = (sp_source_flags & 0x00100000) != 0;
        let sp_source_id = sp_source_flags & 0x000FFFFF;

        let num_trees = buf.try_get_u8()?;

        let mut vlan_id_tuples = Vec::new();
        for _ in 0..num_trees {
            if buf.remaining() < 8 {
                return Err(TlvDecodeError::InvalidLength(stlv_len));
            }

            let flags = buf.try_get_u8()?;
            let u_bit = (flags & 0x80) != 0;
            let m_bit = (flags & 0x40) != 0;
            let a_bit = (flags & 0x20) != 0;

            let ect_algorithm = buf.try_get_u32()?;
            let base_vid = buf.try_get_u16()? & 0x0FFF;
            let spvid = buf.try_get_u16()? & 0x0FFF;

            vlan_id_tuples.push(VlanIdTuple {
                u_bit,
                m_bit,
                a_bit,
                ect_algorithm,
                base_vid,
                spvid,
            });
        }

        Ok(SpbInstanceStlv {
            cist_root_id,
            cist_external_root_path_cost,
            bridge_priority,
            v_bit,
            sp_source_id,
            vlan_id_tuples,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, MtCapabilityStlvType::SpbInstance);

        buf.put_u64(self.cist_root_id);
        buf.put_u32(self.cist_external_root_path_cost);
        buf.put_u16(self.bridge_priority);

        let mut sp_source_flags = self.sp_source_id & 0x000FFFFF;
        if self.v_bit {
            sp_source_flags |= 0x00100000;
        }
        buf.put_u32(sp_source_flags);

        buf.put_u8(self.vlan_id_tuples.len() as u8);

        for tuple in &self.vlan_id_tuples {
            let mut flags = 0u8;
            if tuple.u_bit {
                flags |= 0x80;
            }
            if tuple.m_bit {
                flags |= 0x40;
            }
            if tuple.a_bit {
                flags |= 0x20;
            }
            buf.put_u8(flags);

            buf.put_u32(tuple.ect_algorithm);
            buf.put_u16(tuple.base_vid & 0x0FFF);
            buf.put_u16(tuple.spvid & 0x0FFF);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + 19 + (self.vlan_id_tuples.len() * 8)
    }
}

// ===== SPB Instance Opaque ECT-ALGORITHM Sub-TLV =====

/// SPB Instance Opaque ECT-ALGORITHM Sub-TLV
///
/// RFC 6329 Section 14.1.1
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbInstanceOpaqueEctStlv {
    pub ect_algorithm: u32,
    pub ect_info: Vec<u8>,
}

impl SpbInstanceOpaqueEctStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len < 4 {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let ect_algorithm = buf.try_get_u32()?;
        let info_len = stlv_len - 4;
        let mut ect_info = vec![0u8; info_len as usize];
        buf.try_copy_to_slice(&mut ect_info)?;

        Ok(SpbInstanceOpaqueEctStlv {
            ect_algorithm,
            ect_info,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(
            buf,
            MtCapabilityStlvType::SpbInstanceOpaqueEct,
        );
        buf.put_u32(self.ect_algorithm);
        buf.put_slice(&self.ect_info);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + 4 + self.ect_info.len()
    }
}

// ===== SPBM Service Identifier Sub-TLV =====

/// I-SID Entry for SPBM
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct ISidEntry {
    pub t_bit: bool, // Transmit
    pub r_bit: bool, // Receive
    pub i_sid: u32,  // 24 bits
}

/// SPBM Service Identifier and Unicast Address Sub-TLV
///
/// RFC 6329 Section 16.1
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbmServiceIdStlv {
    pub b_mac: MacAddr,
    pub base_vid: u16, // 12 bits
    pub i_sid_entries: Vec<ISidEntry>,
}

impl SpbmServiceIdStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len < 8 {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let b_mac = buf.try_get_mac()?;
        let base_vid = buf.try_get_u16()? & 0x0FFF;

        let mut i_sid_entries = Vec::new();
        while buf.remaining() >= 4 {
            let flags_isid = buf.try_get_u32()?;
            let t_bit = (flags_isid & 0x80000000) != 0;
            let r_bit = (flags_isid & 0x40000000) != 0;
            let i_sid = flags_isid & 0x00FFFFFF;

            i_sid_entries.push(ISidEntry { t_bit, r_bit, i_sid });
        }

        Ok(SpbmServiceIdStlv {
            b_mac,
            base_vid,
            i_sid_entries,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, MtCapabilityStlvType::SpbmServiceId);

        buf.put_mac(&self.b_mac);
        buf.put_u16(self.base_vid & 0x0FFF);

        for entry in &self.i_sid_entries {
            let mut flags_isid = entry.i_sid & 0x00FFFFFF;
            if entry.t_bit {
                flags_isid |= 0x80000000;
            }
            if entry.r_bit {
                flags_isid |= 0x40000000;
            }
            buf.put_u32(flags_isid);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + 8 + (self.i_sid_entries.len() * 4)
    }
}

// ===== SPBV MAC Address Sub-TLV =====

/// MAC address entry for SPBV
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbvMacEntry {
    pub t_bit: bool, // Transmit
    pub r_bit: bool, // Receive
    pub mac: MacAddr,
}

/// SPBV MAC Address Sub-TLV
///
/// RFC 6329 Section 16.2
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbvMacAddrStlv {
    pub sr_bits: u8, // Service Requirement (2 bits)
    pub spvid: u16,  // 12 bits
    pub mac_entries: Vec<SpbvMacEntry>,
}

impl SpbvMacAddrStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len < 2 {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let spvid_flags = buf.try_get_u16()?;
        let sr_bits = ((spvid_flags >> 12) & 0x03) as u8;
        let spvid = spvid_flags & 0x0FFF;

        let mut mac_entries = Vec::new();
        while buf.remaining() >= 7 {
            let flags = buf.try_get_u8()?;
            let t_bit = (flags & 0x80) != 0;
            let r_bit = (flags & 0x40) != 0;
            let mac = buf.try_get_mac()?;

            mac_entries.push(SpbvMacEntry { t_bit, r_bit, mac });
        }

        Ok(SpbvMacAddrStlv {
            sr_bits,
            spvid,
            mac_entries,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, MtCapabilityStlvType::SpbvMacAddr);

        let spvid_flags =
            ((self.sr_bits as u16 & 0x03) << 12) | (self.spvid & 0x0FFF);
        buf.put_u16(spvid_flags);

        for entry in &self.mac_entries {
            let mut flags = 0u8;
            if entry.t_bit {
                flags |= 0x80;
            }
            if entry.r_bit {
                flags |= 0x40;
            }
            buf.put_u8(flags);
            buf.put_mac(&entry.mac);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + 2 + (self.mac_entries.len() * 7)
    }
}

// ===== SPB Link Metric Sub-TLV =====

/// SPB Link Metric Sub-TLV
///
/// RFC 6329 Section 15.1
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbMetricStlv {
    pub spb_link_metric: u32, // 24 bits
    pub port_identifiers: Vec<u16>,
}

impl SpbMetricStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len < 4 {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        // Read 24-bit metric
        let metric_high = buf.try_get_u8()? as u32;
        let metric_low = buf.try_get_u16()? as u32;
        let spb_link_metric = (metric_high << 16) | metric_low;

        let num_ports = buf.try_get_u8()?;
        let mut port_identifiers = Vec::new();

        for _ in 0..num_ports {
            if buf.remaining() < 2 {
                return Err(TlvDecodeError::InvalidLength(stlv_len));
            }
            port_identifiers.push(buf.try_get_u16()?);
        }

        Ok(SpbMetricStlv {
            spb_link_metric,
            port_identifiers,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, NeighborStlvType::SpbMetric);

        // Write 24-bit metric
        buf.put_u8(((self.spb_link_metric >> 16) & 0xFF) as u8);
        buf.put_u16((self.spb_link_metric & 0xFFFF) as u16);

        buf.put_u8(self.port_identifiers.len() as u8);
        for port_id in &self.port_identifiers {
            buf.put_u16(*port_id);
        }

        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + 4 + (self.port_identifiers.len() * 2)
    }
}

// ===== SPB Adjacency Opaque ECT-ALGORITHM Sub-TLV =====

/// SPB Adjacency Opaque ECT-ALGORITHM Sub-TLV
///
/// RFC 6329 Section 15.1.1
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub struct SpbAdjacencyOpaqueEctStlv {
    pub ect_algorithm: u32,
    pub ect_info: Vec<u8>,
}

impl SpbAdjacencyOpaqueEctStlv {
    pub(crate) fn decode(
        stlv_len: u8,
        buf: &mut Bytes,
    ) -> TlvDecodeResult<Self> {
        if stlv_len < 4 {
            return Err(TlvDecodeError::InvalidLength(stlv_len));
        }

        let ect_algorithm = buf.try_get_u32()?;
        let info_len = stlv_len - 4;
        let mut ect_info = vec![0u8; info_len as usize];
        buf.try_copy_to_slice(&mut ect_info)?;

        Ok(SpbAdjacencyOpaqueEctStlv {
            ect_algorithm,
            ect_info,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos =
            tlv_encode_start(buf, NeighborStlvType::SpbAdjacencyOpaqueEct);
        buf.put_u32(self.ect_algorithm);
        buf.put_slice(&self.ect_info);
        tlv_encode_end(buf, start_pos);
    }

    pub(crate) fn len(&self) -> usize {
        TLV_HDR_SIZE + 4 + self.ect_info.len()
    }
}
