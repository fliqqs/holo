//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use holo_utils::ibus::{IbusMsg, IbusSender};
use holo_utils::southbound::{
    InterfaceIpAddRequestMsg, InterfaceIpDelRequestMsg, MacvlanAddMsg,
};
use ipnetwork::IpNetwork;

pub(crate) fn mvlan_create(
    ibus_tx: &IbusSender,
    parent_name: String,
    name: String,
    mac_address: [u8; 6],
) {
    let msg = MacvlanAddMsg {
        parent_name,
        name,
        mac_address: Some(mac_address),
    };
    let _ = ibus_tx.send(IbusMsg::MacvlanAdd(msg));
}

pub(crate) fn mvlan_delete(ibus_tx: &IbusSender, name: impl Into<String>) {
    let _ = ibus_tx.send(IbusMsg::MacvlanDel(name.into()));
}

pub(crate) fn ip_addr_add(
    ibus_tx: &IbusSender,
    ifname: impl Into<String>,
    addr: impl Into<IpNetwork>,
) {
    let msg = InterfaceIpAddRequestMsg {
        ifname: ifname.into(),
        addr: addr.into(),
    };
    let _ = ibus_tx.send(IbusMsg::InterfaceIpAddRequest(msg));
}

pub(crate) fn ip_addr_del(
    ibus_tx: &IbusSender,
    ifname: impl Into<String>,
    addr: impl Into<IpNetwork>,
) {
    let msg = InterfaceIpDelRequestMsg {
        ifname: ifname.into(),
        addr: addr.into(),
    };
    let _ = ibus_tx.send(IbusMsg::InterfaceIpDelRequest(msg));
}
