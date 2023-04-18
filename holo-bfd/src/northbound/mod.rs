//
// Copyright (c) The Holo Core Contributors
//
// See LICENSE for license details.
//

pub mod configuration;
pub mod notification;
pub mod state;
pub mod yang;

use holo_northbound::ProviderBase;
use holo_utils::protocol::Protocol;
use holo_yang::ToYang;
use tracing::{debug_span, Span};

use crate::master::Master;

impl ProviderBase for Master {
    fn yang_modules() -> &'static [&'static str] {
        &["ietf-bfd-ip-mh", "ietf-bfd-ip-sh", "ietf-bfd"]
    }

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='main']/ietf-bfd:bfd",
            Protocol::BFD.to_yang(),
        )
    }

    fn debug_span(_name: &str) -> Span {
        debug_span!("bfd")
    }
}

// No RPC/Actions to implement.
impl holo_northbound::rpc::Provider for Master {}
