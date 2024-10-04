//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use tracing::{debug, debug_span, trace};

use crate::configuration::CommitPhase;
use crate::{api, CallbackOp};

#[derive(Debug)]
pub enum Debug<'a> {
    RequestRx(&'a api::daemon::Request),
    ValidationCallback(&'a str),
    ConfigurationCallback(CommitPhase, CallbackOp, &'a str),
    RpcCallback(&'a str),
}

// ===== impl Debug =====

impl Debug<'_> {
    pub fn log(&self) {
        match self {
            Debug::RequestRx(message) => {
                debug_span!("northbound").in_scope(|| {
                    debug!("{}", self);
                    trace!(?message);
                });
            }
            Debug::ValidationCallback(path) => {
                debug_span!("northbound").in_scope(|| {
                    debug!(%path, "{}", self);
                });
            }
            Debug::ConfigurationCallback(phase, operation, path) => {
                debug_span!("northbound").in_scope(|| {
                    debug!(
                        ?phase, ?operation, %path,
                        "{}", self
                    )
                });
            }
            Debug::RpcCallback(path) => {
                debug_span!("northbound")
                    .in_scope(|| debug!(%path, "{}", self));
            }
        }
    }
}

impl std::fmt::Display for Debug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Debug::RequestRx(..) => {
                write!(f, "received request")
            }
            Debug::ValidationCallback(..) => {
                write!(f, "validation callback")
            }
            Debug::ConfigurationCallback(..) => {
                write!(f, "configuration callback")
            }
            Debug::RpcCallback(..) => {
                write!(f, "rpc callback")
            }
        }
    }
}
