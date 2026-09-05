//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! The gRPC session with the dataplane agent.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;
use tonic::transport::{Channel, Endpoint, Uri};
use tracing::{debug, info, warn};

use super::proto::spb_dataplane_client::SpbDataplaneClient;
use super::{DataplaneUpdate, proto};
use crate::fdb::{
    MulticastEntry, MulticastKey, ServiceEntry, UnicastEntry, UnicastKey,
};

/// How long to wait before retrying a failed connection.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// A connected dataplane session.
pub struct Client {
    inner: SpbDataplaneClient<Channel>,
}

// ===== impl Client =====

impl Client {
    /// Connects to the dataplane agent's Unix socket.
    pub async fn connect(
        socket: PathBuf,
    ) -> Result<Self, tonic::transport::Error> {
        // The authority is unused: the connector dials the socket directly.
        let channel = Endpoint::try_from("http://spb-dp")?
            .connect_with_connector(tower::service_fn(move |_: Uri| {
                let socket = socket.clone();
                async move {
                    let stream =
                        tokio::net::UnixStream::connect(socket).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                        stream,
                    ))
                }
            }))
            .await?;
        Ok(Client {
            inner: SpbDataplaneClient::new(channel),
        })
    }

    /// Reads the datapath counters.
    pub async fn stats(&mut self) -> Result<proto::StatsReply, tonic::Status> {
        Ok(self
            .inner
            .get_stats(proto::StatsRequest {})
            .await?
            .into_inner())
    }
}

/// Maintains the dataplane session, forwarding deltas as they arrive.
///
/// Reconnects indefinitely: the dataplane is a separate process that may be
/// restarted or upgraded under a running control plane, and forwarding state
/// is re-sent as a snapshot each time the session is re-established.
pub async fn run(
    socket: PathBuf,
    updates: &mut mpsc::UnboundedReceiver<DataplaneUpdate>,
) {
    loop {
        match session(socket.clone(), updates).await {
            Ok(()) => {
                debug!("dataplane session ended");
            }
            Err(error) => {
                // A bare `transport error` says nothing useful, so the
                // source chain is walked and reported too.
                let mut detail = error.to_string();
                let mut source = error.source();
                while let Some(cause) = source {
                    detail.push_str(": ");
                    detail.push_str(&cause.to_string());
                    source = cause.source();
                }
                warn!(
                    socket = %socket.display(),
                    error = %detail,
                    "dataplane session failed"
                );
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn session(
    socket: PathBuf,
    updates: &mut mpsc::UnboundedReceiver<DataplaneUpdate>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = Client::connect(socket.clone()).await?;
    info!(socket = %socket.display(), "connected to the dataplane");

    let (tx, rx) = mpsc::channel::<proto::ControlMsg>(64);
    let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);
    let mut inbound = client.inner.session(outbound).await?.into_inner();

    let mut configured = false;

    tx.send(proto::ControlMsg {
        msg: Some(proto::control_msg::Msg::Hello(proto::Hello {
            generation: 0,
            control_plane: "holo-isis".to_owned(),
        })),
    })
    .await?;

    loop {
        tokio::select! {
            // The dataplane's replies: acknowledgements, and resync requests
            // when its state is older than ours.
            message = inbound.message() => {
                match message? {
                    Some(msg) => handle_reply(msg),
                    None => return Ok(()),
                }
            }
            update = updates.recv() => {
                let Some(update) = update else {
                    return Ok(());
                };
                // The node identity and port roles are re-sent on each
                // session, since a restarted dataplane has neither.
                if !std::mem::replace(&mut configured, true) {
                    for msg in configure(&update) {
                        tx.send(msg).await?;
                    }
                }
                for msg in encode(&update) {
                    tx.send(msg).await?;
                }
            }
        }
    }
}

fn handle_reply(msg: proto::DataplaneMsg) {
    use proto::dataplane_msg::Msg;

    match msg.msg {
        Some(Msg::Hello(hello)) => {
            info!(
                version = %hello.version,
                generation = hello.generation,
                "dataplane ready"
            );
        }
        Some(Msg::Ack(ack)) => {
            debug!(
                generation = ack.generation,
                entries = ack.entries_programmed,
                "dataplane committed"
            );
        }
        Some(Msg::Nack(nack)) => {
            warn!(
                generation = nack.generation,
                reason = %nack.reason,
                "dataplane rejected an update"
            );
        }
        Some(Msg::ResyncRequest(req)) => {
            // The next computation produces a snapshot; nothing to do here
            // beyond noting it, since forwarding state is rebuilt from the
            // topology rather than cached for replay.
            info!(reason = %req.reason, "dataplane asked for a resync");
        }
        Some(Msg::Event(_)) | None => {}
    }
}

/// Encodes this node's identity and its port roles.
fn configure(update: &DataplaneUpdate) -> Vec<proto::ControlMsg> {
    let mut msgs = vec![proto::ControlMsg {
        msg: Some(proto::control_msg::Msg::NodeConfig(proto::NodeConfig {
            b_mac: update.node.b_mac.as_bytes().to_vec(),
            spsource_id: update.node.spsource_id,
        })),
    }];

    for ifname in &update.nni_ports {
        msgs.push(proto::ControlMsg {
            msg: Some(proto::control_msg::Msg::PortConfig(proto::PortConfig {
                ifname: ifname.clone(),
                role: proto::port_config::Role::Nni as i32,
                i_sid: 0,
                b_vid: 0,
            })),
        });
    }

    for (isid, ifnames) in &update.uni_ports {
        let b_vid = update
            .delta
            .services_added
            .iter()
            .find(|(added, _)| added == isid)
            .map(|(_, entry)| entry.base_vid as u32)
            .unwrap_or(0);
        for ifname in ifnames {
            msgs.push(proto::ControlMsg {
                msg: Some(proto::control_msg::Msg::PortConfig(
                    proto::PortConfig {
                        ifname: ifname.clone(),
                        role: proto::port_config::Role::Uni as i32,
                        i_sid: *isid,
                        b_vid,
                    },
                )),
            });
        }
    }

    msgs
}

/// Encodes a delta as a batch of session messages, ending with a commit.
fn encode(update: &DataplaneUpdate) -> Vec<proto::ControlMsg> {
    let delta = &update.delta;
    // The update first, then the commit, so the dataplane applies a whole
    // batch at once rather than a partially written table.
    vec![
        proto::ControlMsg {
            msg: Some(proto::control_msg::Msg::FdbDelta(proto::FdbDelta {
                generation: delta.generation,
                snapshot: delta.snapshot,
                unicast_added: delta
                    .unicast_added
                    .iter()
                    .map(|(key, entry)| unicast(update, key, entry))
                    .collect(),
                unicast_removed: delta
                    .unicast_removed
                    .iter()
                    .map(unicast_key)
                    .collect(),
                multicast_added: delta
                    .multicast_added
                    .iter()
                    .map(|(key, entry)| multicast(update, key, entry))
                    .collect(),
                multicast_removed: delta
                    .multicast_removed
                    .iter()
                    .map(multicast_key)
                    .collect(),
                services_added: delta
                    .services_added
                    .iter()
                    .map(|(isid, entry)| service(update, *isid, entry))
                    .collect(),
                services_removed: delta.services_removed.clone(),
            })),
        },
        proto::ControlMsg {
            msg: Some(proto::control_msg::Msg::Commit(proto::Commit {
                generation: delta.generation,
            })),
        },
    ]
}

fn unicast_key(key: &UnicastKey) -> proto::UnicastKey {
    proto::UnicastKey {
        b_vid: key.base_vid as u32,
        b_mac: key.bmac.as_bytes().to_vec(),
    }
}

fn unicast(
    update: &DataplaneUpdate,
    key: &UnicastKey,
    entry: &UnicastEntry,
) -> proto::UnicastEntry {
    proto::UnicastEntry {
        key: Some(unicast_key(key)),
        nexthop_system_id: entry
            .nexthop
            .map(|id| id.as_bytes().to_vec())
            .unwrap_or_default(),
        // An empty name means the B-MAC is this node's own, which tells the
        // dataplane to decapsulate rather than forward.
        out_ifname: entry
            .nexthop
            .and_then(|id| update.nexthop_ifname(id))
            .unwrap_or_default()
            .to_owned(),
        cost: entry.cost,
    }
}

fn multicast_key(key: &MulticastKey) -> proto::MulticastKey {
    proto::MulticastKey {
        b_vid: key.base_vid as u32,
        group_bmac: key.group_bmac.as_bytes().to_vec(),
    }
}

fn multicast(
    update: &DataplaneUpdate,
    key: &MulticastKey,
    entry: &MulticastEntry,
) -> proto::MulticastEntry {
    proto::MulticastEntry {
        key: Some(multicast_key(key)),
        i_sid: entry.isid,
        source_system_id: entry.source.as_bytes().to_vec(),
        local_deliver: entry.local_deliver,
        // The branches are the local node's children on the source's tree;
        // any that has no adjacency is skipped rather than sent unresolved.
        out_ifnames: entry
            .branches
            .iter()
            .filter_map(|node| update.nexthop_ifname(*node))
            .map(str::to_owned)
            .collect(),
    }
}

fn service(
    update: &DataplaneUpdate,
    isid: u32,
    entry: &ServiceEntry,
) -> proto::ServiceEntry {
    proto::ServiceEntry {
        i_sid: isid,
        b_vid: entry.base_vid as u32,
        transmit: entry.transmit,
        receive: entry.receive,
        uni_ifnames: update.uni_ports.get(&isid).cloned().unwrap_or_default(),
        // Only needed for head-end replication, but sent either way so the
        // dataplane need not be reprogrammed when the T bit changes.
        member_bmacs: entry
            .members
            .values()
            .map(|bmac| bmac.as_bytes().to_vec())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use holo_utils::mac_addr::MacAddr;

    use super::super::NodeIdentity;
    use super::*;
    use crate::fdb::FdbDelta;
    use crate::node::NodeId;

    #[test]
    fn a_delta_encodes_to_an_update_then_a_commit() {
        let mut delta = FdbDelta {
            generation: 7,
            ..Default::default()
        };
        delta.unicast_added.push((
            UnicastKey {
                base_vid: 4000,
                bmac: MacAddr::from([0, 0, 0, 0, 0, 4]),
            },
            UnicastEntry {
                owner: NodeId::new([0, 0, 0, 0, 0, 4]),
                nexthop: Some(NodeId::new([0, 0, 0, 0, 0, 2])),
                cost: 20,
            },
        ));

        let update = DataplaneUpdate {
            delta,
            node: NodeIdentity {
                b_mac: MacAddr::from([0, 0, 0, 0, 0, 1]),
                spsource_id: 0x1001,
            },
            nexthops: [(NodeId::new([0, 0, 0, 0, 0, 2]), "eth-rt2".to_owned())]
                .into_iter()
                .collect(),
            uni_ports: Default::default(),
            nni_ports: vec!["eth-rt2".to_owned()],
        };

        let msgs = encode(&update);
        assert_eq!(msgs.len(), 2);

        let Some(proto::control_msg::Msg::FdbDelta(update)) = &msgs[0].msg
        else {
            panic!("expected an FdbDelta first");
        };
        assert_eq!(update.generation, 7);
        assert_eq!(update.unicast_added.len(), 1);
        let entry = &update.unicast_added[0];
        assert_eq!(entry.cost, 20);
        assert_eq!(entry.key.as_ref().unwrap().b_vid, 4000);
        assert_eq!(entry.nexthop_system_id, vec![0, 0, 0, 0, 0, 2]);
        // The next-hop node must have been resolved to a local interface,
        // since an unresolved entry cannot be programmed.
        assert_eq!(entry.out_ifname, "eth-rt2");

        // The commit must come last, so the dataplane applies a whole batch
        // at once rather than a partially written table.
        let Some(proto::control_msg::Msg::Commit(commit)) = &msgs[1].msg else {
            panic!("expected a Commit last");
        };
        assert_eq!(commit.generation, 7);
    }

    #[test]
    fn configure_sends_identity_then_port_roles() {
        let update = DataplaneUpdate {
            delta: FdbDelta {
                generation: 1,
                snapshot: true,
                services_added: vec![(
                    100,
                    ServiceEntry {
                        base_vid: 4000,
                        transmit: true,
                        receive: true,
                        members: Default::default(),
                    },
                )],
                ..Default::default()
            },
            node: NodeIdentity {
                b_mac: MacAddr::from([0, 0, 0, 0, 0, 1]),
                spsource_id: 0x1001,
            },
            nexthops: Default::default(),
            uni_ports: [(100, vec!["eth-cust".to_owned()])]
                .into_iter()
                .collect(),
            nni_ports: vec!["eth-rt2".to_owned(), "eth-rt3".to_owned()],
        };

        let msgs = configure(&update);
        // Identity first: the datapath drops frames until it knows its own
        // B-MAC.
        let Some(proto::control_msg::Msg::NodeConfig(node)) = &msgs[0].msg
        else {
            panic!("expected NodeConfig first");
        };
        assert_eq!(node.spsource_id, 0x1001);
        assert_eq!(node.b_mac, vec![0, 0, 0, 0, 0, 1]);

        // Then one port per interface, with the customer port carrying the
        // service it belongs to and the B-VID that service runs on.
        assert_eq!(msgs.len(), 1 + 2 + 1);
        let roles: Vec<_> = msgs[1..]
            .iter()
            .map(|m| {
                let Some(proto::control_msg::Msg::PortConfig(p)) = &m.msg
                else {
                    panic!("expected PortConfig");
                };
                (p.ifname.clone(), p.role, p.i_sid, p.b_vid)
            })
            .collect();
        let nni = proto::port_config::Role::Nni as i32;
        let uni = proto::port_config::Role::Uni as i32;
        assert!(roles.contains(&("eth-rt2".to_owned(), nni, 0, 0)));
        assert!(roles.contains(&("eth-rt3".to_owned(), nni, 0, 0)));
        assert!(roles.contains(&("eth-cust".to_owned(), uni, 100, 4000)));
    }

    #[test]
    fn a_service_carries_its_member_bmacs_for_head_end_replication() {
        use holo_utils::mac_addr::MacAddr as Mac;

        // With the T bit clear, no transit node holds multicast state for
        // this node, so it must address one copy per member itself. The
        // member B-MACs therefore have to reach the dataplane.
        let members = [
            (
                NodeId::new([0, 0, 0, 0, 0, 3]),
                Mac::from([0, 0, 0, 0, 0, 3]),
            ),
            (
                NodeId::new([0, 0, 0, 0, 0, 4]),
                Mac::from([0, 0, 0, 0, 0, 4]),
            ),
        ];
        let delta = FdbDelta {
            generation: 5,
            services_added: vec![(
                100,
                ServiceEntry {
                    base_vid: 4000,
                    transmit: false,
                    receive: true,
                    members: members.into_iter().collect(),
                },
            )],
            ..Default::default()
        };
        let update = DataplaneUpdate {
            delta,
            node: NodeIdentity::default(),
            nexthops: Default::default(),
            uni_ports: [(100, vec!["eth-h1".to_owned()])].into_iter().collect(),
            nni_ports: Vec::new(),
        };

        let msgs = encode(&update);
        let Some(proto::control_msg::Msg::FdbDelta(sent)) = &msgs[0].msg else {
            panic!("expected an FdbDelta");
        };
        let svc = &sent.services_added[0];
        assert!(!svc.transmit, "head-end mode is signalled by a clear T bit");
        assert_eq!(svc.uni_ifnames, vec!["eth-h1".to_owned()]);
        assert_eq!(
            svc.member_bmacs,
            vec![vec![0, 0, 0, 0, 0, 3], vec![0, 0, 0, 0, 0, 4]]
        );
    }

    #[test]
    fn multicast_branches_resolve_to_interfaces() {
        use std::collections::BTreeSet;

        use crate::fdb::{MulticastEntry, MulticastKey};

        let mut delta = FdbDelta {
            generation: 3,
            ..Default::default()
        };
        delta.multicast_added.push((
            MulticastKey {
                base_vid: 4000,
                group_bmac: MacAddr::from([0x03, 0x10, 0x01, 0, 0, 0x64]),
            },
            MulticastEntry {
                source: NodeId::new([0, 0, 0, 0, 0, 1]),
                isid: 100,
                local_deliver: false,
                branches: [
                    NodeId::new([0, 0, 0, 0, 0, 2]),
                    // No adjacency for this one: it must be skipped rather
                    // than sent unresolved.
                    NodeId::new([0, 0, 0, 0, 0, 9]),
                ]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            },
        ));

        let update = DataplaneUpdate {
            delta,
            node: NodeIdentity::default(),
            nexthops: [(NodeId::new([0, 0, 0, 0, 0, 2]), "eth-rt2".to_owned())]
                .into_iter()
                .collect(),
            uni_ports: Default::default(),
            nni_ports: Vec::new(),
        };

        let msgs = encode(&update);
        let Some(proto::control_msg::Msg::FdbDelta(sent)) = &msgs[0].msg else {
            panic!("expected an FdbDelta");
        };
        let entry = &sent.multicast_added[0];
        assert_eq!(entry.out_ifnames, vec!["eth-rt2".to_owned()]);
        assert_eq!(entry.i_sid, 100);
        assert!(!entry.local_deliver);
    }

    #[test]
    fn a_local_bmac_encodes_without_a_nexthop() {
        let mut delta = FdbDelta {
            generation: 1,
            snapshot: true,
            ..Default::default()
        };
        delta.unicast_added.push((
            UnicastKey {
                base_vid: 4000,
                bmac: MacAddr::from([0, 0, 0, 0, 0, 1]),
            },
            UnicastEntry {
                owner: NodeId::new([0, 0, 0, 0, 0, 1]),
                nexthop: None,
                cost: 0,
            },
        ));
        let update = DataplaneUpdate {
            delta,
            node: NodeIdentity::default(),
            nexthops: Default::default(),
            uni_ports: Default::default(),
            nni_ports: Vec::new(),
        };
        let msgs = encode(&update);
        let Some(proto::control_msg::Msg::FdbDelta(sent)) = &msgs[0].msg else {
            panic!("expected an FdbDelta");
        };
        assert!(sent.snapshot);
        // No next hop and no interface: the dataplane reads that as "this
        // B-MAC is mine, decapsulate".
        assert!(sent.unicast_added[0].nexthop_system_id.is_empty());
        assert!(sent.unicast_added[0].out_ifname.is_empty());
    }
}
