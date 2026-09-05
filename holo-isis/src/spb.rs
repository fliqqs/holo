//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

//! The boundary between IS-IS and SPB computation.
//!
//! IS-IS owns the LSDB; `holo-spb` owns the RFC 6329 algorithms. This module
//! translates the former into the latter's [`TopologyView`], runs the
//! computation, and keeps the results for northbound state and for
//! programming the dataplane.

use std::collections::BTreeMap;
use std::time::Instant;

use holo_spb::dataplane::{DataplaneUpdate, NodeIdentity};
use holo_spb::digest;
use holo_spb::digest::{
    AgreementDigest, HoloLocalDigest, LocalAgreement, UnsafeTrees,
};
use holo_spb::ect::EctAlgorithm;
use holo_spb::fdb::Fdb;
use holo_spb::node::NodeId;
use holo_spb::topology::{
    EctVid, IsidMembership, LinkView, NodeView, ServiceView, SpbInstanceView,
    TopologyView,
};
use holo_spb::tree::TreeSet;
use holo_utils::task::Task;
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::adjacency::{Adjacency, AdjacencyState};
use crate::collections::{Arena, Interfaces, Lsdb};
use crate::debug::Debug;
use crate::instance::InstanceUpView;
use crate::lsdb::LspEntry;
use crate::northbound::configuration::SpbInterfaceRole;
use crate::packet::iana::MtId;
use crate::packet::{LevelNumber, LevelType, SystemId};
#[cfg(not(feature = "testing"))]
use crate::tasks;

/// Upper bound on the number of trees computed per SPB instance.
///
/// The work is |B-VID| x |multicast transmitters|, which is bounded in
/// practice but not by anything structural, so a cap keeps a
/// misconfiguration from stalling the instance. Exceeding it is reported as
/// state rather than silently degrading forwarding.
const MAX_TREES: usize = 4096;

/// SPB computation results held per instance.
#[derive(Debug, Default)]
pub struct SpbState {
    /// Sender for forwarding updates bound for the dataplane, and the task
    /// draining it. Created on the first computation with SPB enabled.
    pub fdb_tx: Option<UnboundedSender<DataplaneUpdate>>,
    pub dp_task: Option<Task<()>>,
    /// The most recent topology view handed to `holo-spb`.
    pub view: Option<TopologyView>,
    /// Computed trees, keyed by (MT-ID, B-VID, algorithm, root).
    pub trees: TreeSet,
    /// The forwarding state derived from those trees.
    pub fdb: Fdb,
    /// Trees that could not be computed because [`MAX_TREES`] was reached.
    pub trees_skipped: usize,
    /// Our side of the agreement exchange with neighbours.
    pub agreement: LocalAgreement,
    /// Trees whose multicast state is withheld until agreement is reached.
    pub unsafe_trees: UnsafeTrees,
    /// Whether every SPB adjacency is currently in agreement.
    ///
    /// Recomputed as Hellos arrive, so that the gate lifts as soon as
    /// neighbours confirm they see the same topology.
    pub agreed_adjacencies: bool,
    /// Set when the digest changes, so the Hello tasks can be restarted.
    ///
    /// A Hello is built once and re-sent on a timer, so a digest that
    /// changed after the task started would otherwise be advertised stale
    /// forever.
    pub hello_refresh_pending: bool,
    /// Monotonic generation, incremented on every change to `fdb`.
    pub generation: u64,
    /// Duration of the last computation.
    pub last_duration: Option<std::time::Duration>,
}

/// Recomputes SPB state for one level from the current LSDB.
///
/// Called after SPF, since a topology change that affects IS-IS routing
/// affects SPB trees too, and the LSDB is settled at that point.
pub(crate) fn recompute(
    level: LevelNumber,
    instance: &mut InstanceUpView<'_>,
    interfaces: &Interfaces,
    adjacencies: &Arena<Adjacency>,
    lsp_entries: &Arena<LspEntry>,
) {
    if !instance.config.spb.enabled {
        // Drop any state left from when SPB was enabled, so a disabled
        // instance does not keep advertising stale forwarding entries.
        if instance.state.spb.view.is_some() {
            instance.state.spb = Default::default();
        }
        return;
    }

    let start = Instant::now();

    let view = build_topology_view(level, instance, lsp_entries);
    let ect_vids = local_ect_vids(instance);

    let (trees, trees_skipped) =
        TreeSet::compute(&view, MtId::Standard as u16, &ect_vids, MAX_TREES);

    // A tree whose distance to its root has changed cannot have its
    // multicast state updated until neighbours confirm they see the same
    // topology, or a frame could be forwarded back where it came from.
    mark_unsafe_trees(instance, &trees);

    let fdb = Fdb::build(&view, &trees, MtId::Standard as u16, &ect_vids);

    // Evaluate agreement here as well as on Hello receipt, so the verdict is
    // never stale — in particular, a node with no SPB neighbours has nobody
    // to disagree with and must not gate anything.
    reevaluate_agreement(instance, interfaces, adjacencies);
    let fdb = withhold_unsafe(instance, fdb);

    // The digest summarises the view neighbours must agree with. Advertising
    // it is what lets both ends decide the trees are settled.
    let digest = HoloLocalDigest.compute(&view, MtId::Standard as u16);
    if instance.state.spb.agreement.update(digest) {
        // Hellos carry the digest and are built once per task, so the task
        // has to be restarted for the new one to reach neighbours.
        instance.state.spb.hello_refresh_pending = true;
        if instance.config.trace_opts.spb {
            Debug::SpbDigestChanged(instance.state.spb.agreement.agreement)
                .log();
        }
    }

    // Send the dataplane whatever actually changed. The first update after
    // the session starts is a snapshot, so the dataplane can discard state
    // left over from before a restart.
    let previous = &instance.state.spb.fdb;
    let first = instance.state.spb.generation == 0;
    let changed = fdb != *previous;
    if changed {
        instance.state.spb.generation += 1;
        let generation = instance.state.spb.generation;
        let delta = if first {
            fdb.snapshot(generation)
        } else {
            fdb.delta(previous, generation)
        };
        if !delta.is_empty() {
            if instance.config.trace_opts.spb {
                Debug::SpbFdbDelta(delta.len(), delta.snapshot).log();
            }
            let update = DataplaneUpdate {
                delta,
                node: node_identity(instance),
                nexthops: resolve_nexthops(interfaces, adjacencies),
                uni_ports: uni_ports(interfaces),
                nni_ports: nni_ports(interfaces),
            };
            send_dataplane_update(instance, update);
        }
    }

    let duration = start.elapsed();
    if instance.config.trace_opts.spb {
        Debug::SpbComputeFinish(
            trees.len(),
            fdb.unicast.len(),
            fdb.multicast.len(),
            duration,
        )
        .log();
    }

    instance.state.spb.view = Some(view);
    instance.state.spb.trees = trees;
    instance.state.spb.fdb = fdb;
    instance.state.spb.trees_skipped = trees_skipped;
    instance.state.spb.last_duration = Some(duration);

    let _ = level;
}

/// Marks trees whose distance to the root changed since the last run.
///
/// Comparing against the previous computation is what identifies the trees
/// that are unsettled; everything else may be programmed immediately.
fn mark_unsafe_trees(instance: &mut InstanceUpView<'_>, trees: &TreeSet) {
    let local = node_id(instance.config.system_id.unwrap());
    let previous = &instance.state.spb.trees;
    let mut marked = UnsafeTrees::default();

    for (key, tree) in trees.iter() {
        let now = tree.cost(local);
        let before = previous.get(key).and_then(|old| old.cost(local));
        if now != before {
            marked.mark(key.base_vid, key.root);
        }
    }

    instance.state.spb.unsafe_trees = marked;
}

/// Removes multicast state for trees that are not yet safe to program.
///
/// Unicast forwarding is unaffected: the ingress check makes a stale unicast
/// entry a dropped frame, not a loop. Only multicast can loop.
fn withhold_unsafe(instance: &InstanceUpView<'_>, mut fdb: Fdb) -> Fdb {
    let unsafe_trees = &instance.state.spb.unsafe_trees;
    if unsafe_trees.is_empty() || agreed_everywhere(instance) {
        return fdb;
    }

    let before = fdb.multicast.len();
    fdb.multicast
        .retain(|key, entry| unsafe_trees.is_safe(key.base_vid, entry.source));
    let withheld = before - fdb.multicast.len();

    if withheld > 0 && instance.config.trace_opts.spb {
        Debug::SpbMulticastWithheld(withheld).log();
    }
    fdb
}

/// Returns whether every SPB adjacency currently agrees with us.
fn agreed_everywhere(instance: &InstanceUpView<'_>) -> bool {
    instance.state.spb.agreed_adjacencies
}

/// Re-evaluates agreement with every SPB neighbour.
///
/// Called when a Hello brings a neighbour's digest, since that is the only
/// thing that can lift the gate on multicast forwarding. Returns whether the
/// verdict changed, so the caller can recompute only when it matters.
pub(crate) fn reevaluate_agreement(
    instance: &mut InstanceUpView<'_>,
    interfaces: &Interfaces,
    adjacencies: &Arena<Adjacency>,
) -> bool {
    if !instance.config.spb.enabled {
        return false;
    }

    let local = &instance.state.spb.agreement;
    let mut agreed = true;
    let mut any = false;

    for iface in interfaces.iter() {
        if !iface.config.spb.enabled {
            continue;
        }
        for adj in iface.adjacencies(adjacencies) {
            if adj.state != AdjacencyState::Up || !adj.is_spb_capable() {
                continue;
            }
            any = true;

            let verdict = digest::evaluate(local, adj.spb_agreement.as_ref());
            if !verdict.is_agreed() {
                agreed = false;
                if instance.config.trace_opts.spb {
                    Debug::SpbDigestMismatch(
                        adj.system_id,
                        verdict_name(verdict),
                    )
                    .log();
                }
            }
        }
    }

    // With no SPB neighbours there is nobody to disagree with, so nothing is
    // gated.
    let agreed = agreed || !any;
    let changed = instance.state.spb.agreed_adjacencies != agreed;
    instance.state.spb.agreed_adjacencies = agreed;
    changed
}

/// Restarts the Hello tasks on SPB interfaces if the digest has changed.
///
/// Called from the paths that hold the interfaces mutably. A Hello is
/// rebuilt only when there is a new digest to advertise, so this costs
/// nothing in steady state.
pub(crate) fn refresh_hellos(
    instance: &mut InstanceUpView<'_>,
    interfaces: &mut Interfaces,
) {
    if !std::mem::take(&mut instance.state.spb.hello_refresh_pending) {
        return;
    }

    for iface in interfaces.iter_mut() {
        // Only an interface with a running network task sends Hellos. A
        // passive one — a customer port, say — has no socket, and asking it
        // to restart its Hello task would panic.
        if !iface.config.spb.enabled
            || iface.config.passive
            || iface.state.net.is_none()
        {
            continue;
        }
        iface.hello_interval_start(instance, LevelType::All);
    }
}

/// A short reason for a disagreement, for tracing.
fn verdict_name(verdict: digest::Agreement) -> &'static str {
    match verdict {
        digest::Agreement::Agreed => "agreed",
        digest::Agreement::NoDigest => "no digest received",
        digest::Agreement::NotValid => "digest not valid",
        digest::Agreement::DigestMismatch => "digests differ",
        digest::Agreement::Outstanding => "agreement number outstanding",
    }
}

/// Returns this node's backbone identity.
///
/// The nodal B-MAC is the B-MAC of the first configured service; a node with
/// no service of its own is pure transit and never sources a frame, so a zero
/// address is correct for it.
fn node_identity(instance: &InstanceUpView<'_>) -> NodeIdentity {
    let cfg = &instance.config.spb;
    NodeIdentity {
        b_mac: cfg
            .services
            .keys()
            .map(|key| key.bmac)
            .next()
            .unwrap_or_default(),
        spsource_id: cfg.spsource_id.unwrap_or(0),
    }
}

/// Maps each adjacent node to the local interface reaching it.
///
/// SPB computation names next hops by node; the dataplane needs ports, and
/// only the adjacency database can bridge the two.
fn resolve_nexthops(
    interfaces: &Interfaces,
    adjacencies: &Arena<Adjacency>,
) -> BTreeMap<NodeId, String> {
    let mut map = BTreeMap::new();
    for iface in interfaces.iter() {
        if !iface.config.spb.enabled {
            continue;
        }
        for adj in iface.adjacencies(adjacencies) {
            if adj.state != AdjacencyState::Up {
                continue;
            }
            map.insert(node_id(adj.system_id), iface.name.clone());
        }
    }
    map
}

/// Returns the customer-facing interfaces of each service.
fn uni_ports(interfaces: &Interfaces) -> BTreeMap<u32, Vec<String>> {
    let mut map: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for iface in interfaces.iter() {
        let cfg = &iface.config.spb;
        if !cfg.enabled || cfg.role != SpbInterfaceRole::Customer {
            continue;
        }
        for isid in &cfg.uni_isids {
            map.entry(*isid).or_default().push(iface.name.clone());
        }
    }
    map
}

/// Returns the backbone-facing interfaces.
fn nni_ports(interfaces: &Interfaces) -> Vec<String> {
    interfaces
        .iter()
        .filter(|iface| {
            iface.config.spb.enabled
                && iface.config.spb.role == SpbInterfaceRole::Backbone
        })
        .map(|iface| iface.name.clone())
        .collect()
}

/// Hands a forwarding update to the dataplane.
///
/// The delta is not mirrored into the conformance harness's output: it is
/// produced from synchronous computation, so its arrival at an async relay
/// would race the harness's per-step collection and make goldens flaky. The
/// same information is asserted deterministically through the `computed`
/// northbound state instead.
#[cfg_attr(feature = "testing", allow(unused_variables))]
fn send_dataplane_update(
    instance: &mut InstanceUpView<'_>,
    update: DataplaneUpdate,
) {
    #[cfg(not(feature = "testing"))]
    {
        if !instance.config.spb.dataplane_enabled {
            return;
        }
        // The session is long-lived and reconnects on its own, so it is
        // started once, on the first update.
        if instance.state.spb.fdb_tx.is_none() {
            let (tx, rx) = mpsc::unbounded_channel();
            let task = tasks::spb_dataplane(
                std::path::PathBuf::from(&instance.config.spb.dataplane_socket),
                rx,
            );
            instance.state.spb.fdb_tx = Some(tx);
            instance.state.spb.dp_task = Some(task);
        }
        if let Some(tx) = &instance.state.spb.fdb_tx {
            let _ = tx.send(update);
        }
    }
}

/// Returns the tree sets this node is configured to operate.
fn local_ect_vids(instance: &InstanceUpView<'_>) -> Vec<EctVid> {
    instance
        .config
        .spb
        .trees
        .iter()
        .map(|(&base_vid, cfg)| EctVid {
            base_vid,
            algorithm: EctAlgorithm::from_index(cfg.algorithm)
                .unwrap_or(holo_spb::ect::ECT_ALG_DEFAULT),
            spvid: cfg.spvid,
            multicast: cfg.multicast,
        })
        .collect()
}

/// Describes the local node from its own configuration.
fn local_node_view(instance: &InstanceUpView<'_>) -> NodeView {
    let cfg = &instance.config.spb;
    let services = cfg
        .services
        .iter()
        .map(|(key, svc)| ServiceView {
            bmac: key.bmac,
            base_vid: key.base_vid,
            isids: svc
                .isids
                .iter()
                .map(|(&isid, isid_cfg)| IsidMembership {
                    isid,
                    transmit: isid_cfg.transmit,
                    receive: isid_cfg.receive,
                })
                .collect(),
        })
        .collect();

    NodeView {
        bridge_priority: cfg.bridge_priority,
        // Zero is advertised while an auto-allocated SPSourceID is still
        // pending, which is exactly what RFC 6329 reserves the value for.
        spsource_id: cfg.spsource_id.unwrap_or(0),
        spsource_id_auto: cfg.spsource_id_auto,
        overload: false,
        ect_vids: local_ect_vids(instance),
        services,
    }
}

/// Builds the SPB topology view from the LSDB.
///
/// Only nodes advertising an SPB-Inst Sub-TLV take part, and only adjacencies
/// carrying an SPB-Metric Sub-TLV contribute links. Both directions of a link
/// are recorded so that an asymmetric metric advertisement stays visible to
/// the cost resolution in `holo-spb` rather than being reconciled here.
fn build_topology_view(
    level: LevelNumber,
    instance: &InstanceUpView<'_>,
    lsp_entries: &Arena<LspEntry>,
) -> TopologyView {
    let lsdb: &Lsdb = instance.state.lsdb.get(level);
    let mut view = TopologyView {
        local: node_id(instance.config.system_id.unwrap()),
        ..Default::default()
    };

    view.instances.insert(
        MtId::Standard as u16,
        SpbInstanceView {
            mt_id: MtId::Standard as u16,
            ect_vids: local_ect_vids(instance),
        },
    );

    // The local node is described from configuration rather than by parsing
    // its own LSP back. Reading it from the LSDB would make SPB state lag
    // LSP origination, so a configuration change would not take effect until
    // the next origination and SPF cycle.
    view.nodes.insert(view.local, local_node_view(instance));

    for lse in lsdb.iter(lsp_entries) {
        let lsp = &lse.data;
        // Only fragment zero carries SPB-Inst, and pseudonode LSPs never do.
        if lsp.lsp_id.fragment != 0 || lsp.lsp_id.is_pseudonode() {
            continue;
        }

        // The local node is already described from configuration.
        if lsp.lsp_id.system_id == instance.config.system_id.unwrap() {
            continue;
        }

        for mt_cap in &lsp.tlvs.mt_cap {
            if mt_cap.mt_id != MtId::Standard as u16 {
                continue;
            }
            let Some(spb_inst) = &mt_cap.sub_tlvs.spb_inst else {
                // Without SPB-Inst the node is not an SPB participant.
                continue;
            };

            let id = node_id(lsp.lsp_id.system_id);
            let ect_vids = spb_inst
                .vlan_id_tuples
                .iter()
                .map(|tuple| EctVid {
                    base_vid: tuple.base_vid,
                    algorithm: EctAlgorithm(tuple.ect_algorithm),
                    spvid: tuple
                        .flags
                        .contains(
                            crate::packet::subtlvs::spb::VlanIdTupleFlags::A,
                        )
                        .then_some(tuple.spvid),
                    multicast: tuple.flags.contains(
                        crate::packet::subtlvs::spb::VlanIdTupleFlags::M,
                    ),
                })
                .collect();

            let services = mt_cap
                .sub_tlvs
                .spbm_si
                .iter()
                .map(|spbm_si| ServiceView {
                    bmac: spbm_si.bmac.into(),
                    base_vid: spbm_si.base_vid,
                    isids: spbm_si
                        .isid_entries
                        .iter()
                        .map(|entry| IsidMembership {
                            isid: entry.isid,
                            transmit: entry.flags.contains(
                                crate::packet::subtlvs::spb::IsidFlags::T,
                            ),
                            receive: entry.flags.contains(
                                crate::packet::subtlvs::spb::IsidFlags::R,
                            ),
                        })
                        .collect(),
                })
                .collect();

            view.nodes.insert(
                id,
                NodeView {
                    bridge_priority: spb_inst.bridge_priority,
                    spsource_id: spb_inst.spsource_id,
                    spsource_id_auto: spb_inst.spsource_id_auto,
                    overload: mt_cap.overload,
                    ect_vids,
                    services,
                },
            );
        }
    }

    // Collect links from every SPB participant's IS reachability TLVs.
    for lse in lsdb.iter(lsp_entries) {
        let lsp = &lse.data;
        if lsp.lsp_id.is_pseudonode() {
            continue;
        }
        let from = node_id(lsp.lsp_id.system_id);
        if !view.nodes.contains_key(&from) {
            continue;
        }

        for reach in lsp.tlvs.ext_is_reach.iter().flat_map(|tlv| &tlv.list) {
            let to = node_id(reach.neighbor.system_id);
            let Some(spb_metric) = &reach.sub_tlvs.spb_metric else {
                // "If this sub-TLV is not present for an IS-IS adjacency,
                // then that adjacency Must not carry SPB traffic."
                continue;
            };
            view.links.push(LinkView {
                from,
                to,
                metric: Some(spb_metric.metric),
                port_ids: spb_metric.port_ids.clone(),
            });
        }
    }

    view
}

fn node_id(system_id: SystemId) -> NodeId {
    NodeId::new(*system_id.as_ref())
}
