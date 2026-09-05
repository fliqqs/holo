//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_isis::instance::Instance;
use holo_protocol::test::stub::run_test_topology;

#[tokio::test]
async fn topology1_1() {
    for rt_num in 1..=7 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance>("topo1-1", &rt_name).await;
    }
}

#[tokio::test]
async fn topology1_2() {
    for rt_num in 1..=7 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance>("topo1-2", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_1() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance>("topo2-1", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_2() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance>("topo2-2", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_3() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance>("topo2-3", &rt_name).await;
    }
}

#[tokio::test]
async fn topology2_4() {
    for rt_num in 1..=6 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance>("topo2-4", &rt_name).await;
    }
}

// Four-node SPB region with a deliberate equal-cost tie: B-VID 4000 uses ECT
// algorithm 1 and B-VID 4001 uses algorithm 2, so the same destination is
// reached through different neighbours on the two B-VIDs.
#[tokio::test]
async fn topology_spb1_1() {
    for rt_num in 1..=4 {
        let rt_name = format!("rt{rt_num}");
        run_test_topology::<Instance>("spb-topo1-1", &rt_name).await;
    }
}
