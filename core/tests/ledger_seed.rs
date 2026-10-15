//! Forensic seed DB generator for ave-ledger-verify e2e tests.
//!
//! NEVER runs with Ave's own packs: marked `ignore`, only the
//! seed script runs it explicitly. It has nothing to do with
//! Ave's suites (no asserts on node behavior, only ledger
//! emission + manifest).
//!
//! `ave-ledger-verify/scripts/seed-ledger-db.sh` (reads
//! `scripts/seed-config.json`, writes DBs + `manifest.json` under
//! the ignored `ledger-verify-e2e/` dir). Boots three real nodes
//! with persistent dirs, runs the event matrix over a real
//! network with real compiles and votes, shuts down cleanly.
//! Every scenario asserts its own outcome: a seed that does not
//! produce exactly the documented ledger fails loud instead of
//! writing a lying manifest.

use std::{
    collections::BTreeSet, path::PathBuf, str::FromStr,
    sync::atomic::Ordering,
};

mod common;

use ave_common::{
    bridge::response::{EvalResDB, RequestEventDB},
    identity::{DigestIdentifier, PublicKey},
};
use ave_core::auth::AuthWitness;
use ave_network::{NodeType, RoutingNode};
use common::{
    CHANGED_SCHEMA_CONTRACT, EXAMPLE_CONTRACT, EXAMPLE_CONTRACT_V2,
    INVALID_EXAMPLE_CONTRACT, PORT_COUNTER, assert_tracker_fact_opaque,
    create_and_authorize_governance, create_node, create_subject, emit_approve,
    emit_confirm, emit_eol, emit_fact, emit_fact_viewpoints, emit_reject,
    emit_transfer, get_events, get_subject, node_running,
};
use futures::future::join_all;
use serde_json::{Value, json};
use test_log::test;

use crate::common::CreateNodeConfig;

// Test-harness node password (`Api::build` callers pass it;
// the manifest records it so consumers never guess).
const PASSWORD: &str = "ave";

fn seed_dir() -> PathBuf {
    PathBuf::from(std::env::var("AVE_SEED_DIR").expect(
        "AVE_SEED_DIR must point at the output dir (run ave-ledger-verify/scripts/seed-ledger-db.sh)",
    ))
}

fn seed_config() -> Value {
    let path = std::env::var("AVE_SEED_CONFIG").expect(
        "AVE_SEED_CONFIG must point at the seed config (run ave-ledger-verify/scripts/seed-ledger-db.sh)",
    );
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("can not read seed config {path}: {e}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("invalid seed config {path}: {e}"))
}

fn on(config: &Value, scenario: &str) -> bool {
    config
        .get("scenarios")
        .and_then(|scenarios| scenarios.get(scenario))
        .and_then(|flag| flag.as_bool())
        .unwrap_or(true)
}

// Node-pattern waits: every network wait below fails loud after
// its budget instead of hanging forever (a reboot-looping request
// never reaches a terminal state, and `wait_request` alone never
// times out). Budgets mirror the node watchdog envelope: minutes
// of headroom so slowness under load never trips them — only a
// stuck request does.
const EMIT_BUDGET_SECS: u64 = 600;
const BOOT_BUDGET_SECS: u64 = 120;

async fn budgeted<F, T>(label: &str, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(std::time::Duration::from_secs(EMIT_BUDGET_SECS), future)
        .await
        .unwrap_or_else(|_| panic!("seed emit timed out: {label}"))
}

async fn emit_fact_timed(
    node: &ave_core::Api,
    subject: DigestIdentifier,
    payload: Value,
) -> Result<DigestIdentifier, Box<dyn std::error::Error>> {
    budgeted(
        &format!("fact on {subject}"),
        emit_fact(node, subject.clone(), payload, true),
    )
    .await

}

async fn emit_fact_viewpoints_timed(
    node: &ave_core::Api,
    subject: DigestIdentifier,
    payload: Value,
    viewpoints: BTreeSet<String>,
) -> Result<DigestIdentifier, Box<dyn std::error::Error>> {
    budgeted(
        &format!("viewpoint fact on {subject}"),
        emit_fact_viewpoints(node, subject.clone(), payload, viewpoints, true),
    )
    .await

}

async fn emit_transfer_timed(
    node: &ave_core::Api,
    subject: DigestIdentifier,
    new_owner: PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    budgeted(
        &format!("transfer on {subject}"),
        emit_transfer(node, subject.clone(), new_owner, true),
    )
    .await

}

async fn emit_confirm_timed(
    node: &ave_core::Api,
    subject: DigestIdentifier,
    new_name: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    budgeted(
        &format!("confirm on {subject}"),
        emit_confirm(node, subject.clone(), new_name, true),
    )
    .await

}

async fn emit_reject_timed(
    node: &ave_core::Api,
    subject: DigestIdentifier,
) -> Result<(), Box<dyn std::error::Error>> {
    budgeted(
        &format!("reject on {subject}"),
        emit_reject(node, subject.clone(), true),
    )
    .await

}

async fn emit_eol_timed(
    node: &ave_core::Api,
    subject: DigestIdentifier,
) -> Result<(), Box<dyn std::error::Error>> {
    budgeted(
        &format!("eol on {subject}"),
        emit_eol(node, subject.clone(), true),
    )
    .await

}

async fn create_subject_timed(
    node: &ave_core::Api,
    governance: DigestIdentifier,
    schema: &str,
    namespace: &str,
) -> Result<(DigestIdentifier, DigestIdentifier), Box<dyn std::error::Error>> {
    budgeted(
        &format!("create subject on {governance}"),
        create_subject(node, governance.clone(), schema, namespace, true),
    )
    .await

}

async fn create_and_authorize_governance_timed(
    owner: &ave_core::Api,
    others: Vec<&ave_core::Api>,
) -> DigestIdentifier {
    budgeted(
        "create governance",
        create_and_authorize_governance(owner, others),
    )
    .await
}

async fn boot_node(
    node_type: NodeType,
    db: PathBuf,
    peers: Vec<RoutingNode>,
    always_accept: bool,
) -> (common::NodeData, PathBuf) {
    std::fs::create_dir_all(&db)
        .unwrap_or_else(|e| panic!("can not create seed db {}: {e}", db.display()));
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _tempdirs) = create_node(CreateNodeConfig {
        node_type,
        listen_address: format!("/memory/{port}"),
        peers,
        always_accept,
        local_db: Some(db.clone()),
        ..Default::default()
    })
    .await;
    tokio::time::timeout(
        std::time::Duration::from_secs(BOOT_BUDGET_SECS),
        node_running(&node.api),
    )
    .await
    .unwrap_or_else(|_| panic!("node boot timed out at {}", db.display()))
    .unwrap();
    (node, db)
}

fn peer_of(node: &common::NodeData, address: &str) -> RoutingNode {
    RoutingNode {
        peer_id: node.api.peer_id().to_string(),
        address: vec![address.to_owned()],
    }
}

async fn shutdown(mut nodes: Vec<common::NodeData>) {
    for node in &nodes {
        node.token.cancel();
    }
    for node in nodes.iter_mut() {
        join_all(node.handler.iter_mut()).await;
    }
}

#[derive(Debug)]
struct SnRecord {
    sn: u64,
    protocols: &'static str,
    success: bool,
    /// Governance version the event anchored (deduced from emission
    /// order; e2e cross-checks it against the real ledger).
    gov_version: u64,
}

fn record(sn: u64, protocols: &'static str, success: bool, gov: u64) -> SnRecord {
    SnRecord {
        sn,
        protocols,
        success,
        gov_version: gov,
    }
}

fn records_json(records: &[SnRecord]) -> Vec<Value> {
    records
        .iter()
        .map(|record| {
            serde_json::json!({
                "sn": record.sn,
                "protocols": record.protocols,
                "success": record.success,
                "gov_version": record.gov_version,
            })
        })
        .collect()
}

fn protocols_of(event: &RequestEventDB) -> (&'static str, bool) {
    match event {
        RequestEventDB::Create { .. } => ("Create", true),
        RequestEventDB::TrackerFactFull {
            evaluation_response,
            ..
        } => (
            "TrackerFactFull",
            matches!(evaluation_response, EvalResDB::Patch(_)),
        ),
        RequestEventDB::TrackerFactOpaque {
            evaluation_success,
            ..
        } => ("TrackerFactOpaque", *evaluation_success),
        RequestEventDB::GovernanceFact {
            approval_success,
            ..
        } => ("GovFact", matches!(approval_success, Some(true))),
        RequestEventDB::Transfer {
            evaluation_error, ..
        } => ("Transfer", evaluation_error.is_none()),
        RequestEventDB::TrackerConfirm => ("TrackerConfirm", true),
        RequestEventDB::GovernanceConfirm {
            evaluation_response,
            ..
        } => (
            "GovConfirm",
            matches!(evaluation_response, EvalResDB::Patch(_)),
        ),
        RequestEventDB::Reject => ("Reject", true),
        RequestEventDB::EOL => ("EOL", true),
    }
}

#[test(tokio::test)]
#[ignore = "forensic seed only: run ave-ledger-verify/scripts/seed-ledger-db.sh"]
async fn seed_ledger_db() {
    let root = seed_dir();
    let config = seed_config();
    assert!(
        root.is_dir(),
        "seed dir {} does not exist",
        root.display()
    );
    if on(&config, "tracker_opaque") {
        assert!(
            on(&config, "tracker_facts"),
            "tracker_opaque needs tracker_facts (sns must be contiguous)"
        );
    }
    assert!(
        on(&config, "gov_member"),
        "everything needs the gov member+schema fact"
    );

    // Three nodes with persistent dirs (nothing TempDir: the data
    // must survive the test process). Extra tempdirs below stay
    // alive till the end (node restarts reuse them).
    let mut seed_held_dirs = Vec::new();
    let (node0, db0) =
        boot_node(NodeType::Bootstrap, root.join("node0"), vec![], true).await;
    let listen0 = node0.listen_address.clone();
    // node1 never auto-votes: the rejection scenario votes by hand.
    let (node1, db1) = boot_node(
        NodeType::Addressable,
        root.join("node1"),
        vec![peer_of(&node0, &listen0)],
        false,
    )
    .await;
    let (mut node2, db2) = boot_node(
        NodeType::Addressable,
        root.join("node2"),
        vec![peer_of(&node0, &listen0)],
        true,
    )
    .await;

    let api0 = &node0.api;
    let api1 = &node1.api;
    let key1 = PublicKey::from_str(api1.public_key()).unwrap();

    // Governance: owner node0, witness node1, member + schema +
    // roles in two facts (the schema fact compiles for real).
    let gov = create_and_authorize_governance_timed(api0, vec![api1, &node2.api]).await;
    // Gov versions are deduced from emission order: every event
    // anchors the governance version in force BEFORE it applies,
    // and every successful gov event bumps exactly one. Failures
    // freeze the version.
    let mut gov_records = vec![SnRecord {
        sn: 0,
        protocols: "Create",
        success: true,
        gov_version: 0,
    }];

    if on(&config, "gov_member") {
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": api1.public_key()}]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
            "roles": {
                "governance": {"add": {"witness": ["AveNode2"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "creator": [{
                            "name": "Owner",
                            "namespace": [],
                            "quantity": "infinity",
                            "witnesses": [{
                                "name": "AveNode2",
                                "viewpoints": ["agua"],
                            }],
                        }],
                        "issuer": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "AveNode2", "namespace": []}],
                    },
                }],
            },
        });
        emit_fact_timed(api0, gov.clone(), json).await.unwrap();
        let _ = get_subject(api0, gov.clone(), Some(1), true).await.unwrap();
        gov_records.push(SnRecord {
            sn: 1,
            protocols: "GovFact",
            success: true,
            gov_version: 0,
        });
        // Creator role for the transfer recipient (transfers
        // require the new owner to be member + creator): without
        // it the transfer below would fail evaluation.
        let json = json!({
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {"creator": [{
                    "name": "AveNode2",
                    "namespace": [],
                    "quantity": "infinity",
                }]},
            }]},
        });
        emit_fact_timed(api0, gov.clone(), json).await.unwrap();
        let _ = get_subject(api1, gov.clone(), Some(2), true).await.unwrap();
        gov_records.push(SnRecord {
            sn: 2,
            protocols: "GovFact",
            success: true,
            gov_version: 1,
        });
    }

    if on(&config, "gov_compile") {
        // Compilers vote InvalidEvent on an unknown schema change:
        // commits failed, no evaluation, version frozen.
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "NotASchema",
                "new_initial_value": {"one": 1},
            }]},
        });
        emit_fact_timed(api0, gov.clone(), json).await.unwrap();
        let next_sn = gov_records.last().expect("gov ran").sn + 1;
        gov_records.push(SnRecord {
            sn: next_sn,
            protocols: "GovFact",
            success: false,
            gov_version: 2,
        });
        // Duplicate schema add: evaluation fails deterministically,
        // commits failed, version frozen.
        let json = json!({
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
        });
        emit_fact_timed(api0, gov.clone(), json).await.unwrap();
        let next_sn = gov_records.last().expect("gov ran").sn + 1;
        gov_records.push(SnRecord {
            sn: next_sn,
            protocols: "GovFact",
            success: false,
            gov_version: 2,
        });
        // The duplicate add touches a schema, so it carries a
        // successful compilation with a failed evaluation
        // (CompileEval shape), not a bare failure.
        {
            use ave_common::bridge::response::{CompResDB, EvalResDB};
            let events = get_events(api0, gov.clone(), next_sn as usize + 1, true)
                .await
                .unwrap();
            match &events[next_sn as usize].event {
                ave_common::bridge::response::RequestEventDB::GovernanceFact {
                    compilation_response:
                        Some(CompResDB::Ok { contracts, .. }),
                    evaluation_response: EvalResDB::Error(_),
                    ..
                } => assert!(!contracts.is_empty()),
                other => panic!("dup-schema must commit CompileEval, got {other:?}"),
            }
        }
    }

    // Tracker T1: facts (ok, error, viewpoint), transfer, confirm.
    // Everything below runs while gov sits at v2, so every event
    // anchors gov_version 2.
    let (t1, ..) =
        create_subject_timed(api0, gov.clone(), "Example", "").await.unwrap();
    let mut t1_records = vec![SnRecord {
        sn: 0,
        protocols: "Create",
        success: true,
        gov_version: 2,
    }];
    if on(&config, "tracker_facts") {
        emit_fact_timed(api0, t1.clone(), json!({"ModOne": {"data": 1}}))
            .await
            .unwrap();
        t1_records.push(SnRecord {
            sn: 1,
            protocols: "TrackerFactFull",
            success: true,
            gov_version: 2,
        });

        // Contract rejects the mistyped payload: commits failed,
        // properties untouched.
        emit_fact_timed(api0, t1.clone(), json!({"ModOne": {"data": "xx"}}))
            .await
            .unwrap();
        let state = get_subject(api0, t1.clone(), Some(2), true).await.unwrap();
        assert_eq!(
            state.properties,
            json!({"one": 1, "two": 0, "three": 0}),
            "failed fact must not move properties"
        );
        t1_records.push(SnRecord {
            sn: 2,
            protocols: "TrackerFactFull",
            success: false,
            gov_version: 2,
        });
    }

    if on(&config, "tracker_transfer_confirm") {
        emit_transfer_timed(api0, t1.clone(), key1.clone()).await.unwrap();
        let next_sn = t1_records.last().expect("facts ran").sn + 1;
        t1_records.push(SnRecord {
            sn: next_sn,
            protocols: "Transfer",
            success: true,
            gov_version: 2,
        });
        emit_confirm_timed(api1, t1.clone(), None).await.unwrap();
        let next_sn = t1_records.last().expect("transfer ran").sn + 1;
        t1_records.push(SnRecord {
            sn: next_sn,
            protocols: "TrackerConfirm",
            success: true,
            gov_version: 2,
        });
        // Barrier: confirm ran on node1; node0 must hold it
        // before the manifest cross-check reads node0.
        let _ = get_subject(api0, t1.clone(), Some(next_sn), true)
            .await
            .unwrap();
    }

    // Tracker Topaque: viewpoint fact only (emitting it degrades
    // the emitter's full ledger, so it lives alone here).
    let mut topaque_entry: Option<Value> = None;
    if on(&config, "tracker_opaque") {
        let (topaque, ..) =
            create_subject_timed(api0, gov.clone(), "Example", "")
                .await
                .unwrap();
        let mut topaque_records = vec![
            SnRecord {
                sn: 0,
                protocols: "Create",
                success: true,
                gov_version: 2,
            },
            SnRecord {
                sn: 1,
                protocols: "TrackerFactFull",
                success: true,
                gov_version: 2,
            },
        ];
        emit_fact_timed(api0, topaque.clone(), json!({"ModOne": {"data": 1}}))
            .await
            .unwrap();
        api1
            .authorize_governance(
                topaque.clone(),
                AuthWitness::One(PublicKey::from_str(api0.public_key()).unwrap()),
            )
            .await
            .unwrap();
        api1.update_subject(topaque.clone()).await.unwrap();
        // Viewpoint the witness does NOT hold: node1 stores the
        // opaque projection (a viewpoint it held would arrive full).
        emit_fact_viewpoints_timed(
            api0,
            topaque.clone(),
            json!({"ModOne": {"data": 2}}),
            BTreeSet::from(["basura".to_owned()])
        )
        .await
        .unwrap();
        let witness_events =
            get_events(api1, topaque.clone(), 3, true).await.unwrap();
        let opaque = witness_events
            .iter()
            .find(|event| event.sn == 2)
            .expect("witness must hold sn 2");
        assert_tracker_fact_opaque(&opaque.event, &["basura"])
            .expect("witness must store the opaque projection");
        topaque_records.push(SnRecord {
            sn: 2,
            protocols: "TrackerFactFull",
            success: true,
            gov_version: 2,
        });
        // Failed evaluation under a viewpoint the witness does
        // not hold: full error on the originator, opaque error on
        // the witness.
        emit_fact_viewpoints_timed(
            api0,
            topaque.clone(),
            json!({"ModOne": {"data": "xx"}}),
            BTreeSet::from(["basura".to_owned()])
        )
        .await
        .unwrap();
        let witness_events =
            get_events(api1, topaque.clone(), 4, true).await.unwrap();
        let opaque_error = witness_events
            .iter()
            .find(|event| event.sn == 3)
            .expect("witness must hold sn 3");
        assert_tracker_fact_opaque(&opaque_error.event, &["basura"])
            .expect("witness must store the opaque error");
        topaque_records.push(SnRecord {
            sn: 3,
            protocols: "TrackerFactFull",
            success: false,
            gov_version: 2,
        });
        topaque_entry = Some(serde_json::json!({
            "name": "tracker_opaque",
            "kind": "tracker",
            "subject_id": topaque.to_string(),
            "governance_id": gov.to_string(),
            "db": "node0",
            "witness_db": "node1",
            "witness_opaque_sn": 2,
            "sns": records_json(&topaque_records),
        }));
    }

    // Tracker Tmixed: half visible, half opaque on the witness.
    // node1 holds viewpoint "agua" (creator witness grant) but
    // not "basura": agua facts arrive full, basura facts arrive
    // opaque. Ok + error on each side, all on one chain.
    let mut tmixed_entry: Option<Value> = None;
    if on(&config, "tracker_mixed") {
        let (tmixed, ..) =
            create_subject_timed(api0, gov.clone(), "Example", "")
                .await
                .unwrap();
        let mut tmixed_records = vec![
            SnRecord {
                sn: 0,
                protocols: "Create",
                success: true,
                gov_version: 2,
            },
            SnRecord {
                sn: 1,
                protocols: "TrackerFactFull",
                success: true,
                gov_version: 2,
            },
        ];
        emit_fact_timed(api0, tmixed.clone(), json!({"ModOne": {"data": 1}}))
            .await
            .unwrap();
        api1
            .authorize_governance(
                tmixed.clone(),
                AuthWitness::One(PublicKey::from_str(api0.public_key()).unwrap()),
            )
            .await
            .unwrap();
        api1.update_subject(tmixed.clone()).await.unwrap();
        // Held viewpoint: full on both sides.
        emit_fact_viewpoints_timed(
            api0,
            tmixed.clone(),
            json!({"ModOne": {"data": 2}}),
            BTreeSet::from(["agua".to_owned()])
        )
        .await
        .unwrap();
        let witness_events =
            get_events(api1, tmixed.clone(), 3, true).await.unwrap();
        assert!(
            matches!(
                witness_events[2].event,
                RequestEventDB::TrackerFactFull { .. }
            ),
            "held-viewpoint fact must stay full on the witness"
        );
        tmixed_records.push(SnRecord {
            sn: 2,
            protocols: "TrackerFactFull",
            success: true,
            gov_version: 2,
        });
        // Unheld viewpoint: opaque on the witness.
        emit_fact_viewpoints_timed(
            api0,
            tmixed.clone(),
            json!({"ModOne": {"data": 3}}),
            BTreeSet::from(["basura".to_owned()])
        )
        .await
        .unwrap();
        let witness_events =
            get_events(api1, tmixed.clone(), 4, true).await.unwrap();
        let opaque = witness_events
            .iter()
            .find(|event| event.sn == 3)
            .expect("witness must hold sn 3");
        assert_tracker_fact_opaque(&opaque.event, &["basura"])
            .expect("unheld-viewpoint fact must be opaque");
        tmixed_records.push(SnRecord {
            sn: 3,
            protocols: "TrackerFactFull",
            success: true,
            gov_version: 2,
        });
        // Held viewpoint, failed evaluation: full error both sides.
        emit_fact_viewpoints_timed(
            api0,
            tmixed.clone(),
            json!({"ModOne": {"data": "xx"}}),
            BTreeSet::from(["agua".to_owned()])
        )
        .await
        .unwrap();
        tmixed_records.push(SnRecord {
            sn: 4,
            protocols: "TrackerFactFull",
            success: false,
            gov_version: 2,
        });
        // Unheld viewpoint, failed evaluation: opaque error.
        emit_fact_viewpoints_timed(
            api0,
            tmixed.clone(),
            json!({"ModOne": {"data": "xx"}}),
            BTreeSet::from(["basura".to_owned()])
        )
        .await
        .unwrap();
        let witness_events =
            get_events(api1, tmixed.clone(), 6, true).await.unwrap();
        let opaque_error = witness_events
            .iter()
            .find(|event| event.sn == 5)
            .expect("witness must hold sn 5");
        assert_tracker_fact_opaque(&opaque_error.event, &["basura"])
            .expect("unheld-viewpoint error must be opaque");
        tmixed_records.push(SnRecord {
            sn: 5,
            protocols: "TrackerFactFull",
            success: false,
            gov_version: 2,
        });
        for event in get_events(api0, tmixed.clone(), tmixed_records.len(), true)
            .await
            .unwrap()
        {
            let (protocols, success) = protocols_of(&event.event);
            let record = &tmixed_records[event.sn as usize];
            assert_eq!(record.sn, event.sn);
            assert_eq!(record.protocols, protocols, "tmixed sn {}", event.sn);
            assert_eq!(record.success, success, "tmixed sn {} success", event.sn);
        }
        tmixed_entry = Some(serde_json::json!({
            "name": "tracker_mixed",
            "kind": "tracker",
            "subject_id": tmixed.to_string(),
            "governance_id": gov.to_string(),
            "db": "node0",
            "witness_db": "node1",
            "sns": records_json(&tmixed_records),
        }));
    }

    // Tracker T3: failed transfer (outsider without membership
    // or creator role commits failed), then EOL.
    let t3_entry: Option<Value>;
    {
        let (t3, ..) =
            create_subject_timed(api0, gov.clone(), "Example", "")
                .await
                .unwrap();
        let mut t3_records = vec![SnRecord {
            sn: 0,
            protocols: "Create",
            success: true,
            gov_version: 2,
        }];
        let outsider = ave_common::identity::keys::Ed25519Signer::generate()
            .unwrap();
        let outsider_key =
            ave_common::identity::keys::KeyPair::Ed25519(outsider)
                .public_key();
        emit_transfer_timed(api0, t3.clone(), outsider_key).await.unwrap();
        t3_records.push(SnRecord {
            sn: 1,
            protocols: "Transfer",
            success: false,
            gov_version: 2,
        });
        emit_eol_timed(api0, t3.clone()).await.unwrap();
        t3_records.push(SnRecord {
            sn: 2,
            protocols: "EOL",
            success: true,
            gov_version: 2,
        });
        // Cross-check like the other subjects.
        for event in get_events(api0, t3.clone(), t3_records.len(), true)
            .await
            .unwrap()
        {
            let (protocols, success) = protocols_of(&event.event);
            let record = &t3_records[event.sn as usize];
            assert_eq!(record.sn, event.sn);
            assert_eq!(record.protocols, protocols, "t3 sn {}", event.sn);
            assert_eq!(record.success, success, "t3 sn {} success", event.sn);
        }
        t3_entry = Some(serde_json::json!({
            "name": "tracker_transfer_error_eol",
            "kind": "tracker",
            "subject_id": t3.to_string(),
            "governance_id": gov.to_string(),
            "db": "node0",
            "sns": records_json(&t3_records),
        }));
    }
    // Tracker T2: transfer, reject, EOL.
    let mut t2_entry: Option<Value> = None;
    if on(&config, "tracker_transfer_reject_eol") {
        let (t2, ..) =
            create_subject_timed(api0, gov.clone(), "Example", "")
                .await
                .unwrap();
        let mut t2_records = vec![SnRecord {
            sn: 0,
            protocols: "Create",
            success: true,
            gov_version: 2,
        }];
        emit_transfer_timed(api0, t2.clone(), key1.clone()).await.unwrap();
        t2_records.push(SnRecord {
            sn: 1,
            protocols: "Transfer",
            success: true,
            gov_version: 2,
        });
        emit_reject_timed(api1, t2.clone()).await.unwrap();
        t2_records.push(SnRecord {
            sn: 2,
            protocols: "Reject",
            success: true,
            gov_version: 2,
        });
        emit_eol_timed(api0, t2.clone()).await.unwrap();
        t2_records.push(SnRecord {
            sn: 3,
            protocols: "EOL",
            success: true,
            gov_version: 2,
        });
        t2_entry = Some(serde_json::json!({
            "name": "tracker_reject_eol",
            "kind": "tracker",
            "subject_id": t2.to_string(),
            "governance_id": gov.to_string(),
            "db": "node0",
            "sns": records_json(&t2_records),
        }));
    }

    // Second approver + manual rejection. From here on every
    // approval needs both votes: owner auto-agrees, node1 votes
    // by hand. Nothing approval-gated follows except this one.
    let json = json!({
        "roles": {"governance": {"add": {"approver": ["AveNode2"]}}},
    });
    emit_fact_timed(api0, gov.clone(), json).await.unwrap();
    let next_sn = gov_records.last().expect("gov ran").sn + 1;
    gov_records.push(SnRecord {
        sn: next_sn,
        protocols: "GovFact",
        success: true,
        gov_version: 2,
    });
    {
        let fake_key =
            ave_common::identity::keys::KeyPair::Ed25519(
                ave_common::identity::keys::Ed25519Signer::generate().unwrap(),
            )
            .public_key()
            .to_string();
        let json = json!({
            "members": {"add": [{"name": "RejectedMember", "key": fake_key}]},
        });
        let request_id =
            emit_fact_timed(api0, gov.clone(), json).await.unwrap();
        emit_approve(
            api1,
            gov.clone(),
            ave_common::bridge::request::ApprovalStateRes::Rejected,
            request_id,
            false,
        )
        .await
        .unwrap();
        let next_sn = gov_records.last().expect("gov ran").sn + 1;
        gov_records.push(SnRecord {
            sn: next_sn,
            protocols: "GovFact",
            success: false,
            gov_version: 3,
        });
        let state =
            get_subject(api0, gov.clone(), Some(next_sn), true).await.unwrap();
        assert!(
            !state.properties.to_string().contains("RejectedMember"),
            "rejected member must not apply"
        );
    }

    // Failed transfer (outsider without membership): commits
    // failed, ownership never moves, version frozen.
    {
        let outsider =
            ave_common::identity::keys::KeyPair::Ed25519(
                ave_common::identity::keys::Ed25519Signer::generate().unwrap(),
            )
            .public_key();
        emit_transfer_timed(api0, gov.clone(), outsider).await.unwrap();
        let next_sn = gov_records.last().expect("gov ran").sn + 1;
        gov_records.push(SnRecord {
            sn: next_sn,
            protocols: "Transfer",
            success: false,
            gov_version: 3,
        });
    }

    // Schema add with a rejecting second approver: real compile
    // (cache hit on the same bytes), successful evaluation,
    // rejected tally. Version frozen, schema absent.
    {
        let json = json!({
            "schemas": {"add": [{
                "id": "SecondSchema",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
        });
        let request_id =
            emit_fact_timed(api0, gov.clone(), json).await.unwrap();
        emit_approve(
            api1,
            gov.clone(),
            ave_common::bridge::request::ApprovalStateRes::Rejected,
            request_id,
            false,
        )
        .await
        .unwrap();
        let next_sn = gov_records.last().expect("gov ran").sn + 1;
        gov_records.push(SnRecord {
            sn: next_sn,
            protocols: "GovFact",
            success: false,
            gov_version: 3,
        });
        let state =
            get_subject(api0, gov.clone(), Some(next_sn), true).await.unwrap();
        assert!(
            !state.properties.to_string().contains("SecondSchema"),
            "rejected schema must not apply"
        );
    }

    // Governance handover endgame: transfer, confirm, EOL.
    // node1 drives its own steps; node0 keeps 0..9 (it stops
    // syncing past its last driven event), node1 carries the
    // tail, so the manifest reads each sn where it landed
    // (see gov_db).
    emit_transfer_timed(api0, gov.clone(), key1.clone()).await.unwrap();
    let next_sn = gov_records.last().expect("gov ran").sn + 1;
    gov_records.push(SnRecord {
        sn: next_sn,
        protocols: "Transfer",
        success: true,
        gov_version: 3,
    });
    // Barrier: the pending owner must exist on node1.
    let _ = get_subject(api1, gov.clone(), Some(next_sn), true)
        .await
        .unwrap();
    // NOTE: single pending slot — consumed once by the confirm
    // below. A committed-failed confirm (eval Error) is not
    // manufacturable live: invalid confirms abort at intake
    // ("no new owner pending") instead of committing, so the
    // shape lives in unit only. node0 stops syncing past its
    // last driven event; the tail below is read from node1.
    emit_confirm_timed(api1, gov.clone(), None).await.unwrap();
    let next_sn = gov_records.last().expect("gov ran").sn + 1;
    gov_records.push(SnRecord {
        sn: next_sn,
        protocols: "GovConfirm",
        success: true,
        gov_version: 4,
    });
    let _ = get_subject(api1, gov.clone(), Some(next_sn), true)
        .await
        .unwrap();
    emit_eol_timed(api1, gov.clone()).await.unwrap();
    let next_sn = gov_records.last().expect("gov ran").sn + 1;
    gov_records.push(SnRecord {
        sn: next_sn,
        protocols: "EOL",
        success: true,
        gov_version: 5,
    });
    let _ = get_subject(api1, gov.clone(), Some(next_sn), true)
        .await
        .unwrap();
    // Per-sn database: node0 holds its driven prefix, node1 the
    // handover tail it drove. (Manifest reads gov from node1,
    // which demonstrably holds every sn via the barriers above.)

    // Second governance for the reject path: the single pending
    // slot on gov1 is consumed by its confirm, so rejection gets
    // its own gov (transfer then reject, owner never moves).
    let gov2 = create_and_authorize_governance_timed(api0, vec![api1]).await;
    let mut gov2_records = vec![SnRecord {
        sn: 0,
        protocols: "Create",
        success: true,
        gov_version: 0,
    }];
    {
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": api1.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["AveNode2"]}}},
        });
        emit_fact_timed(api0, gov2.clone(), json).await.unwrap();
        gov2_records.push(SnRecord {
            sn: 1,
            protocols: "GovFact",
            success: true,
            gov_version: 0,
        });
    }
    emit_transfer_timed(api0, gov2.clone(), key1.clone()).await.unwrap();
    gov2_records.push(SnRecord {
        sn: 2,
        protocols: "Transfer",
        success: true,
        gov_version: 1,
    });
    let _ = get_subject(api1, gov2.clone(), Some(2), true)
        .await
        .unwrap();
    emit_reject_timed(api1, gov2.clone()).await.unwrap();
    gov2_records.push(SnRecord {
        sn: 3,
        protocols: "Reject",
        success: true,
        gov_version: 2,
    });
    let _ = get_subject(api1, gov2.clone(), Some(3), true)
        .await
        .unwrap();
    for event in get_events(api1, gov2.clone(), gov2_records.len(), true)
        .await
        .unwrap()
    {
        let (protocols, success) = protocols_of(&event.event);
        let record = &gov2_records[event.sn as usize];
        assert_eq!(record.sn, event.sn);
        assert_eq!(record.protocols, protocols, "gov2 sn {}", event.sn);
        assert_eq!(record.success, success, "gov2 sn {} success", event.sn);
    }

    // Third governance for the failed-confirm path: transfer,
    // failed confirm (wrong old-owner name, owner and pending
    // untouched), good confirm, EOL. Single pending slot per
    // gov, so each handover shape gets its own governance.
    let gov3 = create_and_authorize_governance_timed(api0, vec![api1]).await;
    let mut gov3_records = vec![SnRecord {
        sn: 0,
        protocols: "Create",
        success: true,
        gov_version: 0,
    }];
    {
        let charlie_key =
            ave_common::identity::keys::KeyPair::Ed25519(
                ave_common::identity::keys::Ed25519Signer::generate().unwrap(),
            )
            .public_key()
            .to_string();
        let json = json!({
            "members": {"add": [
                {"name": "AveNode2", "key": api1.public_key()},
                {"name": "Charlie", "key": charlie_key},
            ]},
            "roles": {"governance": {"add": {"witness": ["AveNode2"]}}},
        });
        emit_fact_timed(api0, gov3.clone(), json).await.unwrap();
        gov3_records.push(SnRecord {
            sn: 1,
            protocols: "GovFact",
            success: true,
            gov_version: 0,
        });
    }
    emit_transfer_timed(api0, gov3.clone(), key1.clone()).await.unwrap();
    gov3_records.push(SnRecord {
        sn: 2,
        protocols: "Transfer",
        success: true,
        gov_version: 1,
    });
    let _ = get_subject(api1, gov3.clone(), Some(2), true)
        .await
        .unwrap();
    // Failed confirm first: renaming the old owner to an
    // already-taken third member name fails evaluation (owner
    // stays, transfer stays pending). Then the good one, EOL.
    emit_confirm_timed(api1, gov3.clone(), Some("Charlie".to_owned()))
        .await
        .unwrap();
    gov3_records.push(SnRecord {
        sn: 3,
        protocols: "GovConfirm",
        success: false,
        gov_version: 2,
    });
    let _ = get_subject(api1, gov3.clone(), Some(3), true)
        .await
        .unwrap();
    emit_confirm_timed(api1, gov3.clone(), None).await.unwrap();
    gov3_records.push(SnRecord {
        sn: 4,
        protocols: "GovConfirm",
        success: true,
        gov_version: 2,
    });
    let _ = get_subject(api1, gov3.clone(), Some(4), true)
        .await
        .unwrap();
    emit_eol_timed(api1, gov3.clone()).await.unwrap();
    gov3_records.push(SnRecord {
        sn: 5,
        protocols: "EOL",
        success: true,
        gov_version: 3,
    });
    let _ = get_subject(api1, gov3.clone(), Some(5), true)
        .await
        .unwrap();
    for event in get_events(api1, gov3.clone(), gov3_records.len(), true)
        .await
        .unwrap()
    {
        let (protocols, success) = protocols_of(&event.event);
        let record = &gov3_records[event.sn as usize];
        assert_eq!(record.sn, event.sn);
        assert_eq!(record.protocols, protocols, "gov3 sn {}", event.sn);
        assert_eq!(record.success, success, "gov3 sn {} success", event.sn);
    }


    // Governance skip (gov5): the tracker below emits at v2,
    // then the governance advances through two oks and two
    // failures to v5 before the tracker emits again. The second
    // tracker fact must verify against v5 while its predecessor
    // still anchors v2.
    let mut gov_skip_entry: Option<Value> = None;
    let mut skip_entry: Option<Value> = None;
    if on(&config, "gov_skip") {
        let gov5 = create_and_authorize_governance_timed(api0, vec![api1]).await;
        let mut gov5_records = vec![record(0, "Create", true, 0)];
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": api1.public_key()}]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
            "roles": {
                "governance": {"add": {"witness": ["AveNode2"]}},
            },
        });
        emit_fact_timed(api0, gov5.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov5.clone(), Some(1), true).await.unwrap();
        gov5_records.push(record(1, "GovFact", true, 0));
        let json = json!({
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "AveNode2", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "AveNode2", "namespace": []}],
                },
            }]},
        });
        emit_fact_timed(api0, gov5.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov5.clone(), Some(2), true).await.unwrap();
        gov5_records.push(record(2, "GovFact", true, 1));

        let (tsk, ..) =
            create_subject_timed(api0, gov5.clone(), "Example", "")
                .await
                .unwrap();
        let mut tsk_records = vec![record(0, "Create", true, 2)];
        emit_fact_timed(api0, tsk.clone(), json!({"ModOne": {"data": 10}}))
            .await
            .unwrap();
        let _ = get_subject(api0, tsk.clone(), Some(1), true)
            .await
            .unwrap();
        tsk_records.push(record(1, "TrackerFactFull", true, 2));

        // Gov advances underneath: ok, failed compile, failed eval,
        // ok, ok. Tracker stays silent throughout.
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2,
            }]},
        });
        emit_fact_timed(api0, gov5.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov5.clone(), Some(3), true).await.unwrap();
        gov5_records.push(record(3, "GovFact", true, 2));
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "NotASchema",
                "new_initial_value": {"one": 1},
            }]},
        });
        emit_fact_timed(api0, gov5.clone(), json).await.unwrap();
        gov5_records.push(record(4, "GovFact", false, 3));
        let json = json!({
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
        });
        emit_fact_timed(api0, gov5.clone(), json).await.unwrap();
        gov5_records.push(record(5, "GovFact", false, 3));
        for name in ["Charlie", "Dave"] {
            let member_key =
                ave_common::identity::keys::KeyPair::Ed25519(
                    ave_common::identity::keys::Ed25519Signer::generate()
                        .unwrap(),
                )
                .public_key()
                .to_string();
            let json = json!({
                "members": {"add": [{"name": name, "key": member_key}]},
            });
            emit_fact_timed(api0, gov5.clone(), json).await.unwrap();
            let next_sn = gov5_records.last().expect("gov5 ran").sn + 1;
            // Anchor = resulting version so far = one per past success.
            let anchor = gov5_records
                .iter()
                .filter(|record| record.success && record.sn > 0)
                .count() as u64;
            let _ = get_subject(api0, gov5.clone(), Some(next_sn), true)
                .await
                .unwrap();
            gov5_records.push(record(next_sn, "GovFact", true, anchor));
        }
        // Tracker emits again: v2 -> v5 underneath (two oks and two
        // frozen failures in between), running contract V2 now.
        emit_fact_timed(api0, tsk.clone(), json!({"ModOne": {"data": 11}}))
            .await
            .unwrap();
        let _ = get_subject(api0, tsk.clone(), Some(2), true)
            .await
            .unwrap();
        tsk_records.push(record(2, "TrackerFactFull", true, 5));
        // Version churn on the proven compiler (this gov compiled
        // its V2 change cleanly): Second joins (new shape, default
        // pin), Third joins (same A source, default pin). Trackers
        // emit against v6 and v8, skipping v7.
        let json = json!({
            "schemas": {"add": [{
                "id": "Second",
                "contract": CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
                "viewpoints": ["agua"],
            }]},
        });
        emit_fact_timed(api0, gov5.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov5.clone(), Some(8), true).await.unwrap();
        gov5_records.push(record(8, "GovFact", true, 5));
        emit_fact_timed(api0, tsk.clone(), json!({"ModOne": {"data": 12}}))
            .await
            .unwrap();
        let _ = get_subject(api0, tsk.clone(), Some(3), true)
            .await
            .unwrap();
        tsk_records.push(record(3, "TrackerFactFull", true, 6));
        // V2 has no 50-guard on three: the same payload contract A
        // rejects commits fine under V2 (version discriminator).
        emit_fact_timed(
            api0,
            tsk.clone(),
            json!({"ModThree": {"data": 50}})
        )
        .await
        .unwrap();
        let state =
            get_subject(api0, tsk.clone(), Some(4), true).await.unwrap();
        assert_eq!(
            state.properties,
            json!({"one": 12, "two": 0, "three": 50}),
            "V2 must accept three = 50"
        );
        tsk_records.push(record(4, "TrackerFactFull", true, 6));
        let json = json!({
            "schemas": {"add": [{
                "id": "Third",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua"],
            }]},
        });
        emit_fact_timed(api0, gov5.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov5.clone(), Some(9), true).await.unwrap();
        gov5_records.push(record(9, "GovFact", true, 6));
        // Failed fact at the tip keeps state; recovery after.
        emit_fact_timed(api0, tsk.clone(), json!({"ModOne": {"data": "xx"}}))
            .await
            .unwrap();
        let state =
            get_subject(api0, tsk.clone(), Some(5), true).await.unwrap();
        assert_eq!(
            state.properties,
            json!({"one": 12, "two": 0, "three": 50}),
            "failed fact must not move properties"
        );
        tsk_records.push(record(5, "TrackerFactFull", false, 7));
        emit_fact_timed(api0, tsk.clone(), json!({"ModOne": {"data": 13}}))
            .await
            .unwrap();
        let _ = get_subject(api0, tsk.clone(), Some(6), true)
            .await
            .unwrap();
        tsk_records.push(record(6, "TrackerFactFull", true, 7));
        for event in
            get_events(api0, gov5.clone(), gov5_records.len(), true)
                .await
                .unwrap()
        {
            let (protocols, success) = protocols_of(&event.event);
            let record = &gov5_records[event.sn as usize];
            assert_eq!(record.sn, event.sn);
            assert_eq!(record.protocols, protocols, "gov5 sn {}", event.sn);
            assert_eq!(
                record.success, success,
                "gov5 sn {} success",
                event.sn
            );
        }
        for event in
            get_events(api0, tsk.clone(), tsk_records.len(), true).await.unwrap()
        {
            let (protocols, success) = protocols_of(&event.event);
            let record = &tsk_records[event.sn as usize];
            assert_eq!(record.sn, event.sn);
            assert_eq!(record.protocols, protocols, "tsk sn {}", event.sn);
            assert_eq!(
                record.success, success,
                "tsk sn {} success",
                event.sn
            );
        }
        gov_skip_entry = Some(serde_json::json!({
            "name": "gov_skip",
            "kind": "governance",
            "subject_id": gov5.to_string(),
            "governance_id": gov5.to_string(),
            "db": "node0",
            "sns": records_json(&gov5_records),
        }));
        skip_entry = Some(serde_json::json!({
            "name": "tracker_govskip",
            "kind": "tracker",
            "subject_id": tsk.to_string(),
            "governance_id": gov5.to_string(),
            "db": "node0",
            "sns": records_json(&tsk_records),
        }));
        eprintln!("SEED-PROGRESS govskip done");
    }

    // Contract churn on a fresh governance (gov7): change A->V2 as
    // third fact, chain back V2->A, Second joins, an invalid
    // contract fails clean, Third joins, member adds. The tracker
    // emits across every version, including one contract-logic
    // failure under A.
    let mut gov_churn_entry: Option<Value> = None;
    let mut churn_entry: Option<Value> = None;
    if on(&config, "gov_churn") {
        let gov7 = create_and_authorize_governance_timed(api0, vec![api1]).await;
        let mut gov7_records = vec![record(0, "Create", true, 0)];
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": api1.public_key()}]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
            "roles": {
                "governance": {"add": {"witness": ["AveNode2"]}},
            },
        });
        emit_fact_timed(api0, gov7.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov7.clone(), Some(1), true).await.unwrap();
        gov7_records.push(record(1, "GovFact", true, 0));
        let json = json!({
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "AveNode2", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "AveNode2", "namespace": []}],
                },
            }]},
        });
        emit_fact_timed(api0, gov7.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov7.clone(), Some(2), true).await.unwrap();
        gov7_records.push(record(2, "GovFact", true, 1));

        let (tch, ..) =
            create_subject_timed(api0, gov7.clone(), "Example", "")
                .await
                .unwrap();
        let mut tch_records = vec![record(0, "Create", true, 2)];
        emit_fact_timed(api0, tch.clone(), json!({"ModOne": {"data": 20}}))
            .await
            .unwrap();
        let _ = get_subject(api0, tch.clone(), Some(1), true)
            .await
            .unwrap();
        tch_records.push(record(1, "TrackerFactFull", true, 2));

        // Change Example A -> V2 as third fact.
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2,
            }]},
        });
        emit_fact_timed(api0, gov7.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov7.clone(), Some(3), true).await.unwrap();
        gov7_records.push(record(3, "GovFact", true, 2));
        emit_fact_timed(api0, tch.clone(), json!({"ModOne": {"data": 21}}))
            .await
            .unwrap();
        let _ = get_subject(api0, tch.clone(), Some(2), true)
            .await
            .unwrap();
        tch_records.push(record(2, "TrackerFactFull", true, 3));

        // Chain back V2 -> A.
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT,
            }]},
        });
        emit_fact_timed(api0, gov7.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov7.clone(), Some(4), true).await.unwrap();
        gov7_records.push(record(4, "GovFact", true, 3));

        // Second joins with a new shape.
        let json = json!({
            "schemas": {"add": [{
                "id": "Second",
                "contract": CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
                "viewpoints": ["agua"],
            }]},
        });
        emit_fact_timed(api0, gov7.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov7.clone(), Some(5), true).await.unwrap();
        gov7_records.push(record(5, "GovFact", true, 4));
        emit_fact_timed(api0, tch.clone(), json!({"ModOne": {"data": 22}}))
            .await
            .unwrap();
        let _ = get_subject(api0, tch.clone(), Some(3), true)
            .await
            .unwrap();
        tch_records.push(record(3, "TrackerFactFull", true, 5));

        // Contract-logic failure under A: three = 50 is rejected,
        // state does not move.
        emit_fact_timed(
            api0,
            tch.clone(),
            json!({"ModThree": {"data": 50}})
        )
        .await
        .unwrap();
        let state =
            get_subject(api0, tch.clone(), Some(4), true).await.unwrap();
        assert_eq!(
            state.properties,
            json!({"one": 22, "two": 0, "three": 0}),
            "failed fact must not move properties"
        );
        tch_records.push(record(4, "TrackerFactFull", false, 5));

        // Invalid contract: truncated base64 fails decoding, the
        // request aborts and leaves NO event (abort is not a
        // failed vote: no sn is consumed).
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "Example",
                "new_contract": INVALID_EXAMPLE_CONTRACT,
            }]},
        });
        emit_fact_timed(api0, gov7.clone(), json).await.unwrap();

        // Third joins with the A source, as sn6 (the aborted sn6
        // left no event behind).
        let json = json!({
            "schemas": {"add": [{
                "id": "Third",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua"],
            }]},
        });
        emit_fact_timed(api0, gov7.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov7.clone(), Some(6), true).await.unwrap();
        gov7_records.push(record(6, "GovFact", true, 5));
        for name in ["Charlie", "Dave"] {
            let member_key =
                ave_common::identity::keys::KeyPair::Ed25519(
                    ave_common::identity::keys::Ed25519Signer::generate()
                        .unwrap(),
                )
                .public_key()
                .to_string();
            let json = json!({
                "members": {"add": [{"name": name, "key": member_key}]},
            });
            emit_fact_timed(api0, gov7.clone(), json).await.unwrap();
            let next_sn = gov7_records.last().expect("gov7 ran").sn + 1;
            let anchor = gov7_records
                .iter()
                .filter(|record| record.success && record.sn > 0)
                .count() as u64;
            let _ = get_subject(api0, gov7.clone(), Some(next_sn), true)
                .await
                .unwrap();
            gov7_records.push(record(next_sn, "GovFact", true, anchor));
        }
        emit_fact_timed(api0, tch.clone(), json!({"ModOne": {"data": 23}}))
            .await
            .unwrap();
        let _ = get_subject(api0, tch.clone(), Some(5), true)
            .await
            .unwrap();
        tch_records.push(record(5, "TrackerFactFull", true, 8));
        for event in
            get_events(api0, gov7.clone(), gov7_records.len(), true)
                .await
                .unwrap()
        {
            let (protocols, success) = protocols_of(&event.event);
            let record = &gov7_records[event.sn as usize];
            assert_eq!(record.sn, event.sn);
            assert_eq!(record.protocols, protocols, "gov7 sn {}", event.sn);
            assert_eq!(
                record.success, success,
                "gov7 sn {} success",
                event.sn
            );
        }
        for event in
            get_events(api0, tch.clone(), tch_records.len(), true).await.unwrap()
        {
            let (protocols, success) = protocols_of(&event.event);
            let record = &tch_records[event.sn as usize];
            assert_eq!(record.sn, event.sn);
            assert_eq!(record.protocols, protocols, "tch sn {}", event.sn);
            assert_eq!(
                record.success, success,
                "tch sn {} success",
                event.sn
            );
        }
        gov_churn_entry = Some(serde_json::json!({
            "name": "gov_churn",
            "kind": "governance",
            "subject_id": gov7.to_string(),
            "governance_id": gov7.to_string(),
            "db": "node0",
            "sns": records_json(&gov7_records),
        }));
        churn_entry = Some(serde_json::json!({
            "name": "tracker_churn",
            "kind": "tracker",
            "subject_id": tch.to_string(),
            "governance_id": gov7.to_string(),
            "db": "node0",
            "sns": records_json(&tch_records),
        }));
        eprintln!("SEED-PROGRESS govchurn done");
    }

    // Mixed visibility with a handover tail (gov6): full facts,
    // then transfer -> confirm while full, then the opaque fact
    // last. Handover ops need a locally full ledger (node gate),
    // so nothing emitting can follow an opaque fact nobody holds;
    // the witness still verifies the handover 1:1 past it.
    let mut postopaque_entry: Option<Value> = None;
    let mut gov6_entry: Option<Value> = None;
    if on(&config, "tracker_postopaque_tx") {
        let gov6 = create_and_authorize_governance_timed(api0, vec![api1, &node2.api]).await;
        let mut gov6_records = vec![record(0, "Create", true, 0)];
        let json = json!({
            "members": {"add": [
                {"name": "AveNode2", "key": api1.public_key()},
                {"name": "AveNode3", "key": node2.api.public_key()},
            ]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
            "roles": {
                "governance": {"add": {"witness": ["AveNode2", "AveNode3"]}},
            },
        });
        emit_fact_timed(api0, gov6.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov6.clone(), Some(1), true).await.unwrap();
        gov6_records.push(record(1, "GovFact", true, 0));
        let json = json!({
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity",
                         "witnesses": [
                            {"name": "AveNode2", "viewpoints": ["agua"]},
                            {"name": "AveNode3", "viewpoints": ["basura"]},
                        ]},
                        {"name": "AveNode2", "namespace": [], "quantity": "infinity"},
                        {"name": "AveNode3", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [
                        {"name": "Owner", "namespace": []},
                        {"name": "AveNode2", "namespace": []},
                        {"name": "AveNode3", "namespace": []},
                    ],
                    "witness": [
                        {"name": "AveNode2", "namespace": []},
                        {"name": "AveNode3", "namespace": []},
                    ],
                },
            }]},
        });
        emit_fact_timed(api0, gov6.clone(), json).await.unwrap();
        let _ =
            get_subject(api0, gov6.clone(), Some(2), true).await.unwrap();
        gov6_records.push(record(2, "GovFact", true, 1));

        let (tpt, ..) =
            create_subject_timed(api0, gov6.clone(), "Example", "")
                .await
                .unwrap();
        let mut tpt_records = vec![record(0, "Create", true, 2)];
        emit_fact_timed(api0, tpt.clone(), json!({"ModOne": {"data": 1}}))
            .await
            .unwrap();
        let _ = get_subject(api0, tpt.clone(), Some(1), true)
            .await
            .unwrap();
        tpt_records.push(record(1, "TrackerFactFull", true, 2));
        api1
            .authorize_governance(
                tpt.clone(),
                AuthWitness::One(PublicKey::from_str(api0.public_key()).unwrap()),
            )
            .await
            .unwrap();
        api1.update_subject(tpt.clone()).await.unwrap();
        // Second follower (member + creator + witness, holding
        // basura): mirrors unheld facts opaque, held ones full.
        node2
            .api
            .authorize_governance(
                tpt.clone(),
                AuthWitness::One(PublicKey::from_str(api0.public_key()).unwrap()),
            )
            .await
            .unwrap();
        node2.api.update_subject(tpt.clone()).await.unwrap();
        // Second follower (member + creator + witness, holding
        // basura): creation-authorized like node1 on legacy govs,
        // so it syncs on its own; no explicit update needed (it
        // would collide with the running sync).
        node2
            .api
            .authorize_governance(
                tpt.clone(),
                AuthWitness::One(PublicKey::from_str(api0.public_key()).unwrap()),
            )
            .await
            .unwrap();
        emit_fact_viewpoints_timed(
            api0,
            tpt.clone(),
            json!({"ModOne": {"data": 2}}),
            BTreeSet::from(["agua".to_owned()])
        )
        .await
        .unwrap();
        let _ = get_subject(api0, tpt.clone(), Some(2), true)
            .await
            .unwrap();
        tpt_records.push(record(2, "TrackerFactFull", true, 2));
        // Handover while locally full (must precede any opaque
        // fact: handover ops require a full ledger).
        emit_transfer_timed(api0, tpt.clone(), key1.clone()).await.unwrap();
        tpt_records.push(record(3, "Transfer", true, 2));
        let _ = get_subject(api1, tpt.clone(), Some(3), true)
            .await
            .unwrap();
        emit_confirm_timed(api1, tpt.clone(), None).await.unwrap();
        tpt_records.push(record(4, "TrackerConfirm", true, 2));
        let _ = get_subject(api1, tpt.clone(), Some(4), true)
            .await
            .unwrap();
        // Unheld viewpoint, emitted by the new owner (has
        // creator role): full bytes stay with the emitter (like
        // the legacy opaque subject). Followers without the
        // viewpoint mirror it opaque.
        emit_fact_viewpoints_timed(
            api1,
            tpt.clone(),
            json!({"ModOne": {"data": 3}}),
            BTreeSet::from(["basura".to_owned()])
        )
        .await
        .unwrap();
        let emitter_events =
            get_events(api1, tpt.clone(), 6, true).await.unwrap();
        let emitter_fact = emitter_events
            .iter()
            .find(|event| event.sn == 5)
            .expect("emitter must hold sn 5");
        assert!(
            matches!(
                emitter_fact.event,
                RequestEventDB::TrackerFactFull { .. }
            ),
            "emitter keeps the clear fact"
        );
        let _ = get_subject(&node2.api, tpt.clone(), Some(5), true)
            .await
            .unwrap();
        let mirror_events =
            get_events(&node2.api, tpt.clone(), 6, true).await.unwrap();
        let mirror_agua = mirror_events
            .iter()
            .find(|event| event.sn == 2)
            .expect("mirror must hold sn 2");
        assert_tracker_fact_opaque(&mirror_agua.event, &["agua"])
            .expect("unheld agua fact mirrors opaque");
        let mirror_basura = mirror_events
            .iter()
            .find(|event| event.sn == 5)
            .expect("mirror must hold sn 5");
        assert!(
            matches!(
                mirror_basura.event,
                RequestEventDB::TrackerFactFull { .. }
            ),
            "held basura fact mirrors full"
        );
        tpt_records.push(record(5, "TrackerFactFull", true, 2));
        // Second handover, to the degraded mirror: the owner is
        // full and emits fine.
        let node2_key = PublicKey::from_str(node2.api.public_key()).unwrap();
        emit_transfer_timed(api1, tpt.clone(), node2_key.clone())
            .await
            .unwrap();
        tpt_records.push(record(6, "Transfer", true, 2));
        let _ = get_subject(api1, tpt.clone(), Some(6), true)
            .await
            .unwrap();
        let _ = get_subject(&node2.api, tpt.clone(), Some(6), true)
            .await
            .unwrap();
        // The degraded mirror can not accept yet: node pattern is
        // delete the local ledger, fetch the updated copy, then
        // accept (confirm). Safe-mode restart dance like the node
        // safe_mode suite (keys + local db preserved, fresh
        // ext/contracts dirs held till shutdown).
        let node2_keys = node2.keys.clone();
        let node2_db = db2.clone();
        node2.token.cancel();
        join_all(node2.handler.iter_mut()).await;
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (mut safe_node2, mut safe_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address: format!("/memory/{port}"),
            peers: vec![],
            always_accept: true,
            local_db: Some(node2_db.clone()),
            keys: Some(node2_keys.clone()),
            safe_mode: true,
            ..Default::default()
        })
        .await;
        budgeted("node2 safe boot", node_running(&safe_node2.api))
            .await
            .unwrap();
        budgeted(
            "node2 delete tpt",
            safe_node2.api.delete_subject(tpt.clone()),
        )
        .await
        .unwrap();
        seed_held_dirs.append(&mut safe_dirs);
        safe_node2.token.cancel();
        join_all(safe_node2.handler.iter_mut()).await;
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (new_node2, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![peer_of(&node0, &listen0)],
            always_accept: true,
            local_db: Some(node2_db.clone()),
            keys: Some(node2_keys.clone()),
            safe_mode: false,
            ..Default::default()
        })
        .await;
        seed_held_dirs.append(&mut new_dirs);
        budgeted("node2 reboot", node_running(&new_node2.api))
            .await
            .unwrap();
        node2 = new_node2;
        // Re-authorize after the delete (the mapping went away
        // with the rows), then fetch the updated copy.
        node2
            .api
            .authorize_governance(
                tpt.clone(),
                AuthWitness::One(PublicKey::from_str(api0.public_key()).unwrap()),
            )
            .await
            .unwrap();
        budgeted(
            "node2 refetch tpt",
            node2.api.update_subject(tpt.clone()),
        )
        .await
        .unwrap();
        // Catch-up after reboot needs peer discovery first: retry
        // the barrier (fresh 30s budget each round) instead of
        // failing on the first quiet window.
        for _ in 0..10 {
            match get_subject(&node2.api, tpt.clone(), Some(6), true).await {
                Ok(_) => break,
                Err(_) => {
                    budgeted(
                        "node2 refetch retry",
                        node2.api.update_subject(tpt.clone()),
                    )
                    .await
                    .unwrap();
                }
            }
        }
        let _ = get_subject(&node2.api, tpt.clone(), Some(6), true)
            .await
            .unwrap();
        emit_confirm_timed(&node2.api, tpt.clone(), None).await.unwrap();
        tpt_records.push(record(7, "TrackerConfirm", true, 2));
        let _ = get_subject(&node2.api, tpt.clone(), Some(7), true)
            .await
            .unwrap();
        emit_eol_timed(&node2.api, tpt.clone()).await.unwrap();
        tpt_records.push(record(8, "EOL", true, 2));
        let _ = get_subject(&node2.api, tpt.clone(), Some(8), true)
            .await
            .unwrap();
        for event in
            get_events(api0, gov6.clone(), gov6_records.len(), true)
                .await
                .unwrap()
        {
            let (protocols, success) = protocols_of(&event.event);
            let record = &gov6_records[event.sn as usize];
            assert_eq!(record.sn, event.sn);
            assert_eq!(record.protocols, protocols, "gov6 sn {}", event.sn);
            assert_eq!(
                record.success, success,
                "gov6 sn {} success",
                event.sn
            );
        }
        for event in
            get_events(api1, tpt.clone(), tpt_records.len(), true).await.unwrap()
        {
            let (protocols, success) = protocols_of(&event.event);
            let record = &tpt_records[event.sn as usize];
            assert_eq!(record.sn, event.sn);
            assert_eq!(record.protocols, protocols, "tpt sn {}", event.sn);
            assert_eq!(
                record.success, success,
                "tpt sn {} success",
                event.sn
            );
        }
        postopaque_entry = Some(serde_json::json!({
            "name": "tracker_postopaque_tx",
            "kind": "tracker",
            "subject_id": tpt.to_string(),
            "governance_id": gov6.to_string(),
            "db": "node2",
            "full_db": "node1",
            "sns": records_json(&tpt_records),
        }));
        gov6_entry = Some(serde_json::json!({
            "name": "gov_opaque_tail",
            "kind": "governance",
            "subject_id": gov6.to_string(),
            "governance_id": gov6.to_string(),
            "db": "node0",
            "sns": records_json(&gov6_records),
        }));
    }

    // Cross-check the recorded matrix against the node API before
    // writing the manifest: a lying manifest is worse than none.
    // Governance reads from node1, the only copy holding the
    // handover tail; trackers read from node0.
    eprintln!("SEED-PROGRESS legacy matrix done");
    for event in get_events(api1, gov.clone(), gov_records.len(), true)
        .await
        .unwrap()
    {
        let (protocols, success) = protocols_of(&event.event);
        let record = &gov_records[event.sn as usize];
        assert_eq!(record.sn, event.sn);
        assert_eq!(record.protocols, protocols, "gov sn {}", event.sn);
        assert_eq!(record.success, success, "gov sn {} success", event.sn);
    }
    for event in get_events(api0, t1.clone(), t1_records.len(), true)
        .await
        .unwrap()
    {
        let (protocols, success) = protocols_of(&event.event);
        let record = &t1_records[event.sn as usize];
        assert_eq!(record.sn, event.sn);
        assert_eq!(record.protocols, protocols, "t1 sn {}", event.sn);
        assert_eq!(record.success, success, "t1 sn {} success", event.sn);
    }

    shutdown(vec![node0, node1, node2]).await;
    for (name, db) in [("node0", &db0), ("node1", &db1), ("node2", &db2)] {
        assert!(
            db.join("database.db").exists(),
            "{name} internal db missing at {}",
            db.display()
        );
    }

    let mut subjects = vec![
        serde_json::json!({
            "name": "gov",
            "kind": "governance",
            "subject_id": gov.to_string(),
            "governance_id": gov.to_string(),
            "db": "node1",
            "sns": records_json(&gov_records),
        }),
        serde_json::json!({
            "name": "gov_reject",
            "kind": "governance",
            "subject_id": gov2.to_string(),
            "governance_id": gov2.to_string(),
            "db": "node1",
            "sns": records_json(&gov2_records),
        }),
        serde_json::json!({
            "name": "tracker_full",
            "kind": "tracker",
            "subject_id": t1.to_string(),
            "governance_id": gov.to_string(),
            "db": "node0",
            "sns": records_json(&t1_records),
        }),
    ];
    if let Some(entry) = t2_entry {
        subjects.push(entry);
    }
    if let Some(entry) = t3_entry {
        subjects.push(entry);
    }
    if let Some(entry) = topaque_entry {
        subjects.push(entry);
    }
    if let Some(entry) = tmixed_entry {
        subjects.push(entry);
    }
    if let Some(entry) = gov_skip_entry {
        subjects.push(entry);
    }
    if let Some(entry) = gov_churn_entry {
        subjects.push(entry);
    }
    if let Some(entry) = churn_entry {
        subjects.push(entry);
    }
    if let Some(entry) = skip_entry {
        subjects.push(entry);
    }
    if let Some(entry) = gov6_entry {
        subjects.push(entry);
    }
    if let Some(entry) = postopaque_entry {
        subjects.push(entry);
    }
    subjects.push(serde_json::json!({
        "name": "gov_confirm_error",
        "kind": "governance",
        "subject_id": gov3.to_string(),
        "governance_id": gov3.to_string(),
        "db": "node1",
        "sns": records_json(&gov3_records),
    }));
    let manifest = serde_json::json!({
        "password": PASSWORD,
        "nodes": [
            {"name": "node0", "db": "node0"},
            {"name": "node1", "db": "node1"},
            {"name": "node2", "db": "node2"},
        ],
        "subjects": subjects,
    });
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    println!("seed manifest written for gov {} t1 {}", gov, t1);
}
