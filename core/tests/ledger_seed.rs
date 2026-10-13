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
    identity::PublicKey,
};
use ave_core::auth::AuthWitness;
use ave_network::{NodeType, RoutingNode};
use common::{
    EXAMPLE_CONTRACT, PORT_COUNTER, assert_tracker_fact_opaque,
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
    node_running(&node.api).await.unwrap();
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
    // must survive the test process).
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
    let (node2, db2) = boot_node(
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
    let gov = create_and_authorize_governance(api0, vec![api1, &node2.api]).await;
    let mut gov_records = vec![SnRecord {
        sn: 0,
        protocols: "Create",
        success: true,
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
        emit_fact(api0, gov.clone(), json, true).await.unwrap();
        let _ = get_subject(api0, gov.clone(), Some(1), true).await.unwrap();
        gov_records.push(SnRecord {
            sn: 1,
            protocols: "GovFact",
            success: true,
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
        emit_fact(api0, gov.clone(), json, true).await.unwrap();
        let _ = get_subject(api1, gov.clone(), Some(2), true).await.unwrap();
        gov_records.push(SnRecord {
            sn: 2,
            protocols: "GovFact",
            success: true,
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
        emit_fact(api0, gov.clone(), json, true).await.unwrap();
        let next_sn = gov_records.last().expect("gov ran").sn + 1;
        gov_records.push(SnRecord {
            sn: next_sn,
            protocols: "GovFact",
            success: false,
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
        emit_fact(api0, gov.clone(), json, true).await.unwrap();
        let next_sn = gov_records.last().expect("gov ran").sn + 1;
        gov_records.push(SnRecord {
            sn: next_sn,
            protocols: "GovFact",
            success: false,
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
    let (t1, ..) =
        create_subject(api0, gov.clone(), "Example", "", true).await.unwrap();
    let mut t1_records = vec![SnRecord {
        sn: 0,
        protocols: "Create",
        success: true,
    }];
    if on(&config, "tracker_facts") {
        emit_fact(api0, t1.clone(), json!({"ModOne": {"data": 1}}), true)
            .await
            .unwrap();
        t1_records.push(SnRecord {
            sn: 1,
            protocols: "TrackerFactFull",
            success: true,
        });

        // Contract rejects the mistyped payload: commits failed,
        // properties untouched.
        emit_fact(api0, t1.clone(), json!({"ModOne": {"data": "xx"}}), true)
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
        });
    }

    if on(&config, "tracker_transfer_confirm") {
        emit_transfer(api0, t1.clone(), key1.clone(), true).await.unwrap();
        let next_sn = t1_records.last().expect("facts ran").sn + 1;
        t1_records.push(SnRecord {
            sn: next_sn,
            protocols: "Transfer",
            success: true,
        });
        emit_confirm(api1, t1.clone(), None, true).await.unwrap();
        let next_sn = t1_records.last().expect("transfer ran").sn + 1;
        t1_records.push(SnRecord {
            sn: next_sn,
            protocols: "TrackerConfirm",
            success: true,
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
            create_subject(api0, gov.clone(), "Example", "", true)
                .await
                .unwrap();
        let mut topaque_records = vec![
            SnRecord {
                sn: 0,
                protocols: "Create",
                success: true,
            },
            SnRecord {
                sn: 1,
                protocols: "TrackerFactFull",
                success: true,
            },
        ];
        emit_fact(api0, topaque.clone(), json!({"ModOne": {"data": 1}}), true)
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
        emit_fact_viewpoints(
            api0,
            topaque.clone(),
            json!({"ModOne": {"data": 2}}),
            BTreeSet::from(["basura".to_owned()]),
            true,
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
        });
        // Failed evaluation under a viewpoint the witness does
        // not hold: full error on the originator, opaque error on
        // the witness.
        emit_fact_viewpoints(
            api0,
            topaque.clone(),
            json!({"ModOne": {"data": "xx"}}),
            BTreeSet::from(["basura".to_owned()]),
            true,
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
        });
        topaque_entry = Some(serde_json::json!({
            "name": "tracker_opaque",
            "kind": "tracker",
            "subject_id": topaque.to_string(),
            "governance_id": gov.to_string(),
            "db": "node0",
            "witness_db": "node1",
            "witness_opaque_sn": 2,
            "sns": topaque_records.iter().map(|record| serde_json::json!({
                "sn": record.sn,
                "protocols": record.protocols,
                "success": record.success,
            })).collect::<Vec<_>>(),
        }));
    }

    // Tracker Tmixed: half visible, half opaque on the witness.
    // node1 holds viewpoint "agua" (creator witness grant) but
    // not "basura": agua facts arrive full, basura facts arrive
    // opaque. Ok + error on each side, all on one chain.
    let mut tmixed_entry: Option<Value> = None;
    if on(&config, "tracker_mixed") {
        let (tmixed, ..) =
            create_subject(api0, gov.clone(), "Example", "", true)
                .await
                .unwrap();
        let mut tmixed_records = vec![
            SnRecord {
                sn: 0,
                protocols: "Create",
                success: true,
            },
            SnRecord {
                sn: 1,
                protocols: "TrackerFactFull",
                success: true,
            },
        ];
        emit_fact(api0, tmixed.clone(), json!({"ModOne": {"data": 1}}), true)
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
        emit_fact_viewpoints(
            api0,
            tmixed.clone(),
            json!({"ModOne": {"data": 2}}),
            BTreeSet::from(["agua".to_owned()]),
            true,
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
        });
        // Unheld viewpoint: opaque on the witness.
        emit_fact_viewpoints(
            api0,
            tmixed.clone(),
            json!({"ModOne": {"data": 3}}),
            BTreeSet::from(["basura".to_owned()]),
            true,
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
        });
        // Held viewpoint, failed evaluation: full error both sides.
        emit_fact_viewpoints(
            api0,
            tmixed.clone(),
            json!({"ModOne": {"data": "xx"}}),
            BTreeSet::from(["agua".to_owned()]),
            true,
        )
        .await
        .unwrap();
        tmixed_records.push(SnRecord {
            sn: 4,
            protocols: "TrackerFactFull",
            success: false,
        });
        // Unheld viewpoint, failed evaluation: opaque error.
        emit_fact_viewpoints(
            api0,
            tmixed.clone(),
            json!({"ModOne": {"data": "xx"}}),
            BTreeSet::from(["basura".to_owned()]),
            true,
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
            "sns": tmixed_records.iter().map(|record| serde_json::json!({
                "sn": record.sn,
                "protocols": record.protocols,
                "success": record.success,
            })).collect::<Vec<_>>(),
        }));
    }

    // Tracker T3: failed transfer (outsider without membership
    // or creator role commits failed), then EOL.
    let t3_entry: Option<Value>;
    {
        let (t3, ..) =
            create_subject(api0, gov.clone(), "Example", "", true)
                .await
                .unwrap();
        let mut t3_records = vec![SnRecord {
            sn: 0,
            protocols: "Create",
            success: true,
        }];
        let outsider = ave_common::identity::keys::Ed25519Signer::generate()
            .unwrap();
        let outsider_key =
            ave_common::identity::keys::KeyPair::Ed25519(outsider)
                .public_key();
        emit_transfer(api0, t3.clone(), outsider_key, true).await.unwrap();
        t3_records.push(SnRecord {
            sn: 1,
            protocols: "Transfer",
            success: false,
        });
        emit_eol(api0, t3.clone(), true).await.unwrap();
        t3_records.push(SnRecord {
            sn: 2,
            protocols: "EOL",
            success: true,
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
            "sns": t3_records.iter().map(|record| serde_json::json!({
                "sn": record.sn,
                "protocols": record.protocols,
                "success": record.success,
            })).collect::<Vec<_>>(),
        }));
    }
    // Tracker T2: transfer, reject, EOL.
    let mut t2_entry: Option<Value> = None;
    if on(&config, "tracker_transfer_reject_eol") {
        let (t2, ..) =
            create_subject(api0, gov.clone(), "Example", "", true)
                .await
                .unwrap();
        let mut t2_records = vec![SnRecord {
            sn: 0,
            protocols: "Create",
            success: true,
        }];
        emit_transfer(api0, t2.clone(), key1.clone(), true).await.unwrap();
        t2_records.push(SnRecord {
            sn: 1,
            protocols: "Transfer",
            success: true,
        });
        emit_reject(api1, t2.clone(), true).await.unwrap();
        t2_records.push(SnRecord {
            sn: 2,
            protocols: "Reject",
            success: true,
        });
        emit_eol(api0, t2.clone(), true).await.unwrap();
        t2_records.push(SnRecord {
            sn: 3,
            protocols: "EOL",
            success: true,
        });
        t2_entry = Some(serde_json::json!({
            "name": "tracker_reject_eol",
            "kind": "tracker",
            "subject_id": t2.to_string(),
            "governance_id": gov.to_string(),
            "db": "node0",
            "sns": t2_records.iter().map(|record| serde_json::json!({
                "sn": record.sn,
                "protocols": record.protocols,
                "success": record.success,
            })).collect::<Vec<_>>(),
        }));
    }

    // Second approver + manual rejection. From here on every
    // approval needs both votes: owner auto-agrees, node1 votes
    // by hand. Nothing approval-gated follows except this one.
    let json = json!({
        "roles": {"governance": {"add": {"approver": ["AveNode2"]}}},
    });
    emit_fact(api0, gov.clone(), json, true).await.unwrap();
    let next_sn = gov_records.last().expect("gov ran").sn + 1;
    gov_records.push(SnRecord {
        sn: next_sn,
        protocols: "GovFact",
        success: true,
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
            emit_fact(api0, gov.clone(), json, true).await.unwrap();
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
        emit_transfer(api0, gov.clone(), outsider, true).await.unwrap();
        let next_sn = gov_records.last().expect("gov ran").sn + 1;
        gov_records.push(SnRecord {
            sn: next_sn,
            protocols: "Transfer",
            success: false,
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
            emit_fact(api0, gov.clone(), json, true).await.unwrap();
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
    emit_transfer(api0, gov.clone(), key1.clone(), true).await.unwrap();
    let next_sn = gov_records.last().expect("gov ran").sn + 1;
    gov_records.push(SnRecord {
        sn: next_sn,
        protocols: "Transfer",
        success: true,
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
    emit_confirm(api1, gov.clone(), None, true).await.unwrap();
    let next_sn = gov_records.last().expect("gov ran").sn + 1;
    gov_records.push(SnRecord {
        sn: next_sn,
        protocols: "GovConfirm",
        success: true,
    });
    let _ = get_subject(api1, gov.clone(), Some(next_sn), true)
        .await
        .unwrap();
    emit_eol(api1, gov.clone(), true).await.unwrap();
    let next_sn = gov_records.last().expect("gov ran").sn + 1;
    gov_records.push(SnRecord {
        sn: next_sn,
        protocols: "EOL",
        success: true,
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
    let gov2 = create_and_authorize_governance(api0, vec![api1]).await;
    let mut gov2_records = vec![SnRecord {
        sn: 0,
        protocols: "Create",
        success: true,
    }];
    {
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": api1.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["AveNode2"]}}},
        });
        emit_fact(api0, gov2.clone(), json, true).await.unwrap();
        gov2_records.push(SnRecord {
            sn: 1,
            protocols: "GovFact",
            success: true,
        });
    }
    emit_transfer(api0, gov2.clone(), key1.clone(), true).await.unwrap();
    gov2_records.push(SnRecord {
        sn: 2,
        protocols: "Transfer",
        success: true,
    });
    let _ = get_subject(api1, gov2.clone(), Some(2), true)
        .await
        .unwrap();
    emit_reject(api1, gov2.clone(), true).await.unwrap();
    gov2_records.push(SnRecord {
        sn: 3,
        protocols: "Reject",
        success: true,
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
    let gov3 = create_and_authorize_governance(api0, vec![api1]).await;
    let mut gov3_records = vec![SnRecord {
        sn: 0,
        protocols: "Create",
        success: true,
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
        emit_fact(api0, gov3.clone(), json, true).await.unwrap();
        gov3_records.push(SnRecord {
            sn: 1,
            protocols: "GovFact",
            success: true,
        });
    }
    emit_transfer(api0, gov3.clone(), key1.clone(), true).await.unwrap();
    gov3_records.push(SnRecord {
        sn: 2,
        protocols: "Transfer",
        success: true,
    });
    let _ = get_subject(api1, gov3.clone(), Some(2), true)
        .await
        .unwrap();
    // Failed confirm first: renaming the old owner to an
    // already-taken third member name fails evaluation (owner
    // stays, transfer stays pending). Then the good one, EOL.
    emit_confirm(api1, gov3.clone(), Some("Charlie".to_owned()), true)
        .await
        .unwrap();
    gov3_records.push(SnRecord {
        sn: 3,
        protocols: "GovConfirm",
        success: false,
    });
    let _ = get_subject(api1, gov3.clone(), Some(3), true)
        .await
        .unwrap();
    emit_confirm(api1, gov3.clone(), None, true).await.unwrap();
    gov3_records.push(SnRecord {
        sn: 4,
        protocols: "GovConfirm",
        success: true,
    });
    let _ = get_subject(api1, gov3.clone(), Some(4), true)
        .await
        .unwrap();
    emit_eol(api1, gov3.clone(), true).await.unwrap();
    gov3_records.push(SnRecord {
        sn: 5,
        protocols: "EOL",
        success: true,
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

    // Cross-check the recorded matrix against the node API before
    // writing the manifest: a lying manifest is worse than none.
    // Governance reads from node1, the only copy holding the
    // handover tail; trackers read from node0.
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
            "sns": gov_records.iter().map(|record| serde_json::json!({
                "sn": record.sn,
                "protocols": record.protocols,
                "success": record.success,
            })).collect::<Vec<_>>(),
        }),
        serde_json::json!({
            "name": "gov_reject",
            "kind": "governance",
            "subject_id": gov2.to_string(),
            "governance_id": gov2.to_string(),
            "db": "node1",
            "sns": gov2_records.iter().map(|record| serde_json::json!({
                "sn": record.sn,
                "protocols": record.protocols,
                "success": record.success,
            })).collect::<Vec<_>>(),
        }),
        serde_json::json!({
            "name": "tracker_full",
            "kind": "tracker",
            "subject_id": t1.to_string(),
            "governance_id": gov.to_string(),
            "db": "node0",
            "sns": t1_records.iter().map(|record| serde_json::json!({
                "sn": record.sn,
                "protocols": record.protocols,
                "success": record.success,
            })).collect::<Vec<_>>(),
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
    subjects.push(serde_json::json!({
        "name": "gov_confirm_error",
        "kind": "governance",
        "subject_id": gov3.to_string(),
        "governance_id": gov3.to_string(),
        "db": "node1",
        "sns": gov3_records.iter().map(|record| serde_json::json!({
            "sn": record.sn,
            "protocols": record.protocols,
            "success": record.success,
        })).collect::<Vec<_>>(),
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
