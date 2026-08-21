use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    str::FromStr,
    sync::atomic::Ordering,
    time::Duration,
};

mod common;

use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    bridge::{
        request::{ApprovalStateRes, SinkEventsQuery},
        response::{EvalResDB, RequestEventDB},
    },
    identity::{
        DigestIdentifier, PublicKey,
        keys::{Ed25519Signer, KeyPair},
    },
    response::RequestState,
    sink::{DataToSink, DataToSinkEvent},
};
use ave_core::auth::AuthWitness;
use ave_core::config::CompilerNodeConfig;
use ave_core::governance::data::GovernanceData;
use ave_core::governance::model::{
    CreatorWitness, PolicyGov, PolicySchema, Quorum, RoleCreator,
    RoleGovIssuer, RolesGov, RolesSchema, RolesTrackerSchemas, Schema,
};

use ave_network::{NodeType, RoutingNode};
use common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig,
    create_and_authorize_governance, create_nodes_and_connections,
    create_subject, emit_approve, emit_confirm, emit_eol, emit_fact,
    emit_reject, emit_transfer, get_events, get_subject,
};
use futures::future::join_all;
use serde_json::{Value, from_value, json};
use test_log::test;

use crate::common::{
    PORT_COUNTER, create_node, get_abort_request, node_running,
    try_create_node, wait_request_state,
};

const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";
const INVALID_EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXp";
const FUEL_EXHAUSTING_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIGxldCBtdXQgYnVybjogdTY0ID0gZGF0YSBhcyB1NjQ7CiAgICAgICAgbG9vcCB7CiAgICAgICAgICBidXJuID0gYnVybi53cmFwcGluZ19tdWwoMzEpLndyYXBwaW5nX2FkZCg3KTsKICAgICAgICAgIHN0YXRlLm9uZSA9IChidXJuICUgMTAwMCkgYXMgdTMyOwogICAgICAgIH0KICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVHdvIHsgZGF0YSB9ID0+IHsKICAgICAgICBzdGF0ZS50d28gPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RUaHJlZSB7IGRhdGEgfSA9PiB7CiAgICAgICAgaWYgZGF0YSA9PSA1MCB7CiAgICAgICAgICBjb250cmFjdF9yZXN1bHQuZXJyb3IgPSAiQ2FuIG5vdCBjaGFuZ2UgdGhyZWUgdmFsdWUsIDUwIGlzIGEgaW52YWxpZCB2YWx1ZSIudG9fb3duZWQoKTsKICAgICAgICAgIHJldHVybgogICAgICAgIH0KICAgICAgICAKICAgICAgICBzdGF0ZS50aHJlZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZEFsbCB7IG9uZSwgdHdvLCB0aHJlZSB9ID0+IHsKICAgICAgICBzdGF0ZS5vbmUgPSBvbmU7CiAgICAgICAgc3RhdGUudHdvID0gdHdvOwogICAgICAgIHN0YXRlLnRocmVlID0gdGhyZWU7CiAgICAgIH0KICB9CiAgY29udHJhY3RfcmVzdWx0LnN1Y2Nlc3MgPSB0cnVlOwp9";
const CHANGED_SCHEMA_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgZGF0YTogU3RyaW5nCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0KZW51bSBTdGF0ZUV2ZW50IHsKICBDaGFuZ2VEYXRhIHsgZGF0YTogU3RyaW5nIH0sCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gbWFpbl9mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMiwgaW5pdF9zdGF0ZV9wdHI6IGkzMiwgZXZlbnRfcHRyOiBpMzIsIGlzX293bmVyOiBpMzIpIC0+IHUzMiB7CiAgc2RrOjpleGVjdXRlX2NvbnRyYWN0KHN0YXRlX3B0ciwgaW5pdF9zdGF0ZV9wdHIsIGV2ZW50X3B0ciwgaXNfb3duZXIsIGNvbnRyYWN0X2xvZ2ljKQp9CgojW3Vuc2FmZShub19tYW5nbGUpXQpwdWIgdW5zYWZlIGZuIGluaXRfY2hlY2tfZnVuY3Rpb24oc3RhdGVfcHRyOiBpMzIpIC0+IHUzMiB7CiAgc2RrOjpjaGVja19pbml0X2RhdGEoc3RhdGVfcHRyLCBpbml0X2xvZ2ljKQp9CgpmbiBpbml0X2xvZ2ljKAogIF9zdGF0ZTogJlN0YXRlLAogIGNvbnRyYWN0X3Jlc3VsdDogJm11dCBzZGs6OkNvbnRyYWN0SW5pdENoZWNrLAopIHsKICBjb250cmFjdF9yZXN1bHQuc3VjY2VzcyA9IHRydWU7Cn0KCmZuIGNvbnRyYWN0X2xvZ2ljKAogIGNvbnRleHQ6ICZzZGs6OkNvbnRleHQ8U3RhdGVFdmVudD4sCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RSZXN1bHQ8U3RhdGU+LAopIHsKICBsZXQgc3RhdGUgPSAmbXV0IGNvbnRyYWN0X3Jlc3VsdC5zdGF0ZTsKICBtYXRjaCBjb250ZXh0LmV2ZW50LmNsb25lKCkgewogICAgICBTdGF0ZUV2ZW50OjpDaGFuZ2VEYXRhIHsgZGF0YSB9ID0+IHsKICAgICAgICBzdGF0ZS5kYXRhID0gZGF0YS5jbG9uZSgpOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQo=";
// Misma lógica que EXAMPLE_CONTRACT pero sin el rechazo de ModThree=50:
// sirve para discriminar qué versión del contrato evaluó un nodo.
const EXAMPLE_CONTRACT_V2: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLnRocmVlID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kQWxsIHsgb25lLCB0d28sIHRocmVlIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IG9uZTsKICAgICAgICBzdGF0ZS50d28gPSB0d287CiAgICAgICAgc3RhdGUudGhyZWUgPSB0aHJlZTsKICAgICAgfQogIH0KICBjb250cmFjdF9yZXN1bHQuc3VjY2VzcyA9IHRydWU7Cn0=";

#[track_caller]
fn assert_governance_properties_eq(actual: Value, expected: GovernanceData) {
    let actual: GovernanceData = from_value(actual).unwrap();
    assert_eq!(actual, expected);
}

#[track_caller]
fn governance_properties(actual: Value) -> GovernanceData {
    from_value(actual).unwrap()
}

async fn wait_sink_events(
    node: &ave_core::Api,
    subject_id: DigestIdentifier,
    expected_len: usize,
) -> Result<Vec<DataToSink>, Box<dyn Error>> {
    let mut attempts = 0;
    loop {
        let page = node
            .get_sink_events(
                subject_id.clone(),
                SinkEventsQuery {
                    from_sn: Some(0),
                    to_sn: None,
                    limit: Some(100),
                },
            )
            .await?;

        if page.events.len() == expected_len {
            return Ok(page.events);
        }

        if attempts > 100 {
            return Err(format!(
                "timeout waiting for sink events for subject {} at len {}, actual len {}",
                subject_id,
                expected_len,
                page.events.len()
            )
            .into());
        }

        attempts += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[test(tokio::test)]
//  Verificar que update protocol actualiza pasivamente la gobernanza, a un testigo.
async fn test_update_protocol() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            is_service: true,
            ..Default::default()
        })
        .await;
    let node1 = nodes[0].api.clone();
    let node2 = nodes[1].api.clone();
    let node3 = nodes[2].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&node2]).await;

    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "AveNode3"
                    ]
                }
            },
        },
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.public_key()
                }
            ]
        }
    });

    let _request_id = emit_fact(&node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    node2
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node1.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node3
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node1.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node3.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "Fake",
                "key": fake_node
            }
        ]
    }});

    emit_fact(&node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    nodes[0].token.cancel();
    join_all(nodes[0].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: node3.peer_id().to_string(),
        address: vec![nodes[2].listen_address.clone()],
    }];

    let (node_new_node2, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address,
        peers,
        always_accept: true,
        is_service: true,
        keys: Some(nodes[1].keys.clone()),
        local_db: Some(_dirs[2].path().to_path_buf()),
        ext_db: Some(_dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let new_node2 = node_new_node2.api.clone();
    node_running(&new_node2).await.unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(2), false)
        .await
        .unwrap();
}

#[test(tokio::test)]
//  El owner perdió el ledger, se lo pidió a un testigo que no tenía la última versión
// la siguiente request se aborta.
async fn test_approve_invalid_gov_version() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ..Default::default()
        })
        .await;
    let node1 = nodes[0].api.clone();
    let node2 = nodes[1].api.clone();
    let node3 = nodes[2].api.clone();

    let governance_id =
        create_and_authorize_governance(&node2, vec![&node1, &node3]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": node1.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.public_key()
                }
            ]
        },
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "approver": ["AveNode3"]
                }
            }
        }
    });

    let request_id = emit_fact(&node2, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    node1
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node2.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node1.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node3
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node2.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node3.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode4",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&node2, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        &node3,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();

    let _state = get_subject(&node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node3.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: node1.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_node2, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(nodes[1].keys.clone()),
        ..Default::default()
    })
    .await;
    let new_node2 = node_new_node2.api.clone();
    node_running(&new_node2).await.unwrap();

    assert!(
        new_node2
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_node2
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node1.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_node2
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode5",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&new_node2, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        &new_node2,
        request_id.clone(),
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    let aborts =
        get_abort_request(&new_node2, governance_id.clone(), request_id)
            .await
            .unwrap();

    assert_eq!(aborts.events.len(), 1);
    assert_eq!(
        aborts.events[0].error,
        "Abort approval, governance update is required by signer: local=2, request=1"
    );

    new_node2
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node3.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_node2
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode5",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&new_node2, governance_id.clone(), json, false)
        .await
        .unwrap();

    emit_approve(
        &new_node2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        &node3,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
}

#[test(tokio::test)]
// El el init state es invalido, se aborata la request
async fn test_invalid_init_state() {
    //  Ephemeral -> Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let node = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                    }
                }
            ]
        },
    });

    emit_fact(node, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node, governance_id.clone(), None, true)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, node.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_governance_properties_eq(
        state.properties,
        GovernanceData {
            version: 0,
            members: BTreeMap::from([(
                "Owner".to_owned(),
                PublicKey::from_str(node.public_key()).unwrap(),
            )]),
            roles_gov: RolesGov {
                approver: BTreeSet::from(["Owner".to_owned()]),
                evaluator: BTreeSet::from(["Owner".to_owned()]),
                validator: BTreeSet::from(["Owner".to_owned()]),
                witness: BTreeSet::from(["Owner".to_owned()]),
                issuer: RoleGovIssuer {
                    signers: BTreeSet::from(["Owner".to_owned()]),
                    any: false,
                },
            },
            policies_gov: PolicyGov {
                approve: Quorum::Majority,
                evaluate: Quorum::Majority,
                validate: Quorum::Majority,
            },
            schemas: BTreeMap::new(),
            roles_schema: BTreeMap::new(),
            roles_tracker_schemas: RolesTrackerSchemas::default(),
            policies_schema: BTreeMap::new(),
        },
    );
}

#[test(tokio::test)]
// El contrato es invalido, se aborata la request
async fn test_invalid_contract() {
    //  Ephemeral -> Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let node = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": INVALID_EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
    });

    emit_fact(node, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node, governance_id.clone(), None, true)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, node.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 0);
    assert_governance_properties_eq(
        state.properties,
        GovernanceData {
            version: 0,
            members: BTreeMap::from([(
                "Owner".to_owned(),
                PublicKey::from_str(node.public_key()).unwrap(),
            )]),
            roles_gov: RolesGov {
                approver: BTreeSet::from(["Owner".to_owned()]),
                evaluator: BTreeSet::from(["Owner".to_owned()]),
                validator: BTreeSet::from(["Owner".to_owned()]),
                witness: BTreeSet::from(["Owner".to_owned()]),
                issuer: RoleGovIssuer {
                    signers: BTreeSet::from(["Owner".to_owned()]),
                    any: false,
                },
            },
            policies_gov: PolicyGov {
                approve: Quorum::Majority,
                evaluate: Quorum::Majority,
                validate: Quorum::Majority,
            },
            schemas: BTreeMap::new(),
            roles_schema: BTreeMap::new(),
            roles_tracker_schemas: RolesTrackerSchemas::default(),
            policies_schema: BTreeMap::new(),
        },
    );
}

#[test(tokio::test)]
//  Verificar que se puede crear una gobernanza, sujeto y emitir un evento además de recibir la copia
async fn test_governance_and_subject_copy_with_approve() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            ..Default::default()
        })
        .await;
    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "AveNode2"
                    ]
                }
            },
            "schema":
                [
                {
                    "schema_id": "Example",
                        "add": {
                            "evaluator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "validator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "witness": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "AveNode2",
                                    "namespace": [],
                                    "quantity": 2
                                }
                            ],
                            "issuer": [
                                {
                                    "name": "AveNode2",
                                    "namespace": []
                                }
                            ]
                        }

                }
            ]
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let (subject_id, ..) =
        create_subject(node2, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(node2, subject_id.clone(), json, true)
        .await
        .unwrap();

    for i in 0..9 {
        let json = json!({
            "ModTwo": {
                "data": i + 1,
            }
        });

        emit_fact(node2, subject_id.clone(), json, false)
            .await
            .unwrap();
    }

    let json = json!({
        "ModTwo": {
            "data": 9 + 1,
        }
    });

    emit_fact(node2, subject_id.clone(), json, true)
        .await
        .unwrap();

    let events = node2
        .get_first_or_end_events(
            subject_id.clone(),
            Some(11),
            Some(false),
            None,
        )
        .await
        .unwrap();

    assert_eq!(events.len(), 11);

    let state = get_subject(node1, subject_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node2.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node2.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 11);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 10
        })
    );

    let state = get_subject(node2, subject_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node2.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node2.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 11);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 10
        })
    );
}

#[test(tokio::test)]
// Caso de uso básico 1 bootstrap (intermediario), 1 ephemeral(issuer de subject),
// 1 addressable(owner de la gobernanza)
async fn test_basic_use_case_1b_1e_1a() {
    //  Ephemeral -> Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            ephemeral: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let bootstrap = &nodes[0].api;
    let addressable = &nodes[1].api;
    let ephimeral = &nodes[2].api;

    let governance_id = create_and_authorize_governance(
        addressable,
        vec![bootstrap, ephimeral],
    )
    .await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": bootstrap.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": ephimeral.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"],
                }
            }
        }
    });

    emit_fact(addressable, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(addressable, governance_id.clone(), None, true)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, addressable.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, addressable.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    let expected = GovernanceData {
        version: 1,
        members: BTreeMap::from([
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(bootstrap.public_key()).unwrap(),
            ),
            (
                "AveNode3".to_owned(),
                PublicKey::from_str(ephimeral.public_key()).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(addressable.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode2".to_owned(),
                "AveNode3".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };
    assert_governance_properties_eq(state.properties, expected.clone());

    let state = get_subject(bootstrap, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, addressable.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, addressable.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_governance_properties_eq(state.properties, expected.clone());

    ephimeral
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let state = get_subject(ephimeral, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, addressable.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, addressable.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
async fn test_many_schema_in_one_governance() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example1",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Example2",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Example3",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
    });
    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), None, true)
            .await
            .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    let expected = GovernanceData {
        version: 1,
        members: BTreeMap::from([(
            "Owner".to_owned(),
            PublicKey::from_str(owner_governance.public_key()).unwrap(),
        )]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::from([
            (
                SchemaType::Type("Example1".to_owned()),
                Schema {
                    contract: EXAMPLE_CONTRACT.to_owned(),
                    initial_value: ValueWrapper(
                        json!({"one": 0, "two": 0, "three": 0}),
                    ),
                    viewpoints: BTreeSet::new(),
                },
            ),
            (
                SchemaType::Type("Example2".to_owned()),
                Schema {
                    contract: EXAMPLE_CONTRACT.to_owned(),
                    initial_value: ValueWrapper(
                        json!({"one": 0, "two": 0, "three": 0}),
                    ),
                    viewpoints: BTreeSet::new(),
                },
            ),
            (
                SchemaType::Type("Example3".to_owned()),
                Schema {
                    contract: EXAMPLE_CONTRACT.to_owned(),
                    initial_value: ValueWrapper(
                        json!({"one": 0, "two": 0, "three": 0}),
                    ),
                    viewpoints: BTreeSet::new(),
                },
            ),
        ]),
        roles_schema: BTreeMap::from([
            (
                SchemaType::Type("Example1".to_owned()),
                RolesSchema::default(),
            ),
            (
                SchemaType::Type("Example2".to_owned()),
                RolesSchema::default(),
            ),
            (
                SchemaType::Type("Example3".to_owned()),
                RolesSchema::default(),
            ),
        ]),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::from([
            (
                SchemaType::Type("Example1".to_owned()),
                PolicySchema {
                    evaluate: Quorum::Majority,
                    validate: Quorum::Majority,
                },
            ),
            (
                SchemaType::Type("Example2".to_owned()),
                PolicySchema {
                    evaluate: Quorum::Majority,
                    validate: Quorum::Majority,
                },
            ),
            (
                SchemaType::Type("Example3".to_owned()),
                PolicySchema {
                    evaluate: Quorum::Majority,
                    validate: Quorum::Majority,
                },
            ),
        ]),
    };
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
// Testear la transferencia de gobernanza
async fn test_transfer_event_governance_1() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let future_owner = &nodes[0].api;
    let owner_governance = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![future_owner])
            .await;
    // add member to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": future_owner.public_key()
                }
            ]
        },
            "roles": {
                "governance": {
                    "add": {
                        "witness": ["AveNode1"],
                    }
                }
            }
    });
    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        owner_governance,
        governance_id.clone(),
        PublicKey::from_str(future_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    // Confirm transfer event
    emit_confirm(future_owner, governance_id.clone(), None, true)
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode2",
                "key": fake_node
            }
        ]
    }});

    emit_fact(future_owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(future_owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, future_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    let expected = GovernanceData {
        version: 4,
        members: BTreeMap::from([
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(future_owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };
    assert_governance_properties_eq(state.properties, expected);

    let state =
        get_subject(owner_governance, governance_id.clone(), None, true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, Some(future_owner.public_key().to_string()));
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(future_owner.public_key()).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
// Testear la transferencia de gobernanza, pero el owner se queda como miembro
async fn test_transfer_event_governance_2() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let future_owner = &nodes[0].api;
    let owner_governance = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![future_owner])
            .await;

    // Auth governance in old owner, in future he will be a normal member and need auth governance for receive a ledger copy.
    owner_governance
        .authorize_governance(governance_id.clone(), AuthWitness::None)
        .await
        .unwrap();
    // add member to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": future_owner.public_key()
                }
            ]
        },
            "roles": {
                "governance": {
                    "add": {
                        "witness": ["AveNode1"],
                    }
                }
            }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        owner_governance,
        governance_id.clone(),
        PublicKey::from_str(future_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let transfer_data = owner_governance.get_pending_transfers().await.unwrap();
    assert_eq!(
        transfer_data[0].actual_owner.to_string(),
        owner_governance.public_key()
    );
    assert_eq!(
        transfer_data[0].new_owner.to_string(),
        future_owner.public_key()
    );
    assert_eq!(transfer_data[0].subject_id, governance_id);

    let transfer_data = future_owner.get_pending_transfers().await.unwrap();
    assert_eq!(
        transfer_data[0].actual_owner.to_string(),
        owner_governance.public_key()
    );
    assert_eq!(
        transfer_data[0].new_owner.to_string(),
        future_owner.public_key()
    );
    assert_eq!(transfer_data[0].subject_id, governance_id);

    // Confirm transfer event
    emit_confirm(
        future_owner,
        governance_id.clone(),
        Some("AveNode_Old".to_owned()),
        true,
    )
    .await
    .unwrap();

    let transfer_data = owner_governance.get_pending_transfers().await.unwrap();
    assert!(transfer_data.is_empty());

    let transfer_data = future_owner.get_pending_transfers().await.unwrap();
    assert!(transfer_data.is_empty());

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    // add new fake member to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": fake_node
                }
            ]
        }
    });

    emit_fact(future_owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(future_owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, future_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    let expected = GovernanceData {
        version: 4,
        members: BTreeMap::from([
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node).unwrap(),
            ),
            (
                "AveNode_Old".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(future_owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode_Old".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };
    assert_governance_properties_eq(state.properties, expected.clone());

    let state =
        get_subject(owner_governance, governance_id.clone(), None, true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, future_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
async fn test_governance_fail_approve() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            ..Default::default()
        })
        .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode1"],
                }
            }
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id,
        true,
    )
    .await
    .unwrap();

    let state = get_subject(node1, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_governance_properties_eq(
        state.properties,
        GovernanceData {
            version: 0,
            members: BTreeMap::from([(
                "Owner".to_owned(),
                PublicKey::from_str(node1.public_key()).unwrap(),
            )]),
            roles_gov: RolesGov {
                approver: BTreeSet::from(["Owner".to_owned()]),
                evaluator: BTreeSet::from(["Owner".to_owned()]),
                validator: BTreeSet::from(["Owner".to_owned()]),
                witness: BTreeSet::from(["Owner".to_owned()]),
                issuer: RoleGovIssuer {
                    signers: BTreeSet::from(["Owner".to_owned()]),
                    any: false,
                },
            },
            policies_gov: PolicyGov {
                approve: Quorum::Majority,
                evaluate: Quorum::Majority,
                validate: Quorum::Majority,
            },
            schemas: BTreeMap::new(),
            roles_schema: BTreeMap::new(),
            roles_tracker_schemas: RolesTrackerSchemas::default(),
            policies_schema: BTreeMap::new(),
        },
    );
}

#[test(tokio::test)]
// Varios approvers y todos dicen que sí, se cumple el quorum.
async fn test_governance_manual_many_approvers() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![approver_1, approver_2])
            .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    emit_approve(
        approver_2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Approver1".to_owned(),
                PublicKey::from_str(approver_1.public_key()).unwrap(),
            ),
            (
                "Approver2".to_owned(),
                PublicKey::from_str(approver_2.public_key()).unwrap(),
            ),
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(&fake_node).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Fixed(100),
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
// Varios approvers y todos dicen que sí, se cumple el quorum. de forma automática.
async fn test_governance_auto_many_approvers() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![approver_1, approver_2])
            .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Approver1".to_owned(),
                PublicKey::from_str(approver_1.public_key()).unwrap(),
            ),
            (
                "Approver2".to_owned(),
                PublicKey::from_str(approver_2.public_key()).unwrap(),
            ),
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(&fake_node).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Fixed(100),
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
// Varios approvers pero uno dice que no y el quorum no se cumple.
async fn test_governance_not_quorum_many_approvers() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![approver_1, approver_2])
            .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "approver": ["Approver1", "Approver2"],
                    "witness": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    emit_approve(
        approver_2,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    let expected = GovernanceData {
        version: 1,
        members: BTreeMap::from([
            (
                "Approver1".to_owned(),
                PublicKey::from_str(approver_1.public_key()).unwrap(),
            ),
            (
                "Approver2".to_owned(),
                PublicKey::from_str(approver_2.public_key()).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Fixed(100),
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
// Se añade un evaluador, se evalua, se le elimina y se vuelve a evaluar.
async fn test_change_roles_gov() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let eval_node = &nodes[0].api;
    let owner_governance = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![eval_node])
            .await;
    // add member to governance
    let json: serde_json::Value = json!({
    "roles": {
        "governance": {
            "add": {
                "witness": ["AveNode1"],
                "evaluator": ["AveNode1"],
                "validator": ["AveNode1"]
            }
        }
    },
    "members": {
        "add": [
            {
                "name": "AveNode1",
                "key": eval_node.public_key()
            }
        ]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let fake_node_1 = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode2",
                "key": fake_node_1
            }
        ]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(eval_node.public_key()).unwrap(),
            ),
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node_1).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            validator: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            witness: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(eval_node, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);

    let json = json!({
    "roles": {
        "governance": {
            "remove": {
                "evaluator": ["AveNode1"],
                "validator": ["AveNode1"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 3,
        members: BTreeMap::from([
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(eval_node.public_key()).unwrap(),
            ),
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node_1).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 3);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(eval_node, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 3);
    assert_governance_properties_eq(state.properties, expected);

    let fake_node_2 = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode3",
                    "key": fake_node_2
                }
            ]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 4,
        members: BTreeMap::from([
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(eval_node.public_key()).unwrap(),
            ),
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node_1).unwrap(),
            ),
            (
                "AveNode3".to_owned(),
                PublicKey::from_str(&fake_node_2).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(4), true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(eval_node, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
async fn test_delete_schema() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",

                        "add": {
                            "evaluator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "validator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "witness": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": 2
                                }
                            ],
                            "issuer": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ]
                        }

                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, subject_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 0
        })
    );

    let json = json!({
        "schemas": {
            "remove": ["Example"]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    create_subject(node1, governance_id.clone(), "Example", "", true)
        .await
        .unwrap_err();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap_err();
    let state = get_subject(node1, subject_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 0
        })
    );
}

#[test(tokio::test)]
async fn test_change_schema() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",

                        "add": {
                            "evaluator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "validator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "witness": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": 2
                                }
                            ],
                            "issuer": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ]
                        }

                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 0
        })
    );

    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": CHANGED_SCHEMA_CONTRACT,
                "new_initial_value": {
                    "data": ""
                }
            }]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "ChangeData": {
            "data": "AveLedger",
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap();
    let state = get_subject(node1, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({
            "data": "AveLedger"
        })
    );
}

#[test(tokio::test)]
// Definimos 2 validadores con Quorum 1, pero solo funciona uno.
// Hay que tener en cuenta que seleccionar uno es rng, puede seleccionar
// uno que esté o que no
async fn test_gov_no_all_validators() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let offline_controller =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "offline",
                    "key": offline_controller
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "validator": [
                        "offline"
                    ]
                }
            }
        },
        "policies": {
            "governance": {
               "change": {
                    "evaluate": {
                        "fixed": 1
                    },
                    "validate": {
                        "fixed": 1
                    }
               }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let user = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
            "members": {
                "add": [
                    {
                        "name": "user",
                        "key": user
                    }
                ]
            },
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
            (
                "offline".to_owned(),
                PublicKey::from_str(&offline_controller).unwrap(),
            ),
            ("user".to_owned(), PublicKey::from_str(&user).unwrap()),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from([
                "Owner".to_owned(),
                "offline".to_owned(),
            ]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Fixed(1),
            validate: Quorum::Fixed(1),
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
// Definimos 2 evaluadores con Quorum 1, pero solo funciona uno.
// Hay que tener en cuenta que seleccionar uno es rng, puede seleccionar
// uno que esté o que no.
async fn test_gov_no_all_evaluators() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let offline_controller =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "offline",
                    "key": offline_controller
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": [
                        "offline"
                    ]
                }
            }
        },
        "policies": {
            "governance": {
               "change": {
                    "evaluate": {
                        "fixed": 1
                    },
                    "validate": {
                        "fixed": 1
                    }
               }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let user = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
            "members": {
                "add": [
                    {
                        "name": "user",
                        "key": user
                    }
                ]
            },
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
            (
                "offline".to_owned(),
                PublicKey::from_str(&offline_controller).unwrap(),
            ),
            ("user".to_owned(), PublicKey::from_str(&user).unwrap()),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from([
                "Owner".to_owned(),
                "offline".to_owned(),
            ]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Fixed(1),
            validate: Quorum::Fixed(1),
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
// Definimos 2 validadores con Quorum 1, pero solo funciona uno.
// Hay que tener en cuenta que seleccionar uno es rng, puede seleccionar
// uno que esté o que no
// Algunos eventos fallan, por lo que la versión de la governanza no aumenta
async fn test_gov_fail_no_all_evaluators() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let offline_controller =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "offline",
                    "key": offline_controller
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": [
                        "offline"
                    ]
                }
            }
        },
        "policies": {
            "governance": {
               "change": {
                    "evaluate": {
                        "fixed": 1
                    },
                    "validate": {
                        "fixed": 1
                    }
               }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let mut keys = vec![];
    for i in 0..2 {
        let user = if i % 2 != 0 {
            let user = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                .public_key()
                .to_string();

            keys.push(user.clone());

            user
        } else {
            String::default()
        };

        // add node bootstrap and ephemeral to governance
        let json = json!({
                "members": {
                    "add": [
                        {
                            "name": format!("user{}", i),
                            "key": user
                        }
                    ]
                },
        });

        emit_fact(owner_governance, governance_id.clone(), json, true)
            .await
            .unwrap();
    }

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
            (
                "offline".to_owned(),
                PublicKey::from_str(&offline_controller).unwrap(),
            ),
            ("user1".to_owned(), PublicKey::from_str(&keys[0]).unwrap()),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from([
                "Owner".to_owned(),
                "offline".to_owned(),
            ]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Fixed(1),
            validate: Quorum::Fixed(1),
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(3), true)
            .await
            .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 3);
    assert_governance_properties_eq(state.properties, expected);
}

#[test(tokio::test)]
async fn test_governance_schema_and_creator_viewpoints_state() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;

    let governance_id = create_and_authorize_governance(owner, vec![]).await;

    let alice = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": alice
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    },
                    "viewpoints": ["agua", "basura", "NoViewpoints"]
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 2
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let governance = governance_properties(state.properties);
    let schema_id = SchemaType::Type("Example".to_owned());

    assert_eq!(governance.version, 2);
    assert_eq!(
        governance.schemas.get(&schema_id).unwrap().viewpoints,
        BTreeSet::from([
            "NoViewpoints".to_owned(),
            "agua".to_owned(),
            "basura".to_owned(),
        ])
    );

    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(
        creator.witnesses,
        BTreeSet::from([CreatorWitness {
            name: "Witnesses".to_owned(),
            viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
        }])
    );

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Witnesses",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "Alice",
                                        "viewpoints": []
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let governance = governance_properties(state.properties);
    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(
        creator.witnesses,
        BTreeSet::from([
            CreatorWitness {
                name: "Alice".to_owned(),
                viewpoints: BTreeSet::new(),
            },
            CreatorWitness {
                name: "Witnesses".to_owned(),
                viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
            },
        ])
    );

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Witnesses",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "Alice",
                                        "viewpoints": ["NoViewpoints"]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        },
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_viewpoints": ["agua", "basura", "vidrio", "NoViewpoints"]
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
    let governance = governance_properties(state.properties);
    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(governance.version, 4);
    assert_eq!(
        governance.schemas.get(&schema_id).unwrap().viewpoints,
        BTreeSet::from([
            "NoViewpoints".to_owned(),
            "agua".to_owned(),
            "basura".to_owned(),
            "vidrio".to_owned()
        ])
    );
    assert_eq!(
        creator.witnesses,
        BTreeSet::from([
            CreatorWitness {
                name: "Alice".to_owned(),
                viewpoints: BTreeSet::from(["NoViewpoints".to_owned()]),
            },
            CreatorWitness {
                name: "Witnesses".to_owned(),
                viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
            },
        ])
    );
}

#[test(tokio::test)]
async fn test_governance_invalid_viewpoints_validation() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;

    let governance_id = create_and_authorize_governance(owner, vec![]).await;

    let alice = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": alice
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "InvalidDuplicate",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    },
                    "viewpoints": ["agua", "agua"]
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "InvalidReserved",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    },
                    "viewpoints": ["AllViewpoints"]
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    },
                    "viewpoints": ["agua", "basura"]
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 2
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Witnesses",
                                        "viewpoints": []
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Witnesses",
                                        "viewpoints": ["NoViewpoints"]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(6), true)
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Witnesses",
                                        "viewpoints": ["agua"]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(7), true)
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Alice",
                                        "viewpoints": ["vidrio"]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(8), true)
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Alice",
                                        "viewpoints": ["AllViewpoints", "agua"]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(9), true)
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Owner",
                                        "viewpoints": ["agua"]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(10), true)
        .await
        .unwrap();

    let state = get_subject(owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    let governance = governance_properties(state.properties);
    let schema_id = SchemaType::Type("Example".to_owned());
    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(governance.version, 2);
    assert_eq!(
        creator.witnesses,
        BTreeSet::from([CreatorWitness {
            name: "Witnesses".to_owned(),
            viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
        }])
    );
}

#[test(tokio::test)]
async fn test_sink_replay_and_external_db_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = nodes[0].api.clone();
    let bob = nodes[1].api.clone();
    let bob_pk = PublicKey::from_str(bob.public_key()).unwrap();
    let charlie_pk =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    let invalid_member_pk =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&bob]).await;
    let governance_id_string = governance_id.to_string();

    let governance_setup_payload = json!({
        "members": {
            "add": [
                {
                    "name": "Bob",
                    "key": bob.public_key()
                },
                {
                    "name": "Charlie",
                    "key": charlie_pk.to_string()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Bob"]
                }
            }
        }
    });

    emit_fact(
        &owner,
        governance_id.clone(),
        governance_setup_payload.clone(),
        true,
    )
    .await
    .unwrap();

    get_subject(&bob, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    emit_fact(
        &owner,
        governance_id.clone(),
        governance_setup_payload.clone(),
        true,
    )
    .await
    .unwrap();

    emit_transfer(
        &owner,
        governance_id.clone(),
        invalid_member_pk.clone(),
        true,
    )
    .await
    .unwrap();

    emit_transfer(&owner, governance_id.clone(), bob_pk.clone(), true)
        .await
        .unwrap();

    get_subject(&bob, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    emit_confirm(
        &bob,
        governance_id.clone(),
        Some("Charlie".to_owned()),
        true,
    )
    .await
    .unwrap();

    emit_reject(&bob, governance_id.clone(), true)
        .await
        .unwrap();

    owner
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(bob_pk.clone()),
        )
        .await
        .unwrap();
    owner.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&owner, governance_id.clone(), Some(6), true)
        .await
        .unwrap();

    emit_eol(&owner, governance_id.clone(), true).await.unwrap();

    let subject_state =
        get_subject(&owner, governance_id.clone(), Some(7), true)
            .await
            .unwrap();
    assert!(!subject_state.active);

    let api_events = get_events(&owner, governance_id.clone(), 8, true)
        .await
        .unwrap();
    let sink_events = wait_sink_events(&owner, governance_id.clone(), 8)
        .await
        .unwrap();

    assert_eq!(api_events.len(), 8);
    assert_eq!(sink_events.len(), 8);

    match &api_events[0].event {
        RequestEventDB::Create {
            name,
            description,
            schema_id,
            namespace,
        } => {
            assert_eq!(name.as_deref(), Some("Governance Tests"));
            assert_eq!(
                description.as_deref(),
                Some("A description for Governance Tests")
            );
            assert_eq!(schema_id, "governance");
            assert_eq!(namespace, "");
        }
        other => panic!("unexpected create event: {other:?}"),
    }

    match &api_events[1].event {
        RequestEventDB::GovernanceFact {
            payload,
            evaluation_response,
            approval_success,
        } => {
            assert_eq!(payload, &governance_setup_payload);
            match evaluation_response {
                EvalResDB::Patch(_) => {}
                other => {
                    panic!("unexpected governance fact result: {other:?}")
                }
            }
            assert_eq!(*approval_success, Some(true));
        }
        other => panic!("unexpected governance fact event: {other:?}"),
    }

    match &api_events[2].event {
        RequestEventDB::GovernanceFact {
            payload,
            evaluation_response,
            approval_success,
        } => {
            assert_eq!(payload, &governance_setup_payload);
            match evaluation_response {
                EvalResDB::Error(error) => {
                    assert!(!error.is_empty());
                }
                other => {
                    panic!(
                        "unexpected failed governance fact result: {other:?}"
                    )
                }
            }
            assert!(approval_success.is_none());
        }
        other => panic!("unexpected failed governance fact event: {other:?}"),
    }

    match &api_events[3].event {
        RequestEventDB::Transfer {
            evaluation_error,
            new_owner,
        } => {
            assert_eq!(new_owner, &invalid_member_pk.to_string());
            assert!(evaluation_error.is_some());
        }
        other => panic!("unexpected failed transfer event: {other:?}"),
    }

    match &api_events[4].event {
        RequestEventDB::Transfer {
            evaluation_error,
            new_owner,
        } => {
            assert_eq!(new_owner, &bob.public_key());
            assert!(evaluation_error.is_none());
        }
        other => panic!("unexpected successful transfer event: {other:?}"),
    }

    match &api_events[5].event {
        RequestEventDB::GovernanceConfirm {
            name_old_owner,
            evaluation_response,
        } => {
            assert_eq!(name_old_owner.as_deref(), Some("Charlie"));
            match evaluation_response {
                EvalResDB::Error(error) => {
                    assert!(!error.is_empty());
                }
                other => panic!("unexpected failed confirm result: {other:?}"),
            }
        }
        other => panic!("unexpected failed confirm event: {other:?}"),
    }

    assert!(matches!(api_events[6].event, RequestEventDB::Reject));
    assert!(matches!(api_events[7].event, RequestEventDB::EOL));

    for event in &sink_events {
        assert!(event.event_request_timestamp > 0);
        assert!(event.event_ledger_timestamp > 0);
        assert!(event.sink_timestamp > 0);
    }

    match &sink_events[0].payload {
        DataToSinkEvent::Create {
            governance_id: event_governance_id,
            subject_id,
            owner: event_owner,
            schema_id,
            namespace,
            sn,
            gov_version,
            state,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(namespace, "");
            assert_eq!(*sn, 0);
            assert_eq!(*gov_version, 0);
            assert!(state.is_object());
        }
        other => panic!("unexpected sink create event: {other:?}"),
    }
    assert_eq!(sink_events[0].public_key, owner.public_key());

    match &sink_events[1].payload {
        DataToSinkEvent::FactFull {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            viewpoints,
            issuer,
            owner: event_owner,
            payload,
            patch,
            success,
            error,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert!(viewpoints.is_empty());
            assert_eq!(issuer, &owner.public_key());
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(payload, &governance_setup_payload);
            assert!(patch.is_some());
            assert!(*success);
            assert!(error.is_none());
            assert_eq!(*sn, 1);
            assert_eq!(*gov_version, 0);
        }
        other => panic!("unexpected sink successful fact event: {other:?}"),
    }
    assert_eq!(sink_events[1].public_key, owner.public_key());

    match &sink_events[2].payload {
        DataToSinkEvent::FactFull {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            viewpoints,
            issuer,
            owner: event_owner,
            payload,
            patch,
            success,
            error,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert!(viewpoints.is_empty());
            assert_eq!(issuer, &owner.public_key());
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(payload, &governance_setup_payload);
            assert!(patch.is_none());
            assert!(!success);
            assert!(error.is_some());
            assert_eq!(*sn, 2);
            assert_eq!(*gov_version, 1);
        }
        other => panic!("unexpected sink failed fact event: {other:?}"),
    }
    assert_eq!(sink_events[2].public_key, owner.public_key());

    match &sink_events[3].payload {
        DataToSinkEvent::Transfer {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            owner: event_owner,
            new_owner,
            success,
            error,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(new_owner, &invalid_member_pk.to_string());
            assert!(!success);
            assert!(error.is_some());
            assert_eq!(*sn, 3);
            assert_eq!(*gov_version, 1);
        }
        other => panic!("unexpected sink failed transfer event: {other:?}"),
    }
    assert_eq!(sink_events[3].public_key, owner.public_key());

    match &sink_events[4].payload {
        DataToSinkEvent::Transfer {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            owner: event_owner,
            new_owner,
            success,
            error,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(new_owner, &bob.public_key());
            assert!(*success);
            assert!(error.is_none());
            assert_eq!(*sn, 4);
            assert_eq!(*gov_version, 1);
        }
        other => panic!("unexpected sink successful transfer event: {other:?}"),
    }
    assert_eq!(sink_events[4].public_key, owner.public_key());

    match &sink_events[5].payload {
        DataToSinkEvent::Confirm {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            sn,
            patch,
            success,
            error,
            gov_version,
            name_old_owner,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(*sn, 5);
            assert!(patch.is_none());
            assert!(!success);
            assert!(error.is_some());
            assert_eq!(*gov_version, 2);
            assert_eq!(name_old_owner.as_deref(), Some("Charlie"));
        }
        other => panic!("unexpected sink failed confirm event: {other:?}"),
    }
    assert_eq!(sink_events[5].public_key, owner.public_key());

    match &sink_events[6].payload {
        DataToSinkEvent::Reject {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(*sn, 6);
            assert_eq!(*gov_version, 2);
        }
        other => panic!("unexpected sink reject event: {other:?}"),
    }
    assert_eq!(sink_events[6].public_key, owner.public_key());

    match &sink_events[7].payload {
        DataToSinkEvent::Eol {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(*sn, 7);
            assert_eq!(*gov_version, 3);
        }
        other => panic!("unexpected sink eol event: {other:?}"),
    }
    assert_eq!(sink_events[7].public_key, owner.public_key());
}

#[test(tokio::test)]
// test_build_batch_gov: Emisor construye batch de governance
//
// Qué se prueba:
//   `build_distribution_batch` para una governance. Verifica que el emisor
//   construye correctamente un batch de eventos de gobernanza (is_gov=true),
//   sin transfer_event, con los límites de gov_version aplicados.
//
// Setup:
//   1. Owner crea gobernanza con batch_size=2 (ledger_batch_size pequeño).
//   2. Owner emite 1 fact de config + 3 facts (SN llega a 4:
//      create SN=0 + config SN=1 + 3 facts SN=2..4).
//   3. Witness W1 se autoriza con owner y hace update_subject.
//   4. Verificar que W1 recibe TODOS los eventos (el batch se divide en
//      múltiples chunks porque batch_size=2 < total_events).
//   5. Verificar que W1 tiene el mismo SN que owner.
//
// Prioridad: MEDIA.
async fn test_build_batch_gov() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ledger_batch_size: Some(2),
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let witness = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![witness]).await;

    // Configurar gobernanza: añadir witness como witness y member
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": witness.public_key()
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Emitir más facts para crear múltiples SN
    for i in 1..=3 {
        let json = json!({
            "members": {
                "add": [
                    {
                        "name": format!("Fake{}", i),
                        "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                            .public_key()
                            .to_string()
                    }
                ]
            }
        });
        emit_fact(owner, governance_id.clone(), json, true)
            .await
            .unwrap();
    }

    // Witness se autoriza con owner como fuente
    witness
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    // Witness pide update → debe recibir todos los chunks
    witness.update_subject(governance_id.clone()).await.unwrap();

    // Verificar que witness tiene el mismo SN que owner (SN=5)
    get_subject(owner, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    get_subject(witness, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
}

#[test(tokio::test)]
// test_update_offer_gov: Receptor responde a GetLastSn con governance
//
// Qué se prueba:
//   `build_last_sn_offer` para una governance. Cuando un receptor solicita
//   el último SN de una governance, el emisor debe responder correctamente
//   con el SN, is_all, y los metadatos de gobernanza.
//
// Setup:
//   1. Owner crea gobernanza (SN=0).
//   2. Owner emite fact → SN=1.
//   3. Witness W1 se autoriza y hace update_subject → obtiene SN=1.
//   4. Owner emite más facts → SN avanza a 3.
//   5. W1 hace update_subject de nuevo → debe obtener SN=3.
//   6. Verificar que W1 siempre recibe el SN más alto ofrecido por owner.
//
// Prioridad: MEDIA.
async fn test_update_offer_gov() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let witness = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![witness]).await;

    // Configurar gobernanza: añadir witness como witness y member
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": witness.public_key()
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Witness se autoriza y obtiene SN=1
    witness
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    witness.update_subject(governance_id.clone()).await.unwrap();

    get_subject(witness, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Owner emite más facts → SN=2 y SN=3
    for i in 1..=2 {
        let json = json!({
            "members": {
                "add": [
                    {
                        "name": format!("Fake{}", i),
                        "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                            .public_key()
                            .to_string()
                    }
                ]
            }
        });
        emit_fact(owner, governance_id.clone(), json, true)
            .await
            .unwrap();
    }

    // Witness pide update de nuevo → debe llegar a SN=3
    witness.update_subject(governance_id.clone()).await.unwrap();

    get_subject(witness, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
}

#[test(tokio::test)]
// Un evaluador con el compilador caído responde `Unavailable` y no arrastra
// la request: el quorum de evaluación se cierra con el resto de evaluadores
// y el fact de gobernanza con contrato se confirma.
async fn test_gov_evaluator_compiler_unavailable_quorum_holds() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    // Tercer nodo cuyo compilador apunta a un endpoint muerto: toda
    // compilación falla con `CompilersUnavailable`.
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node3, mut node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", port),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node3_dirs);
    node_running(&node3.api).await.unwrap();
    let node3 = &node3.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2, node3]).await;

    // SN 1: los tres nodos pasan a ser evaluadores y witnesses de la
    // gobernanza. Este fact no añade contratos, así que no necesita
    // compilación y lo evalúa el Owner (quorum Majority de 1 evaluador).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"],
                    "evaluator": ["AveNode2", "AveNode3"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Esperar a que el fact commitee en node1 antes de sincronizar:
    // wait_request puede terminar en Approval, antes del commit real.
    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Los evaluadores deben tener la gobernanza en SN 1 antes del siguiente
    // fact, o responderían por desincronización de versión.
    node2.update_subject(governance_id.clone()).await.unwrap();
    node3.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    get_subject(node3, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: fact que añade un schema con contrato. La evaluación exige
    // compilarlo de forma temporal; node3 no puede y responde `Unavailable`,
    // pero el quorum Majority (2 de 3) se cierra con node1 y node2.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.sn, 2);
    assert!(state.active);

    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
    assert_eq!(gov.members.len(), 3);
}

#[test(tokio::test)]
// Si el quorum de evaluación es inalcanzable porque los compiladores no
// están disponibles, la request no se pierde ni se marca inválida: entra en
// RebootTimeOut y el nodo emisor sigue operativo.
async fn test_gov_evaluator_compiler_unavailable_quorum_fails_reboot() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // Segundo nodo con el compilador apuntando a un endpoint muerto.
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", port),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();
    let node2 = &node2.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: node2 pasa a ser evaluador y witness. Con 2 evaluadores y
    // quorum Majority la evaluación exige el visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "evaluator": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Esperar a que el fact commitee en node1 antes de sincronizar:
    // wait_request puede terminar en Approval, antes del commit real.
    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Fact con contrato: node1 evalúa correctamente pero node2 responde
    // `Unavailable`; sin quorum la request entra en RebootTimeOut.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        node1,
        request_id,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // La gobernanza no avanza y el nodo emisor sigue respondiendo.
    let state = get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert_eq!(state.sn, 1);
    assert!(state.active);
}

#[test(tokio::test)]
// Un contrato que agota el fuel es un fallo determinista del contrato:
// todos los evaluadores votan Error idéntico, el evento queda registrado
// como fallido y ningún nodo se tumba (antes cada evaluador crasheaba —
// DoS por contrato).
async fn test_contract_fuel_exhaustion_fails_event_nodes_survive() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: schema con un contrato que entra en bucle en ModOne. Ambos
    // nodos son testigos de la gobernanza y evaluadores del schema, así
    // los dos ejecutan el contrato y votan.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Fuel",
                    "contract": FUEL_EXHAUSTING_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"]
                }
            },
            "schema": [
                {
                    "schema_id": "Fuel",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "validator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "witness": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
                            }
                        ],
                        "issuer": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Esperar el commit en node1 y sincronizar node2 antes de seguir.
    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // La creación del subject funciona: init_check no ejecuta el bucle.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Fuel", "", true)
            .await
            .unwrap();

    // node2 es testigo del schema desde antes de la creación: recibe el
    // evento Create por distribución automática.
    get_subject(node2, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    // ModOne entra en bucle: ambos evaluadores agotan el fuel y votan
    // Error idéntico, así que el agregador cierra Error (no Diff-reboot)
    // y el evento queda registrado como fallido.
    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // El evento fallido avanza el sn pero no modifica las propiedades.
    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 0}));

    // El evento registrado lleva el error de evaluación (fuel agotado).
    let events = get_events(node1, subject_id.clone(), 2, true)
        .await
        .unwrap();
    match &events[1].event {
        RequestEventDB::TrackerFactFull {
            evaluation_response,
            ..
        } => match evaluation_response {
            EvalResDB::Error(error) => assert!(!error.is_empty()),
            other => panic!("unexpected evaluation result: {other:?}"),
        },
        other => panic!("unexpected event: {other:?}"),
    }

    // node2 también lo recibe: los dos nodos siguen vivos y consistentes.
    get_subject(node2, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Y el nodo sigue operando con normalidad: un fact posterior de
    // gobernanza completa sin problema.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode3",
                    "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                        .public_key()
                        .to_string()
                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
}

#[test(tokio::test)]
// Un fallo de disco al persistir los artefactos de un contrato es un
// fallo local fatal, no un problema del pool de compiladores: el nodo no
// puede evaluar ese schema de forma fiable y el arranque debe fallar de
// forma controlada en lugar de continuar en modo degradado.
async fn test_gov_contract_artifacts_disk_failure_node_fails_boot() {
    use std::os::unix::fs::PermissionsExt;

    let contracts_dir = tempfile::tempdir().unwrap();
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, dirs) = create_node(CreateNodeConfig {
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    // SN 1: schema con contrato. La compilación final persiste los
    // artefactos bajo el directorio de contratos del nodo.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });
    emit_fact(&node.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&node.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert!(contracts_dir.path().join("contracts").exists());

    // Apagado ordenado conservando claves y bases de datos.
    let keys = node.keys.clone();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    // Simular corrupción de disco: los artefactos desaparecen y el
    // directorio queda sin permisos de escritura, así la recompilación
    // del arranque no puede persistir el artefacto.
    fs::remove_dir_all(contracts_dir.path().join("contracts")).unwrap();
    fs::set_permissions(
        contracts_dir.path(),
        fs::Permissions::from_mode(0o555),
    )
    .unwrap();

    let result = try_create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(keys),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    // Restaurar permisos para que el TempDir pueda limpiarse al salir.
    fs::set_permissions(
        contracts_dir.path(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    match result {
        Err(ave_core::error::Error::ActorCreation { actor, .. }) => {
            assert_eq!(actor, "node");
        }
        Err(error) => panic!("unexpected boot error: {error}"),
        Ok(_) => {
            panic!("node booted with a read-only contracts directory")
        }
    }
}

#[test(tokio::test)]
// Un compilador cuya clave pública no coincide con el pin configurado es
// indistinguible de uno comprometido: el cliente descarta sus respuestas
// (firma de atestación inválida), el evaluador responde `Unavailable` sin
// emitir veredicto y, al no cerrarse el quorum, la request entra en
// RebootTimeOut en lugar de perderse. Ambos nodos siguen operativos.
async fn test_gov_evaluator_wrong_compiler_pin_unavailable_reboot() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // Segundo nodo apuntando al compilador embebido real pero con un pin
    // de clave pública incorrecto: toda respuesta se descarta.
    let mut compiler_config =
        ave_core::test_compiler::test_compiler_config().await;
    compiler_config.compiler_public_key = Some(
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string(),
    );

    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(compiler_config),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();
    let node2 = &node2.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: node2 pasa a ser evaluador y testigo. Con 2 evaluadores y
    // quorum Majority la evaluación exige el visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "evaluator": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Esperar a que el fact commitee en node1 antes de sincronizar:
    // wait_request puede terminar en Approval, antes del commit real.
    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Fact con contrato: node1 evalúa correctamente pero las respuestas
    // del compilador de node2 se descartan por el pin; sin quorum la
    // request entra en RebootTimeOut.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        node1,
        request_id,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // La gobernanza no avanza y ambos nodos siguen respondiendo.
    let state = get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert_eq!(state.sn, 1);
    assert!(state.active);
    node_running(node2).await.unwrap();
}

#[test(tokio::test)]
// La compilación final con el pool caído degrada pero no tumba el nodo:
// el schema queda sin artefacto local y sus evaluaciones responden
// `Unavailable`, el quorum se cierra con el resto de evaluadores y el
// nodo degradado sigue aplicando el ledger como testigo.
async fn test_gov_evaluator_degraded_compile_survives_and_serves_ledger() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    // Tercer nodo cuyo compilador apunta a un endpoint muerto.
    let (node3, mut node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node3_dirs);
    node_running(&node3.api).await.unwrap();
    let node3 = &node3.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2, node3]).await;

    // SN 1: los tres nodos pasan a ser evaluadores y testigos de la
    // gobernanza. Sin contratos de por medio, la evalúa el Owner.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"],
                    "evaluator": ["AveNode2", "AveNode3"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    node3.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    get_subject(node3, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: schema con contrato y roles de schema. La evaluación temporal
    // de node3 responde `Unavailable` pero el quorum Majority (2 de 3) se
    // cierra con node1 y node2. Al commitear, node3 intenta la
    // compilación final, agota los reintentos (~30s de backoff; el poll
    // de get_subject absorbe la espera) y degrada: el schema queda sin
    // artefacto local.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ],
                        "validator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "witness": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
                            }
                        ],
                        "issuer": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    node3.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    get_subject(node3, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Creación del subject: node3 responde `Unavailable` (contrato no
    // encontrado) y el quorum se cierra con node1 y node2.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(node2, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    get_subject(node3, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    // El fact se evalúa sin node3 y commitea con el quorum restante.
    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    // El nodo degradado sigue vivo y aplica el ledger como testigo.
    let state = get_subject(node3, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));
}

#[test(tokio::test)]
// Si el refresh de un contrato modificado falla por infraestructura del
// pool, el módulo anterior se expulsa del caché local: evaluar con el
// contrato stale divergiría del resto de la red. El evaluador responde
// `Unavailable` (RebootTimeOut) en lugar de votar con la versión vieja,
// lo que produciría un RebootDiff.
async fn test_contract_refresh_failure_evicts_stale_module_reboot_timeout() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // node2 con un directorio de contratos explícito: el artefacto v1
    // debe sobrevivir al reinicio para que el arranque lo cargue de
    // disco (si no se preserva, el restart genera un directorio vacío y
    // el nodo arrancaría ya degradado, sin módulo stale que expulsar).
    let contracts_dir = tempfile::tempdir().unwrap();
    let (mut node2_data, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2_data.api).await.unwrap();

    let node2 = &node2_data.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: miembro + schema "Example" (v1). node2 es testigo de la
    // gobernanza (no evaluador: los facts de gobernanza commitean solo
    // con el Owner) y evaluador del schema; el quorum Majority de
    // evaluación del schema exige a los dos evaluadores.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "validator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "witness": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
                            }
                        ],
                        "issuer": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Subject y fact con la v1: ambos evaluadores operativos.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(node2, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Esperar a que node2 aplique el evento antes de apagarlo: reiniciar
    // un nodo desincronizado degrada todo lo posterior bajo estrés.
    get_subject(node2, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Reinicio de node2 con el compilador muerto conservando el
    // directorio de contratos: el artefacto v1 está en disco, así que el
    // arranque no necesita al pool.
    let keys = node2_data.keys.clone();
    let local_db = node2_dirs[0].path().to_path_buf();
    let ext_db = node2_dirs[1].path().to_path_buf();

    node2_data.token.cancel();
    join_all(node2_data.handler.iter_mut()).await;

    let (node2, mut node2_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    dirs.append(&mut node2_dirs_new);
    node_running(&node2.api).await.unwrap();
    let node2 = &node2.api;

    // SN 2: cambio de contrato a la v2 (ModThree=50 pasa a ser válido).
    // Lo evalúa el Owner únicamente. Al commitear, node2 intenta el
    // refresh contra su pool muerto, agota los reintentos (~30s de
    // backoff) y expulsa el módulo v1 del caché.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Sincronizar node2: su gobernanza queda ocupada con los reintentos
    // del refresh, así que este poll espera a que la expulsión ya haya
    // ocurrido antes de emitir el siguiente fact.
    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // ModThree=50: node1 (v2) vota OK; node2, sin módulo, responde
    // `Unavailable`. Sin quorum la request entra en RebootTimeOut. Si la
    // expulsión no existiera, node2 votaría Error con la v1 y el
    // resultado sería RebootDiff.
    let request_id = emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        false,
    )
    .await
    .unwrap();

    wait_request_state(
        node1,
        request_id,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // El nodo degradado sigue operativo.
    node_running(node2).await.unwrap();
}

#[test(tokio::test)]
// Un evaluador degradado se recupera al reiniciar con un pool sano: los
// artefactos se obtienen en el arranque y el nodo vuelve a votar. El
// quorum Majority exige a los dos evaluadores, así que el commit del
// fact prueba que el nodo recuperado participa de nuevo.
async fn test_gov_evaluator_recovers_after_compiler_restart() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // Segundo nodo con el compilador apuntando a un endpoint muerto.
    let (mut node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: node2 pasa a ser evaluador y testigo. Con 2 evaluadores y
    // quorum Majority la evaluación exige el visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "evaluator": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Intento de fact con contrato: node2 no puede evaluar y la request
    // entra en RebootTimeOut.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        node1,
        request_id,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // Reinicio con el pool sano (el embebido autoinyectado): los
    // artefactos se obtienen al arrancar y node2 vuelve a evaluar.
    let keys = node2.keys.clone();
    let local_db = node2_dirs[0].path().to_path_buf();
    let ext_db = node2_dirs[1].path().to_path_buf();

    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, mut node2_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    dirs.append(&mut node2_dirs_new);
    node_running(&node2.api).await.unwrap();

    // Con el pool recuperado, la propia request sale del reboot y
    // commitea: como el quorum exige el voto de node2, el commit prueba
    // la recuperación. No hace falta reemitir nada — los reboots por
    // TimeOut son ilimitados (el schedule repite su último valor).
    let state = get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// Un artefacto corrupto en disco no es un fallo fatal: el check de
// integridad (hash del wasm y del precompilado) lo detecta en el
// arranque, lo descarta y recompila desde el pool. El nodo arranca y
// evalúa con normalidad.
async fn test_contract_artifact_corruption_self_heals_on_boot() {
    let contracts_dir = tempfile::tempdir().unwrap();
    let (mut node, dirs) = create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    // SN 1: schema con contrato y roles del Owner; la compilación final
    // persiste los artefactos en el directorio de contratos.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "validator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "witness": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
                            }
                        ],
                        "issuer": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(&node.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&node.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert!(contracts_dir.path().join("contracts").exists());

    // Apagado ordenado conservando claves y bases de datos.
    let keys = node.keys.clone();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    // Corromper todos los artefactos persistidos: los hashes no
    // coincidirán con los registrados y el loader los descartará.
    let contracts_root = contracts_dir.path().join("contracts");
    for entry in fs::read_dir(&contracts_root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            for artifact in fs::read_dir(entry.path()).unwrap() {
                let artifact = artifact.unwrap();
                if artifact.file_type().unwrap().is_file() {
                    fs::write(artifact.path(), b"corrupted artifact").unwrap();
                }
            }
        }
    }

    // Reinicio: el loader detecta el hash mismatch, recompila desde el
    // pool y el nodo arranca con normalidad.
    let (node, _new_dirs) = create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(keys),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    // El nodo evalúa con el artefacto recompilado: subject + fact.
    let (subject_id, ..) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));
}

#[test(tokio::test)]
// La degradación es por schema, no por nodo: un evaluador que reinicia
// con el pool caído pero con el artefacto en disco sigue evaluando ese
// schema con total normalidad (solo queda mudo para schemas que no puede
// obtener). El quorum Majority exige a los dos evaluadores, así que el
// commit prueba que node2 votó con el artefacto cacheado.
async fn test_contract_cached_artifact_evaluates_with_dead_compiler_pool() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // node2 con un directorio de contratos explícito: el artefacto debe
    // sobrevivir al reinicio para que el arranque lo cargue de disco (si
    // no se preserva, el restart genera un directorio vacío y el nodo
    // degradaría, que no es lo que se quiere probar).
    let contracts_dir = tempfile::tempdir().unwrap();
    let (mut node2_data, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2_data.api).await.unwrap();

    let node2 = &node2_data.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: miembro + schema "Example". node2 es testigo de la
    // gobernanza y evaluador del schema; el quorum Majority exige a los
    // dos evaluadores.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "validator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "witness": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
                            }
                        ],
                        "issuer": [
                            {
                                "name": "Owner",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Subject y fact con ambos nodos sanos: el artefacto queda
    // persistido en disco en node2.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(node2, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Esperar a que node2 aplique el evento antes de apagarlo: reiniciar
    // un nodo desincronizado degrada todo lo posterior bajo estrés.
    get_subject(node2, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Reinicio de node2 con el compilador muerto conservando el
    // directorio de contratos: el arranque carga el artefacto desde
    // disco y no necesita al pool.
    let keys = node2_data.keys.clone();
    let local_db = node2_dirs[0].path().to_path_buf();
    let ext_db = node2_dirs[1].path().to_path_buf();

    node2_data.token.cancel();
    join_all(node2_data.handler.iter_mut()).await;

    let (node2, mut node2_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    dirs.append(&mut node2_dirs_new);
    node_running(&node2.api).await.unwrap();
    let node2 = &node2.api;

    // Fact posterior: node2 evalúa con el artefacto cacheado y el fact
    // commitea. Sin su voto no habría quorum, así que el commit prueba
    // que el nodo sigue operativo para este schema pese al pool caído.
    // Se emite async y se espera el commit con get_subject (acotado):
    // wait_request no tiene límite y bajo estrés la request puede pasar
    // por varias rondas de reboot antes de commitear.
    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModTwo": {"data": 9}}),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert_eq!(state.properties, json!({"one": 1, "two": 9, "three": 0}));

    let state = get_subject(node2, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert_eq!(state.properties, json!({"one": 1, "two": 9, "three": 0}));
}
