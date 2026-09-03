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
                compiler: BTreeSet::from(["Owner".to_owned()]),
            },
            policies_gov: PolicyGov {
                approve: Quorum::Majority,
                evaluate: Quorum::Majority,
                validate: Quorum::Majority,
                compile: Quorum::Majority,
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
                compiler: BTreeSet::from(["Owner".to_owned()]),
            },
            policies_gov: PolicyGov {
                approve: Quorum::Majority,
                evaluate: Quorum::Majority,
                validate: Quorum::Majority,
                compile: Quorum::Majority,
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
                        "compiler": ["AveNode1"],
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
            compiler: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
                        "compiler": ["AveNode1"],
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
                compiler: BTreeSet::from(["Owner".to_owned()]),
            },
            policies_gov: PolicyGov {
                approve: Quorum::Majority,
                evaluate: Quorum::Majority,
                validate: Quorum::Majority,
                compile: Quorum::Majority,
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Fixed(100),
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Fixed(100),
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Fixed(100),
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
                "validator": ["AveNode1"],
                "compiler": ["AveNode1"]
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
    },
    "roles": {
        "governance": {
            "add": {
                "compiler": ["AveNode2"]
            }
        }
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
            compiler: BTreeSet::from([
                "AveNode1".to_owned(),
                "AveNode2".to_owned(),
                "Owner".to_owned(),
            ]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
                "validator": ["AveNode1"],
                "compiler": ["AveNode1"]
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
            compiler: BTreeSet::from([
                "AveNode2".to_owned(),
                "Owner".to_owned(),
            ]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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
            compiler: BTreeSet::from([
                "AveNode2".to_owned(),
                "Owner".to_owned(),
            ]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
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

    // SN 5 (fallido): quitar el rol compiler al Owner está protegido por
    // check_basic_gov, como el resto de roles básicos.
    let json = json!({
    "roles": {
        "governance": {
            "remove": {
                "compiler": ["Owner"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    // SN 6 (fallido): dar el rol compiler a un miembro que no existe.
    let json = json!({
    "roles": {
        "governance": {
            "add": {
                "compiler": ["NotAMember"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    // SN 7 (fallido): dar el rol compiler a AveNode2, que ya lo tiene.
    let json = json!({
    "roles": {
        "governance": {
            "add": {
                "compiler": ["AveNode2"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    // SN 8 (fallido): quitar el rol compiler a AveNode1, que ya no lo
    // tiene (se le quitó en el SN 3).
    let json = json!({
    "roles": {
        "governance": {
            "remove": {
                "compiler": ["AveNode1"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Los cuatro eventos commitean como fallidos: el sn avanza pero las
    // propiedades no cambian (compiler sigue siendo {AveNode2, Owner}).
    let state =
        get_subject(owner_governance, governance_id.clone(), Some(8), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 4);
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["AveNode2".to_owned(), "Owner".to_owned()])
    );

    // SN 9: se elimina al MIEMBRO AveNode2 (sin evento de roles). La
    // cascada de borrado (remove_member_role) debe quitarlo también del
    // rol compiler.
    let json = json!({
    "members": {
        "remove": ["AveNode2"]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(9), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 5);
    assert!(!properties.members.contains_key("AveNode2"));
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["Owner".to_owned()])
    );

    // SN 10: se devuelve el rol compiler a AveNode1 (nodo real). A partir
    // de aquí el quórum de compile Majority exige el 2/2: Owner compila
    // en local y AveNode1 por red.
    let json = json!({
    "roles": {
        "governance": {
            "add": {
                "compiler": ["AveNode1"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(10), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 6);
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["AveNode1".to_owned(), "Owner".to_owned()])
    );

    // Se sincroniza a AveNode1 antes de emitir: los siguientes facts
    // exigen su compile remoto contra la gov_version actual, y la
    // distribución a testigos no forma parte del ciclo de la request.
    get_subject(eval_node, governance_id.clone(), Some(10), true)
        .await
        .unwrap();

    // SN 11: se añade un schema con contrato. La fase compile exige el
    // 2/2, así que AveNode1 compila por red; el commit también en
    // AveNode1 (testigo de la gov) prueba que aplica el evento con la
    // evidencia de compilación remota.
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

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(11), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 7);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);

    let state = get_subject(eval_node, governance_id.clone(), Some(11), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 7);
    assert!(
        properties
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    // SN 12: cambio solo de initial_value. Los compilers resuelven el
    // contrato actual contra su estado local (misma gov_version que la
    // request), sin que el contrato viaje por red.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_initial_value": {
                    "one": 10,
                    "two": 20,
                    "three": 30
                }
            }]
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(12), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 8);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 10, "two": 20, "three": 30})
    );

    // AveNode1 tiene que estar al día antes del siguiente compile remoto.
    get_subject(eval_node, governance_id.clone(), Some(12), true)
        .await
        .unwrap();

    // SN 13 (fallido): cambiar el initial_value de un schema que no
    // existe. Los compilers votan InvalidEvent y el evento commitea
    // fallido sin pasar por evaluación: el sn avanza pero la versión y
    // los schemas no cambian, también en el testigo.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "NotASchema",
                "new_initial_value": {
                    "one": 1,
                    "two": 2,
                    "three": 3
                }
            }]
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(13), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 8);
    assert_eq!(properties.schemas.len(), 1);
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["AveNode1".to_owned(), "Owner".to_owned()])
    );

    let state = get_subject(eval_node, governance_id.clone(), Some(13), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 8);
    assert_eq!(properties.schemas.len(), 1);

    // SN 14: cambio solo de contrato. El source viaja en el propio
    // evento (la rama que faltaba de resolve_compile_targets) y el
    // initial_value commiteado se mantiene intacto, como exige la
    // aplicación del evento. Cambiar al mismo valor sería un evento
    // inválido, así que se usa la otra versión del contrato de ejemplo
    // (misma forma de estado, distinto hash).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(14), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 9);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT_V2);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 10, "two": 20, "three": 30})
    );

    // AveNode1 tiene que estar al día antes del siguiente compile remoto.
    get_subject(eval_node, governance_id.clone(), Some(14), true)
        .await
        .unwrap();

    // SN 15: un solo evento añade dos schemas. La evidencia de compile
    // cubre varios contratos a la vez (mapa ordenado: si no fuese
    // determinista, los compilers firmarían resultados distintos y el
    // quórum no cerraría).
    let json = json!({
        "schemas": {
            "add": [
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
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(15), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 10);
    assert_eq!(properties.schemas.len(), 3);
    assert!(
        properties
            .schemas
            .contains_key(&SchemaType::Type("Example2".to_owned()))
    );
    assert!(
        properties
            .schemas
            .contains_key(&SchemaType::Type("Example3".to_owned()))
    );

    let state = get_subject(eval_node, governance_id.clone(), Some(15), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 10);
    assert_eq!(properties.schemas.len(), 3);

    // SN 16: un mismo evento cambia un contrato y quita el rol compiler
    // a AveNode1. La fase compile se evalúa contra los roles ANTERIORES
    // al evento (quórum 2/2 con AveNode1 por red); tras el commit el set
    // de compilers queda reducido a {Owner}. El contrato vuelve a la
    // versión original (rollback).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT
            }]
        },
        "roles": {
            "governance": {
                "remove": {
                    "compiler": ["AveNode1"]
                }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(16), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 11);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["Owner".to_owned()])
    );

    // SN 17: con el set reducido a {Owner} la fase compile sigue
    // funcionando 1/1 (cambio solo de initial_value), también aplicado
    // en AveNode1 como testigo.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_initial_value": {
                    "one": 100,
                    "two": 200,
                    "three": 300
                }
            }]
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(17), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 12);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 100, "two": 200, "three": 300})
    );

    let state = get_subject(eval_node, governance_id.clone(), Some(17), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 12);
}

#[test(tokio::test)]
// Sin quórum de compile la request entra en RebootTimeOut y sale sola
// cuando el compiler vuelve: con compilers {Owner, AveNode2} y Majority
// se exige el 2/2, así que el commit final prueba que AveNode2 compiló
// por red tras recuperarse. No hace falta reemitir nada — los reboots
// por TimeOut son ilimitados (el schedule repite su último valor).
async fn test_gov_compile_quorum_unmet_reboots_and_recovers() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // Segundo nodo: compiler y testigo de la gobernanza.
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
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
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
                    "compiler": ["AveNode2"]
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

    // Con AveNode2 caído no hay quórum de compile: el fact con contrato
    // no puede commitear y la request entra en RebootTimeOut.
    let keys = node2.keys.clone();
    let local_db = node2_dirs[0].path().to_path_buf();
    let ext_db = node2_dirs[1].path().to_path_buf();

    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    // AveNode2 vuelve con las mismas claves y bases de datos: la propia
    // request sale del reboot y commitea (quórum 2/2 con compile remoto
    // de AveNode2).
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
// Una request atascada en la fase compile (compiler caído, sin quórum)
// se puede abortar manualmente con limpieza: el manager para los hijos
// de la fase, registra el abort y la gobernanza no avanza.
async fn test_gov_compile_request_aborted_manually() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
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
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
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
                    "compiler": ["AveNode2"]
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

    // Con AveNode2 caído la request no puede cerrar el quórum de
    // compile: se queda peleando con la fase.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    // Abort manual con la fase compile en vuelo.
    node1
        .manual_request_abort(governance_id.clone())
        .await
        .unwrap();

    wait_request_state(
        node1,
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

    let aborts = get_abort_request(node1, governance_id.clone(), request_id)
        .await
        .unwrap();
    assert_eq!(aborts.events.len(), 1);
    assert_eq!(
        aborts.events[0].error,
        "The user manually aborted the request"
    );

    // La gobernanza no ha avanzado: sigue en el SN 1.
    let state = get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
}

#[test(tokio::test)]
// Una request atascada en la fase de aprobación (aprobador caído, sin
// quórum) se puede abortar manualmente con limpieza: el manager para
// los hijos de la fase con reintentos de red en vuelo, registra el
// abort y la gobernanza no avanza.
async fn test_gov_approval_request_aborted_manually() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 pasa a ser aprobador y todo cambio de gobernanza
    // exige la aprobación de todos los aprobadores (fixed 100).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
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
                    "approver": ["AveNode2"]
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
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la aprobación no puede cerrar el quórum: la
    // fase se queda reintentando el envío de red.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    // El helper espera al estado Approval: la fase está en vuelo.
    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    // El owner aprueba; solo falta AveNode2, que está caído.
    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    // Abort manual con la fase de aprobación en vuelo.
    node1
        .manual_request_abort(governance_id.clone())
        .await
        .unwrap();

    wait_request_state(
        node1,
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

    let aborts = get_abort_request(node1, governance_id.clone(), request_id)
        .await
        .unwrap();
    assert_eq!(aborts.events.len(), 1);
    assert_eq!(
        aborts.events[0].error,
        "The user manually aborted the request"
    );

    // La gobernanza no ha avanzado: sigue en el SN 1.
    let state = get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
}

#[test(tokio::test)]
// Una request abortada a mitad de la fase compile nunca commitea: el
// abort barre su staging y reemitir el mismo cambio recompila y
// commitea con normalidad, sin colisiones con restos anteriores.
async fn test_gov_compile_abort_sweeps_staging_and_reemit_commits() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
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
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    // Con AveNode2 caído la request no puede cerrar el quórum de
    // compile: node1 compila a staging y se queda peleando con la fase.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    let request_id =
        emit_fact(&node1.api, governance_id.clone(), json.clone(), false)
            .await
            .unwrap();

    // Se espera a que el staging exista en disco (sondeo, como los
    // helpers).
    for _ in 0..100 {
        if !staging_dirs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(staging_dirs().len(), 1);

    // Abort manual con la fase compile en vuelo: barre el staging.
    node1
        .api
        .manual_request_abort(governance_id.clone())
        .await
        .unwrap();

    wait_request_state(
        &node1.api,
        request_id,
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    // El abort barrió el staging: la request nunca va a commitear.
    assert!(staging_dirs().is_empty());

    // AveNode2 vuelve y la reemisión del mismo cambio commitea.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    // El staging se promovió: no queda nada temporal y el artefacto
    // oficial existe.
    assert!(staging_dirs().is_empty());
    assert!(
        node1_contracts
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .exists()
    );
}

#[test(tokio::test)]
// Un nodo que cae a mitad de la fase compile deja staging huérfano en
// disco: al reiniciar la request se reanuda sola, reutiliza o
// recompila ese staging y commitea cuando el quórum vuelve.
async fn test_gov_compile_orphan_staging_survives_restart() {
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
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
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    // Con AveNode2 caído la request no puede cerrar el quórum de
    // compile: node1 compila a staging y se queda peleando con la fase.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Se espera a que el staging exista en disco (sondeo, como los
    // helpers).
    for _ in 0..100 {
        if !staging_dirs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(staging_dirs().len(), 1);

    // node1 cae a mitad de la fase compile: staging huérfano en disco.
    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    // node1 reinicia con los mismos datos: la request se reanuda sola.
    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    // El staging huérfano sobrevive al reinicio: la request reanudada
    // lo reutiliza o lo recompila.
    assert_eq!(staging_dirs().len(), 1);

    // AveNode2 vuelve: el quórum de compile se cierra y commitea.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    // El staging se promovió: no queda nada temporal y el artefacto
    // oficial existe.
    assert!(staging_dirs().is_empty());
    assert!(
        node1_contracts
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .exists()
    );
}

#[test(tokio::test)]
// El staging de una fase compile ya completada también se barre si el
// owner aborta la request más tarde, en la fase de aprobación: la
// request nunca commitea y sus artefactos temporales no pueden quedar
// en disco.
async fn test_gov_compile_staging_swept_on_approval_abort() {
    let node1_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: AveNode2 pasa a ser aprobador y todo cambio de gobernanza
    // exige la aprobación de todos los aprobadores (fixed 100).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
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
                    "approver": ["AveNode2"]
                }
            }
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la aprobación no puede cerrar el quórum.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    // La compile y la evaluación sí completan: el staging queda
    // escrito y la fase de aprobación se queda en vuelo.
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

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    assert_eq!(staging_dirs().len(), 1);

    // Abort manual con la fase de aprobación en vuelo y el staging ya
    // escrito: el barrido también aplica.
    node1
        .api
        .manual_request_abort(governance_id.clone())
        .await
        .unwrap();

    wait_request_state(
        &node1.api,
        request_id,
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    assert!(staging_dirs().is_empty());

    // La gobernanza no ha avanzado: sigue en el SN 1.
    let state = get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
}

#[test(tokio::test)]
// Un cambio de contrato que compila y evalúa bien pero se rechaza en
// aprobación commitea sin aplicar: su staging se barre y el contrato
// oficial sigue siendo el anterior, así que el sujeto sigue evaluando
// con el contrato numérico original.
async fn test_gov_compile_staging_swept_on_approval_reject() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = |dir: &tempfile::TempDir| -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: esquema con el contrato numérico, sus roles, y AveNode2 de
    // compiler y testigo. Con 2 compilers y quórum Majority la fase
    // compile exige el visto bueno de ambos: los dos stagean.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
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
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
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
                                "quantity": "infinity"
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

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    // Sujeto del esquema: un evento numérico funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // SN 2: cambio a un contrato de strings. Compila y evalúa bien en
    // ambos compilers (los dos tienen staging), pero la aprobación lo
    // rechaza.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": CHANGED_SCHEMA_CONTRACT,
                    "new_initial_value": {
                        "data": "hola"
                    }
                }
            ]
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    assert_eq!(staging_dirs(&node1_contracts).len(), 1);
    assert_eq!(staging_dirs(&node2_contracts).len(), 1);

    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id,
        true,
    )
    .await
    .unwrap();

    // El evento commitea rechazado: el staging se barre y el contrato
    // no cambia.
    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert!(staging_dirs(&node1_contracts).is_empty());

    // El barrido es de todos los nodos que aplican el evento, no solo
    // del requester: AveNode2 aplica el evento al sincronizarse y su
    // staging también desaparece.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert!(staging_dirs(&node2_contracts).is_empty());

    // El contrato oficial sigue siendo el numérico: el evento de
    // números sigue funcionando.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 200 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
}

#[test(tokio::test)]
// Un cambio que solo toca el initial_value reutiliza el artefacto oficial
// (no hay contrato nuevo que compilar): si el nuevo valor no pasa el init
// check del contrato, el veredicto es un fallo determinista — recompilar
// el mismo source fallaría igual — y el evento commitea fallido sin tocar
// el esquema ni el artefacto.
async fn test_gov_compile_invalid_init_only_change_fails_event() {
    let node1_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: esquema con el contrato numérico y sus roles.
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
                                "quantity": "infinity"
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Sujeto del esquema: un evento numérico funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // SN 2 (fallido): cambio solo de initial_value, con un tipo que el
    // contrato no acepta (`one` es u32). La fase compile valida el nuevo
    // valor contra el artefacto oficial y vota el fallo.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_initial_value": {
                        "one": "abc",
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    // El evento commitea fallido: el sn avanza pero la versión y el
    // esquema no cambian.
    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 1);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 0, "two": 0, "three": 0})
    );

    // Sin contrato nuevo no hay staging: nada que barrer y el artefacto
    // oficial sigue intacto.
    let staging: Vec<_> = fs::read_dir(node1_contracts.path())
        .unwrap()
        .filter_map(|entry| {
            let name =
                entry.unwrap().file_name().to_string_lossy().into_owned();
            name.contains("_temp_staging_").then_some(name)
        })
        .collect();
    assert!(staging.is_empty());
    assert!(
        node1_contracts
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .join("contract.cwasm")
            .exists()
    );

    // El artefacto oficial sigue sirviendo: el evento de números funciona.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 200 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
}

#[test(tokio::test)]
// Si el artefacto precompilado (contract.cwasm) está corrupto pero el
// wasm persiste íntegro, la primera evaluación tras rearrancar el nodo
// (sin el módulo cacheado en memoria) se autocura: precompila desde el
// wasm, vuelve a persistir el precompilado y el evento se evalúa con
// normalidad, sin pedir nada a la red.
async fn test_contract_cwasm_corruption_falls_back_to_wasm() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: esquema con el contrato numérico y sus roles.
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
                                "quantity": "infinity"
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Sujeto del esquema: un evento numérico funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // El módulo compilado queda cacheado en memoria tras el primer uso:
    // el fallback de disco solo se ejerce cuando el nodo arranca sin esa
    // caché. Se para el nodo, se corrompe el precompilado (el wasm, que
    // es la fuente de verdad del artefacto, no se toca) y se rearranca
    // con las mismas claves y bases de datos.
    let artifact_dir = node1_contracts
        .path()
        .join("contracts")
        .join(format!("{}_Example", governance_id));
    let cwasm_path = artifact_dir.join("contract.cwasm");
    assert!(cwasm_path.exists());

    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    fs::write(&cwasm_path, b"corrupted").unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    // La evaluación carga el contrato desde disco: el precompilado no
    // deserializa, se cae al wasm, se regenera el precompilado y el
    // evento se aplica con normalidad, sin pedir nada a la red.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 200 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    // Autocuración: el fallback vuelve a persistir el precompilado, así
    // que el fichero corrupto ha sido reemplazado.
    let healed = fs::read(&cwasm_path).unwrap();
    assert_ne!(healed, b"corrupted");
}

#[test(tokio::test)]
// Un alta de schema cuyo contrato compila pero cuyo initial_value no
// pasa el init check falla en la fase compile después de stagear: el
// evento commitea fallido y no queda residuo en disco — ni staging ni
// artefacto oficial.
async fn test_gov_compile_failed_add_leaves_no_artifacts() {
    let node1_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1 (fallido): el contrato compila pero `one` es u32 y llega un
    // string: el init check falla contra el artefacto stageado.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": "abc",
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    // El evento commitea fallido: el sn avanza pero la versión no y no
    // hay schemas.
    let state = get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 0);
    assert!(properties.schemas.is_empty());

    // Sin residuo en disco: el staging se barre al commitear fallido y
    // no se crea artefacto oficial.
    let staging: Vec<_> = fs::read_dir(node1_contracts.path())
        .unwrap()
        .filter_map(|entry| {
            let name =
                entry.unwrap().file_name().to_string_lossy().into_owned();
            name.contains("_temp_staging_").then_some(name)
        })
        .collect();
    assert!(staging.is_empty());
    assert!(
        !node1_contracts
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .exists()
    );
}

#[test(tokio::test)]
// Si los dos ficheros del artefacto (wasm y precompilado) están corruptos
// no hay fallback local posible: la primera evaluación tras rearrancar el
// nodo detecta el hash mismatch y recompila desde el source del schema,
// regenerando los artefactos, y el evento se aplica con normalidad.
async fn test_contract_full_artifact_corruption_recompiles_on_boot() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: esquema con el contrato numérico y sus roles.
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
                                "quantity": "infinity"
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Sujeto del esquema: un evento numérico funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // Corrupción total con el nodo parado (sin la caché en memoria): ni
    // el precompilado ni el wasm sobreviven íntegros.
    let artifact_dir = node1_contracts
        .path()
        .join("contracts")
        .join(format!("{}_Example", governance_id));
    let wasm_path = artifact_dir.join("contract.wasm");
    let cwasm_path = artifact_dir.join("contract.cwasm");
    assert!(wasm_path.exists());
    assert!(cwasm_path.exists());

    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    fs::write(&wasm_path, b"corrupted").unwrap();
    fs::write(&cwasm_path, b"corrupted").unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    // La evaluación carga el contrato desde disco: ambos artefactos
    // fallan su hash, se recompila desde el source y el evento se aplica
    // con normalidad.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 200 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    // La recompilación vuelve a persistir los artefactos: los ficheros
    // corruptos han sido reemplazados.
    let healed_wasm = fs::read(&wasm_path).unwrap();
    assert_ne!(healed_wasm, b"corrupted");
    let healed_cwasm = fs::read(&cwasm_path).unwrap();
    assert_ne!(healed_cwasm, b"corrupted");
}

#[test(tokio::test)]
// Un fallo de disco al promover el staging a oficial durante el commit
// es un fallo local fatal: el nodo cae controlado en vez de quedarse
// reintentando para siempre.
async fn test_gov_compile_promotion_disk_failure_is_fatal() {
    use std::os::unix::fs::PermissionsExt;

    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: esquema con contrato y AveNode2 de compiler y testigo.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
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
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    // Con AveNode2 caído la request se queda peleando con la fase
    // compile tras escribir el staging.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Se espera a que el staging exista en disco (sondeo, como los
    // helpers).
    for _ in 0..100 {
        if !staging_dirs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(staging_dirs().len(), 1);

    // Disco roto en caliente: el directorio de contratos queda sin
    // permisos de escritura, así que el rename de la promoción fallará.
    fs::set_permissions(
        node1_contracts.path(),
        fs::Permissions::from_mode(0o555),
    )
    .unwrap();

    // AveNode2 vuelve: el quórum se cierra y el commit intenta la
    // promoción con el disco roto.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    // Un nodo que no puede hacer su trabajo es un nodo muerto: el fallo
    // de disco en la promoción tumba el nodo entero de forma controlada.
    join_all(node1.handler.iter_mut()).await;

    // Restaurar permisos para que el TempDir pueda limpiarse al salir.
    fs::set_permissions(
        node1_contracts.path(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

#[test(tokio::test)]
// Un staging corrompido en disco entre la compile y el commit (bitrot,
// escritura parcial) no rompe al nodo: el evento commitea y en la
// siguiente evaluación la lectura detecta el mismatch de hash y
// recompila, autorrecuperándose.
async fn test_gov_compile_staging_corruption_self_heals() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
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
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    // Con AveNode2 caído la request se queda peleando con la fase
    // compile tras escribir el staging.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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
                                "quantity": "infinity"
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

    emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Se espera a que el staging exista en disco (sondeo, como los
    // helpers).
    for _ in 0..100 {
        if !staging_dirs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let staging = staging_dirs();
    assert_eq!(staging.len(), 1);

    // El wasm staged se corrompe antes de que el evento commitee.
    fs::write(
        node1_contracts
            .path()
            .join(&staging[0])
            .join("contract.wasm"),
        b"corrupted",
    )
    .unwrap();

    // AveNode2 vuelve: el quórum se cierra y el evento commitea con el
    // artefacto corrompido promovido.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert!(staging_dirs().is_empty());

    // La primera evaluación lee el artefacto oficial corrompido,
    // detecta el mismatch de hash y recompila: el nodo se
    // autorrecupera y el sujeto funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
}

#[test(tokio::test)]
// Un evento que añade dos schemas con contratos distintos genera dos
// stagings: si la request se aborta, el barrido los elimina todos.
async fn test_gov_compile_abort_sweeps_every_staging() {
    let node1_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
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
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    // Con AveNode2 caído la request se queda peleando con la fase
    // compile tras escribir los stagings.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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
                },
                {
                    "id": "ExampleV2",
                    "contract": EXAMPLE_CONTRACT_V2,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Se espera a que ambos stagings existan en disco (sondeo, como
    // los helpers).
    for _ in 0..100 {
        if staging_dirs().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(staging_dirs().len(), 2);

    // Abort manual con la fase compile en vuelo: barre los dos
    // stagings.
    node1
        .api
        .manual_request_abort(governance_id.clone())
        .await
        .unwrap();

    wait_request_state(
        &node1.api,
        request_id,
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    assert!(staging_dirs().is_empty());

    // La gobernanza no ha avanzado: sigue en el SN 1.
    let state = get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
}

#[test(tokio::test)]
// El artefacto compilado en la fase compile queda en staging hasta que
// el evento commitea: si el commit es exitoso se promueve al slot
// oficial y el staging desaparece (sin recompilar); si el evento
// commitea fallido, el staging se borra y el artefacto nunca se vuelve
// oficial.
async fn test_gov_compile_staging_promoted_and_swept() {
    let contracts_dir = tempfile::tempdir().unwrap();
    let (node, _dirs) = create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    let temp_staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(contracts_dir.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1 (exitoso): se añade un schema con contrato. La fase compile
    // deja el artefacto en staging y, al commitear, se promueve al slot
    // oficial: el staging desaparece.
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

    assert!(
        contracts_dir
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .exists(),
        "el artefacto promovido debe existir en el slot oficial"
    );
    assert!(
        temp_staging_dirs().is_empty(),
        "tras el commit exitoso no debe quedar staging: {:?}",
        temp_staging_dirs()
    );

    // SN 2 (fallido): se añade otro schema con contrato (se compila y
    // queda en staging) pero el evento también da el rol compiler a un
    // miembro que no existe, así que la evaluación lo rechaza. El
    // evento commitea fallido: el staging se borra y el artefacto de
    // Example2 nunca llega al slot oficial.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example2",
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
                    "compiler": ["NotAMember"]
                }
            }
        }
    });

    emit_fact(&node.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    let state = get_subject(&node.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 1);
    assert_eq!(properties.schemas.len(), 1);

    assert!(
        temp_staging_dirs().is_empty(),
        "tras el commit fallido no debe quedar staging: {:?}",
        temp_staging_dirs()
    );
    assert!(
        !contracts_dir
            .path()
            .join("contracts")
            .join(format!("{}_Example2", governance_id))
            .exists(),
        "el artefacto de un evento fallido no debe ser oficial"
    );
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
                    },
                    "compile": {
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Fixed(1),
            validate: Quorum::Fixed(1),
            compile: Quorum::Fixed(1),
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Fixed(1),
            validate: Quorum::Fixed(1),
            compile: Quorum::Majority,
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
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Fixed(1),
            validate: Quorum::Fixed(1),
            compile: Quorum::Majority,
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
// Un compilador con el pool caído responde `Unavailable` y no arrastra
// la request: el quorum de compilación (Majority de 3 = 2) se cierra con
// el resto de compiladores y el fact de gobernanza con contrato se
// confirma.
async fn test_gov_compiler_unavailable_quorum_holds() {
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
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);    let (node3, mut node3_dirs) = create_node(CreateNodeConfig {
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

    // SN 1: los tres nodos pasan a ser evaluadores, witnesses y
    // compiladores de la gobernanza. Este fact no añade contratos, así
    // que no necesita compilación y lo evalúa el Owner (quorum Majority
    // de 1 evaluador y 1 compilador).
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
                    "evaluator": ["AveNode2", "AveNode3"],
                    "compiler": ["AveNode2", "AveNode3"]
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

    // SN 2: fact que añade un schema con contrato. La fase de compilación
    // exige quorum Majority de 3 compiladores (2): node3 no puede compilar
    // y responde `Unavailable`, pero el quorum se cierra con node1 y
    // node2. La evaluación posterior es nativa y no toca el pool.
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
// Si el quorum de compilación es inalcanzable porque un compilador no
// está disponible, la request no se pierde ni se marca inválida: entra en
// RebootTimeOut y el nodo emisor sigue operativo.
async fn test_gov_compiler_unavailable_quorum_fails_reboot() {
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

    // SN 1: node2 pasa a ser evaluador, witness y compilador. Con 2
    // compiladores y quorum Majority la fase de compilación exige el
    // visto bueno de ambos.
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
                    "evaluator": ["AveNode2"],
                    "compiler": ["AveNode2"]
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

    // Fact con contrato: node1 compila correctamente pero node2 responde
    // `Unavailable` (pool muerto); sin quorum de compilación la request
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
// (firma de atestación inválida), el nodo responde `Unavailable` en la
// fase de compilación sin emitir veredicto y, al no cerrarse el quorum,
// la request entra en RebootTimeOut en lugar de perderse. Ambos nodos
// siguen operativos.
async fn test_gov_compiler_wrong_pin_unavailable_reboot() {
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

    // SN 1: node2 pasa a ser evaluador, testigo y compilador. Con 2
    // compiladores y quorum Majority la compilación exige el visto
    // bueno de ambos.
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
                    "evaluator": ["AveNode2"],
                    "compiler": ["AveNode2"]
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

    // Fact con contrato: node1 compila correctamente pero las respuestas
    // del compilador de node2 se descartan por el pin; sin quorum de
    // compilación la request entra en RebootTimeOut.
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
// La compilación con el pool caído degrada la evaluación sin tumbar el
// nodo: mientras node3 no dispone del artefacto responde `Unavailable`,
// el quorum se cierra con el resto de evaluadores y el nodo sigue
// aplicando el ledger como testigo. Tras commitear el evento, node3
// intenta reponer el artefacto por fetch desde los compiladores de la
// red, así que la degradación puede ser transitoria.
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
    // cierra con node1 y node2. Al commitear, node3 no puede compilar
    // (pool muerto) y arranca el fetch del artefacto desde un compilador
    // de la red; hasta que el fetch termina sigue sin artefacto local.
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

    // Creación del subject: si node3 aún no ha terminado el fetch
    // responde `Unavailable` (contrato no encontrado) y el quorum se
    // cierra con node1 y node2; si ya lo tiene, evalúa con normalidad.
    // En ambos casos el evento commitea.
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

    // El fact commitea con independencia de si node3 ya recuperó el
    // artefacto por fetch (quorum Majority: basta 2 de 3 evaluadores).
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

    // El nodo sigue vivo y aplica el ledger como testigo.
    let state = get_subject(node3, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));
}

#[test(tokio::test)]
// Un evaluador con el pool muerto no queda bloqueado tras un cambio de
// contrato: al commitear el evento registra el ancla de compilación de
// la nueva versión y repone el artefacto por fetch desde los
// compiladores de la red (verificado contra el ancla), volviendo a
// evaluar con el quorum completo.
async fn test_evaluator_with_dead_pool_fetches_contract_and_evaluates() {
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
    // el escenario cambia: el nodo arrancaría ya sin artefacto).
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
    // Lo evalúa el Owner únicamente. Al commitear, node2 registra el
    // ancla de compilación de la v2 y, como no puede recompilar (pool
    // muerto), arranca el fetch del artefacto desde node1.
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

    // Sincronizar node2: al aplicar SN 2 arranca el fetch de la v2.
    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // ModThree=50 solo es válido con la v2 y el quorum Majority con 2
    // evaluadores exige el visto bueno de ambos. Si node2 aún no ha
    // terminado el fetch responde `Unavailable` y la request reintenta
    // hasta que dispone del artefacto: el evento solo commitea cuando
    // node2 evalúa con la v2 verificada contra el ancla.
    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 0, "three": 50}));

    // node2 commiteó el evento: evaluó con la v2 obtenida por fetch.
    let state = get_subject(node2, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 0, "three": 50}));

    // El artefacto fetcheado quedó persistido en el directorio de
    // contratos preservado de node2.
    assert!(
        contracts_dir
            .path()
            .join("contracts")
            .join(format!("{governance_id}_Example"))
            .exists()
    );

    // El evaluador recuperado sigue operativo.
    node_running(node2).await.unwrap();
}

#[test(tokio::test)]
// Un fallo local fatal durante la compilación pre-commit de un contrato
// (el disco no puede persistir el staging) no se degrada: el nodo se
// baja controladamente, el evento no commitea y, con el disco aún roto,
// el reinicio se niega a arrancar en modo degradado.
async fn test_gov_contract_refresh_disk_failure_restart_is_fatal() {
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

    // SN 1: schema "Example" con la v1 del contrato.
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

    // Disco roto en caliente: los artefactos desaparecen y el directorio
    // queda sin permisos de escritura.
    fs::remove_dir_all(contracts_dir.path().join("contracts")).unwrap();
    fs::set_permissions(
        contracts_dir.path(),
        fs::Permissions::from_mode(0o555),
    )
    .unwrap();

    // SN 2: cambio de contrato a la v2. La compilación es pre-commit: el
    // worker intenta crear el staging con el disco roto, un fallo local
    // fatal. Se emite async porque el nodo entero se baja justo después.
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
    emit_fact(&node.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Un nodo que no puede hacer su trabajo es un nodo muerto: el fallo
    // de disco tumba el nodo entero (no solo la gobernanza) y el evento
    // no llega a commitear.
    join_all(node.handler.iter_mut()).await;

    // Con el disco aún roto el nodo no debe arrancar degradado: el fallo
    // local fatal vuelve a aparecer al recuperar los artefactos en el
    // arranque.
    let result = try_create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(node.keys.clone()),
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
            panic!("node booted degraded with a read-only contracts directory")
        }
    }
}

#[test(tokio::test)]
// Un compilador degradado se recupera al reiniciar con un pool sano:
// vuelve a compilar en la fase de compilación y la request sale del
// reboot. El quorum Majority exige a los dos compiladores, así que el
// commit del fact prueba que el nodo recuperado participa de nuevo.
async fn test_gov_compiler_recovers_after_pool_restart() {
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

    // SN 1: node2 pasa a ser evaluador, testigo y compilador. Con 2
    // compiladores y quorum Majority la compilación exige el visto
    // bueno de ambos.
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
                    "evaluator": ["AveNode2"],
                    "compiler": ["AveNode2"]
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

    // Intento de fact con contrato: node2 no puede compilar (pool
    // muerto), el quorum de compilación no se cierra y la request entra
    // en RebootTimeOut.
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

    // Reinicio con el pool sano (el embebido autoinyectado): node2
    // vuelve a compilar en la fase de compilación.
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
    // commitea: como el quorum de compilación exige el voto de node2, el
    // commit prueba la recuperación. No hace falta reemitir nada — los
    // reboots por TimeOut son ilimitados (el schedule repite su último
    // valor).
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

#[test(tokio::test)]
// Un evaluador de gobernanza SIN rol compiler y con el pool muerto evalúa
// y vota eventos de gobernanza (incluido un alta de schema que compilan
// OTROS nodos): la evaluación de gobernanza es código nativo y nunca toca
// el pool. El quorum Majority con 2 evaluadores exige ambos votos, así que
// el commit prueba que AveNode2 evaluó con el pool caído.
async fn test_gov_evaluator_dead_pool_votes_schema_add() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // AveNode2: evaluador y testigo de gobernanza con el pool muerto.
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
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 pasa a ser evaluador y testigo de la gobernanza.
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

    // SN 2: alta del schema con contrato. Lo compila el Owner (único
    // compiler); la evaluación de gobernanza exige el voto de AveNode2,
    // que evalúa nativamente con su pool muerto.
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
    let state = get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// Un cambio de schema que solo toca viewpoints (sin contrato ni
// initial_value) no pasa por la fase de compilación: con el pool muerto
// tras el reinicio el evento commitea igualmente y el schema sigue
// evaluando con el artefacto persistido.
async fn test_gov_viewpoints_only_change_no_compile_dead_pool() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (mut node1, mut node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: schema "Example" con viewpoints iniciales y sus roles.
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
                    "viewpoints": ["base"]
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Reinicio con el pool muerto conservando claves, bases de datos y el
    // directorio de contratos (el artefacto v1 carga de disco).
    let keys = node1.keys.clone();
    let local_db = node1_dirs[0].path().to_path_buf();
    let ext_db = node1_dirs[1].path().to_path_buf();

    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    let (node1, mut node1_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
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
    node1_dirs.append(&mut node1_dirs_new);
    node_running(&node1.api).await.unwrap();

    // SN 2: cambio solo de viewpoints. Nada que compilar: el evento
    // commitea con el pool muerto.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_viewpoints": ["agua"]
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    let schema = gov
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.viewpoints, BTreeSet::from(["agua".to_owned()]));

    // El schema sigue evaluando con el artefacto persistido.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    node_running(&node1.api).await.unwrap();
}

#[test(tokio::test)]
// Un cambio solo de initial_value con el pool muerto y el artefacto
// oficial sano reutiliza los bytes persistidos: la fase de compilación
// revalida el nuevo init contra el artefacto en disco, el evento commitea
// sin ninguna build (el pool muerto lo prueba: cualquier llamada al pool
// impediría el commit) y el ancla no se mueve (mismo wasm tras el commit).
async fn test_gov_init_only_change_reuses_artifact_dead_pool() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (mut node1, mut node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: schema "Example" con la v1 del contrato.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let wasm_path = contracts_dir
        .path()
        .join("contracts")
        .join(format!("{governance_id}_Example"))
        .join("contract.wasm");
    let wasm_before = fs::read(&wasm_path).unwrap();

    // Reinicio con el pool muerto conservando claves, bases de datos y el
    // directorio de contratos.
    let keys = node1.keys.clone();
    let local_db = node1_dirs[0].path().to_path_buf();
    let ext_db = node1_dirs[1].path().to_path_buf();

    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    let (node1, mut node1_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
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
    node1_dirs.append(&mut node1_dirs_new);
    node_running(&node1.api).await.unwrap();

    // SN 2: cambio solo de initial_value. El worker revalida el nuevo
    // valor contra el artefacto persistido y commitea sin tocar el pool.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_initial_value": {
                        "one": 1,
                        "two": 2,
                        "three": 3
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert_eq!(gov.version, 2);
    let schema = gov
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 1, "two": 2, "three": 3})
    );

    // El ancla no se movió: el wasm oficial es byte a byte el mismo.
    let wasm_after = fs::read(&wasm_path).unwrap();
    assert_eq!(wasm_before, wasm_after);

    node_running(&node1.api).await.unwrap();
}

#[test(tokio::test)]
// Un mismo evento que da de alta dos schemas con la MISMA fuente de
// contrato promueve ambos artefactos (staging nombrado por schema) y
// ambos schemas evalúan con normalidad.
async fn test_gov_compile_same_source_two_schemas() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: dos schemas con la misma fuente de contrato en un evento.
    let schema_roles = |schema_id: &str| {
        json!({
            "schema_id": schema_id,
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
        })
    };

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "ExampleA",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "ExampleB",
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
                schema_roles("ExampleA"),
                schema_roles("ExampleB")
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("ExampleA".to_owned()))
    );
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("ExampleB".to_owned()))
    );

    // Ambos artefactos quedaron promovidos.
    for schema_id in ["ExampleA", "ExampleB"] {
        assert!(
            contracts_dir
                .path()
                .join("contracts")
                .join(format!("{governance_id}_{schema_id}"))
                .join("contract.cwasm")
                .exists()
        );
    }

    // Y ambos schemas evalúan.
    for (schema_id, value) in [("ExampleA", 1), ("ExampleB", 2)] {
        let (subject_id, ..) = create_subject(
            &node1.api,
            governance_id.clone(),
            schema_id,
            "",
            true,
        )
        .await
        .unwrap();

        emit_fact(
            &node1.api,
            subject_id.clone(),
            json!({"ModOne": {"data": value}}),
            true,
        )
        .await
        .unwrap();

        let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
            .await
            .unwrap();
        assert_eq!(
            state.properties,
            json!({"one": value, "two": 0, "three": 0})
        );
    }

    node_running(&node1.api).await.unwrap();
}

#[test(tokio::test)]
// Un cambio solo de initial_value con el artefacto oficial borrado del
// disco fuerza una recompilación verificada contra el ancla del ledger:
// la build reproduce los bytes anclados, la ronda cierra Ok y el ancla no
// se mueve (el wasm repuesto es byte a byte el original).
async fn test_gov_init_only_change_missing_artifact_recompiles_anchored() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: schema "Example" con la v1 del contrato.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_dir = contracts_dir
        .path()
        .join("contracts")
        .join(format!("{governance_id}_Example"));
    let wasm_before = fs::read(artifact_dir.join("contract.wasm")).unwrap();

    // El artefacto oficial desaparece del disco en caliente.
    fs::remove_dir_all(&artifact_dir).unwrap();

    // SN 2: cambio solo de initial_value. El worker no encuentra el
    // artefacto, recompila desde el pool y la verificación contra el
    // ancla pasa: la build es determinista y reproduce los bytes
    // anclados.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_initial_value": {
                        "one": 5,
                        "two": 6,
                        "three": 7
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert_eq!(gov.version, 2);
    let schema = gov
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 5, "two": 6, "three": 7})
    );

    // El ancla no se movió: el artefacto repuesto reproduce los bytes
    // originales.
    let wasm_after = fs::read(artifact_dir.join("contract.wasm")).unwrap();
    assert_eq!(wasm_before, wasm_after);

    node_running(&node1.api).await.unwrap();
}

// Espera acotada a que el artefacto wasm de un schema exista en disco y
// devuelve sus bytes.
async fn wait_artifact_bytes(
    contracts_path: &std::path::Path,
    artifact_name: &str,
) -> Vec<u8> {
    let path = contracts_path
        .join("contracts")
        .join(artifact_name)
        .join("contract.wasm");
    for _ in 0..100 {
        if let Ok(bytes) = fs::read(&path) {
            return bytes;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("timeout waiting for artifact {}", path.display());
}

#[test(tokio::test)]
// Al commitear un cambio de contrato TODOS los nodos que aplican el
// evento registran el ancla, incluidos testigos sin rol de evaluador ni
// compilador: el testigo pasa a evaluador DESPUÉS del commit y su fetch
// se verifica contra el ancla que registró cuando era solo testigo.
async fn test_anchor_recorded_on_witness_without_roles() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let node2_contracts = tempfile::tempdir().unwrap();
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 es solo testigo de la gobernanza. El schema v1 se
    // crea con roles del Owner únicamente.
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

    // SN 2: cambio de contrato a la v2. AveNode2 lo aplica como simple
    // testigo y registra el ancla de la v2.
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

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3: AveNode2 pasa a ser evaluador del schema. Al aplicar el
    // evento necesita el artefacto v2: lo pide a la red y lo verifica
    // contra el ancla que registró cuando era testigo.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "witness": [
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // El fetch verificado contra el ancla termina: el artefacto v2 está
    // en disco en AveNode2.
    let artifact_name = format!("{governance_id}_Example");
    let node2_v2 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert!(!node2_v2.is_empty());

    // Un fact solo válido con la v2 (ModThree=50) commitea con el quorum
    // de 2 evaluadores: prueba que AveNode2 evalúa con la v2.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    let state = get_subject(&node2.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// El ancla sobrevive a perder y recuperar el rol de evaluador sin eventos
// intermedios: si el artefacto local desapareció, la recuperación del rol
// relanza el fetch verificado contra el ancla conservada.
async fn test_fetch_anchor_survives_role_loss_and_regain() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let node1_contracts = tempfile::tempdir().unwrap();
    let _keep_node1_contracts = &node1_contracts;

    let node2_contracts = tempfile::tempdir().unwrap();
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 evaluador y testigo del schema v1.
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

    // AveNode2 dispone del artefacto v1 (fetcheado del Owner).
    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: AveNode2 pierde el rol de evaluador. El ancla se conserva.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "evaluator": [
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El artefacto local desaparece del disco (el ancla sigue en el
    // registro).
    fs::remove_dir_all(
        node2_contracts.path().join("contracts").join(&artifact_name),
    )
    .unwrap();

    // SN 3: AveNode2 recupera el rol. Sin evento de contrato intermedio:
    // el fetch se relanza contra el ancla conservada.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // El refetch trae los mismos bytes anclados.
    let node2_v1_again =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v1, node2_v1_again);

    // Y evalúa: un fact commitea con el quorum de 2 evaluadores.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 9}}),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 9, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// Perder y recuperar el rol de evaluador conserva ancla Y bytes: la
// recuperación carga el artefacto local sin red. El commit final exige
// el voto de AveNode2 con la red inservible para él (Owner caído y el
// otro evaluador sirviendo basura), así que prueba que no hubo refetch.
async fn test_fetch_role_regain_local_first_no_network() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let node3_contracts = tempfile::tempdir().unwrap();
    let (node3, mut node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node3_dirs);
    node_running(&node3.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api, &node3.api])
            .await;

    // SN 1: AveNode2 y AveNode3 evaluadores (quorum Majority = 2 de 3);
    // AveNode3 además emisor.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"]
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
                            },
                            {
                                "name": "AveNode3",
                                "namespace": [],
                                "quantity": 10
                            }
                        ],
                        "issuer": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ]
                    }
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
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Subject de AveNode3 (es quien emite el fact final con el Owner
    // caído: los facts de tracker solo los emite el dueño del subject)
    // y un fact v1: todos evalúan.
    let (subject_id, ..) = create_subject(
        &node3.api,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    get_subject(&node3.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        &node3.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    get_subject(&node3.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2 y SN 3: AveNode2 pierde y recupera el rol de evaluador. Sus
    // bytes no se tocan.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "evaluator": [
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // La red queda inservible para un refetch de AveNode2: el Owner se
    // apaga y el artefacto en disco de AveNode3 se corrompe (su caché de
    // serving está vacía: nunca ha servido).
    nodes[0].token.cancel();
    let mut owner = std::mem::take(&mut nodes[0].handler);
    join_all(owner.iter_mut()).await;

    let artifact_name = format!("{governance_id}_Example");
    fs::write(
        node3_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .join("contract.wasm"),
        b"garbage",
    )
    .unwrap();

    // AveNode3 emite un fact: el quorum exige a AveNode2, que solo puede
    // votar si evalúa con su artefacto LOCAL (cargado sin red).
    emit_fact(
        &node3.api,
        subject_id.clone(),
        json!({"ModTwo": {"data": 5}}),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(&node3.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 5, "three": 0}));

    let state = get_subject(&node2.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 5, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// Un evento que cambia el contrato de un schema y elimina OTRO schema a
// la vez: solo el schema vivo se promueve y ancla; el eliminado
// desaparece de las propiedades.
async fn test_gov_compile_change_and_remove_schema_same_event() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    let schema_roles = |schema_id: &str| {
        json!({
            "schema_id": schema_id,
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
        })
    };

    // SN 1: dos schemas con contrato.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "ExampleA",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "ExampleB",
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
                schema_roles("ExampleA"),
                schema_roles("ExampleB")
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: un solo evento cambia el contrato de ExampleA a la v2 y
    // elimina ExampleB.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "ExampleA",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }
            ],
            "remove": ["ExampleB"]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert_eq!(gov.version, 2);

    let schema_a = gov
        .schemas
        .get(&SchemaType::Type("ExampleA".to_owned()))
        .expect("el schema ExampleA debe existir");
    assert_eq!(schema_a.contract, EXAMPLE_CONTRACT_V2);
    assert!(
        !gov.schemas
            .contains_key(&SchemaType::Type("ExampleB".to_owned()))
    );

    // El artefacto promovido de ExampleA es el de la v2.
    let artifact_a = wait_artifact_bytes(
        contracts_dir.path(),
        &format!("{governance_id}_ExampleA"),
    )
    .await;
    assert!(!artifact_a.is_empty());

    // ExampleA evalúa con la v2 (ModThree=50 solo es válido en la v2).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "ExampleA", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node1.api).await.unwrap();
}

#[test(tokio::test)]
// La política de compilación Percentage(50) se respeta: con 4 compilers
// basta 1 firma de cada 2 (2 de 4) para commitear un alta de schema, y
// con solo 1 de 4 la request entra en RebootTimeOut sin commitear.
async fn test_gov_compile_quorum_percentage() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let mut compiler_nodes = Vec::new();
    for _ in 0..3 {
        let (node, mut node_dirs) = create_node(CreateNodeConfig {
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
            ..Default::default()
        })
        .await;
        dirs.append(&mut node_dirs);
        node_running(&node.api).await.unwrap();
        compiler_nodes.push(node);
    }

    let governance_id = create_and_authorize_governance(
        node1,
        compiler_nodes.iter().map(|n| &n.api).collect(),
    )
    .await;

    // SN 1: los tres nodos nuevos son compilers y testigos (4 compilers
    // en total contando al Owner).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": compiler_nodes[0].api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": compiler_nodes[1].api.public_key()
                },
                {
                    "name": "AveNode4",
                    "key": compiler_nodes[2].api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3", "AveNode4"],
                    "compiler": ["AveNode2", "AveNode3", "AveNode4"]
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

    for node in &compiler_nodes {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    // SN 2: política de compilación Percentage(50): con 4 compilers el
    // quorum son 2 firmas.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "compile": {
                        "percentage": 50
                    }
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    for node in &compiler_nodes {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    }

    // Caen AveNode3 y AveNode4: quedan 2 de 4 compilers, justo el 50%.
    for node in &compiler_nodes[1..] {
        node.token.cancel();
    }
    join_all(
        compiler_nodes[1..]
            .iter_mut()
            .flat_map(|n| n.handler.iter_mut()),
    )
    .await;

    // SN 3: alta de schema con contrato. El quorum Percentage(50) se
    // cubre con Owner y AveNode2 (con Majority necesitaría 3 y no
    // commitearía).
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

    let state = get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    // Cae también AveNode2: queda 1 de 4, por debajo del 50%. El alta de
    // un segundo schema no puede commitear.
    compiler_nodes[0].token.cancel();
    join_all(compiler_nodes[0].handler.iter_mut()).await;

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example2",
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

    let state = get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        !gov.schemas
            .contains_key(&SchemaType::Type("Example2".to_owned()))
    );
}

// Espera acotada a que el artefacto wasm de un schema exista en disco
// con exactamente los bytes esperados (cubre el caso tampered: el
// fichero existe con basura hasta que el refetch lo reemplaza).
async fn wait_artifact_bytes_eq(
    contracts_path: &std::path::Path,
    artifact_name: &str,
    expected: &[u8],
) {
    let path = contracts_path
        .join("contracts")
        .join(artifact_name)
        .join("contract.wasm");
    for _ in 0..100 {
        if let Ok(bytes) = fs::read(&path) {
            if bytes == expected {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!(
        "timeout waiting for artifact {} with expected bytes",
        path.display()
    );
}

#[test(tokio::test)]
// Plan B de serving: con el único compiler (Owner) caído, un evaluador
// que ya tiene el artefacto v1 lo sirve a otro evaluador que se
// incorpora. Sin el serving del evaluador, AveNode3 no podría obtener
// el artefacto.
async fn test_fetch_plan_b_evaluator_serves_with_compilers_down() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    let node2_contracts = tempfile::tempdir().unwrap();
    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let node3_contracts = tempfile::tempdir().unwrap();
    let (node3, mut node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node3_dirs);
    node_running(&node3.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // AveNode3 sincroniza la gobernanza con el Owner ya caído: su única
    // fuente posible es AveNode2 (testigo del gov desde SN1), así que se
    // autoriza con ambos como sync peers.
    node3
        .api
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::Many(vec![
                PublicKey::from_str(node1.public_key()).unwrap(),
                PublicKey::from_str(&node2.api.public_key()).unwrap(),
            ]),
        )
        .await
        .unwrap();

    // SN 1: AveNode2 evaluador y testigo de la gobernanza; AveNode3 solo
    // evaluador. El único compiler es el Owner.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
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
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // AveNode2 sincroniza y fetcheada la v1 del Owner (único compiler).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // Cae el Owner: no queda ningún compiler vivo. AveNode3 solo puede
    // obtener la v1 por plan B (evaluador que ya la tiene).
    nodes[0].token.cancel();
    let mut owner = std::mem::take(&mut nodes[0].handler);
    join_all(owner.iter_mut()).await;

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v1, node3_v1);

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// Ciclo update+timeoff: dos schemas sin nadie que los sirva dejan al
// evaluador esperando (una sola ronda de gov update para ambos), el
// schema cuyo artefacto sí tiene sigue evaluando con normalidad y un
// alta sobre un schema sin artefacto responde Unavailable (la request
// entra en RebootTimeOut). Cuando el servidor vuelve a tener los bytes
// oficiales, el fetch se completa y la request rebootada commitea.
async fn test_fetch_unavailable_until_server_returns() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema "Stable" evaluado por ambos. AveNode2 lo fetcheada.
    // AveNode2 NO es testigo de la gobernanza a propósito: si lo fuera,
    // aplicaría SN 2 por distribución en el commit (antes de corromper
    // los bytes del Owner) y fetcheada Foo/Bar válidos. Así solo aplica
    // SN 2 cuando el test hace update_subject, con los bytes ya
    // corruptos.
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
            "schema": [
                {
                    "schema_id": "Stable",
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
        },
        "schemas": {
            "add": [
                {
                    "id": "Stable",
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    let stable_name = format!("{governance_id}_Stable");
    wait_artifact_bytes(node2_contracts.path(), &stable_name).await;

    // SN 2: se añaden "Foo" y "Bar", evaluados SOLO por AveNode2 (así el
    // Owner nunca los evalúa y no dispara su propia recompilación).
    let foo_bar_roles = |schema_id: &str| {
        json!({
            "schema_id": schema_id,
            "add": {
                "evaluator": [
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
        })
    };

    let json = json!({
        "roles": {
            "schema": [foo_bar_roles("Foo"), foo_bar_roles("Bar")]
        },
        "schemas": {
            "add": [
                {
                    "id": "Foo",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Bar",
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El Owner compiló Foo y Bar pero nadie se los ha pedido jamás: su
    // caché de serving está vacía. Movemos los directorios de artefacto
    // (no se corrompen los bytes: esos bytes se servirían y quedarían
    // 300s en la caché de serving — SERVING_CACHE_TTL — envenenando los
    // fetches posteriores; con el directorio ausente el serve devuelve
    // None y NO rellena la caché, así que al restaurar el siguiente
    // fetch lee los bytes buenos de disco).
    let foo_name = format!("{governance_id}_Foo");
    let bar_name = format!("{governance_id}_Bar");
    let foo_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&foo_name);
    let bar_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&bar_name);
    let foo_bytes = fs::read(foo_dir.join("contract.wasm")).unwrap();
    let bar_bytes = fs::read(bar_dir.join("contract.wasm")).unwrap();
    let foo_hidden = foo_dir.with_extension("bak");
    let bar_hidden = bar_dir.with_extension("bak");
    fs::rename(&foo_dir, &foo_hidden).unwrap();
    fs::rename(&bar_dir, &bar_hidden).unwrap();

    // AveNode2 aplica SN 2: necesita Foo y Bar, pero nadie sirve bytes
    // válidos. El fetch queda en ciclo de reintentos.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&foo_name)
            .exists()
    );
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&bar_name)
            .exists()
    );

    // El schema con artefacto local sigue evaluando: un fact de Stable
    // commitea con el voto de AveNode2 mientras Foo y Bar están
    // bloqueados.
    let (stable_subject, ..) =
        create_subject(&node1.api, governance_id.clone(), "Stable", "", true)
            .await
            .unwrap();

    get_subject(&node2.api, stable_subject.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        &node1.api,
        stable_subject.clone(),
        json!({"ModOne": {"data": 9}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node2.api, stable_subject.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 9, "two": 0, "three": 0}));

    // Los Create de tracker NO pasan por evaluación (el init_value se
    // verifica en la fase de compilación del schema, no por subject), así
    // que el alta de un subject Foo commitea aunque AveNode2 no tenga el
    // artefacto. Lo que no puede commitear es un FACT: la evaluación la
    // hace AveNode2, que no tiene módulo → Unavailable → RebootTimeOut.
    let (foo_subject, ..) =
        create_subject(&node1.api, governance_id.clone(), "Foo", "", true)
            .await
            .unwrap();

    let foo_request = emit_fact(
        &node1.api,
        foo_subject.clone(),
        json!({"ModOne": {"data": 3}}),
        false,
    )
    .await
    .unwrap();

    wait_request_state(
        &node1.api,
        foo_request,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // El servidor vuelve a tener los artefactos oficiales: el ciclo de
    // reintentos de AveNode2 completa ambos fetches verificados contra
    // el ancla.
    fs::rename(&foo_hidden, &foo_dir).unwrap();
    fs::rename(&bar_hidden, &bar_dir).unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &foo_name, &foo_bytes)
        .await;
    wait_artifact_bytes_eq(node2_contracts.path(), &bar_name, &bar_bytes)
        .await;

    // La request rebootada evalúa Foo y commitea.
    let state = get_subject(&node1.api, foo_subject.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 3, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// Un peer corrupto sirve bytes que no casan con el ancla: el receptor
// los descarta (warn) y no los escribe en disco; cuando un servidor con
// los bytes oficiales vuelve a estar disponible, el fetch se completa.
async fn test_fetch_corrupt_peer_hash_mismatch_failover() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    // SN 1: AveNode2 pasa a ser compiler y testigo de la gobernanza.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    // SN 2: alta del schema. Los compilers son Owner y AveNode2: ambos
    // compilan la v1 localmente (nadie la fetcheada, así que ninguna
    // caché de serving se llena y la corrupción en disco es efectiva).
    let json = json!({
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Escenario: AveNode2 es el peer corrupto (sirve bytes que no casan
    // con el ancla → el receptor los descarta sin escribir en disco) y el
    // Owner está no disponible (artefacto ausente → serve devuelve None).
    // OJO: no se corrompen los bytes del Owner — esos bytes se servirían
    // y quedarían 300s en su caché de serving (SERVING_CACHE_TTL,
    // worker.rs), envenenando los fetches posteriores a la restauración;
    // con el directorio ausente la caché no se rellena.
    let artifact_name = format!("{governance_id}_Example");
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node2_wasm = node2_contracts
        .path()
        .join("contracts")
        .join(&artifact_name)
        .join("contract.wasm");
    let node1_v1 = fs::read(node1_dir.join("contract.wasm")).unwrap();
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();
    fs::write(&node2_wasm, b"garbage").unwrap();

    // AveNode3 aplica SN 2 y necesita la v1: todos los bytes que recibe
    // fallan la verificación contra el ancla y se descartan.
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        !node3_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists()
    );

    // El Owner vuelve a estar disponible: el siguiente intento de
    // AveNode3 completa el fetch verificado contra el ancla.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // AveNode3 evalúa con el artefacto fetcheado: un fact commitea con
    // el quórum de los dos evaluadores.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node3.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 9}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node3.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 9, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// Recuperación en arranque por la vía FETCH (evaluador): artefacto
// intacto → no hay refetch (arranca aislado y los bytes no cambian);
// artefacto ausente → refetch verificado contra el ancla; artefacto
// manipulado en disco (wasm corrupto y cwasm borrado) → se descarta y
// se refetcheada.
async fn test_fetch_startup_recovery_absent_tampered_intact() {
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: tres schemas con contrato, evaluados por ambos. AveNode2 los
    // fetcheada del Owner (único compiler).
    let schema_roles = |schema_id: &str| {
        json!({
            "schema_id": schema_id,
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
        })
    };

    let schema_add = |schema_id: &str| {
        json!({
            "id": schema_id,
            "contract": EXAMPLE_CONTRACT,
            "initial_value": {
                "one": 0,
                "two": 0,
                "three": 0
            }
        })
    };

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
                    "witness": ["AveNode2"]
                }
            },
            "schema": [
                schema_roles("Alpha"),
                schema_roles("Beta"),
                schema_roles("Gamma")
            ]
        },
        "schemas": {
            "add": [
                schema_add("Alpha"),
                schema_add("Beta"),
                schema_add("Gamma")
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    let alpha_name = format!("{governance_id}_Alpha");
    let beta_name = format!("{governance_id}_Beta");
    let gamma_name = format!("{governance_id}_Gamma");
    let alpha_bytes =
        wait_artifact_bytes(node2_contracts.path(), &alpha_name).await;
    let beta_bytes =
        wait_artifact_bytes(node2_contracts.path(), &beta_name).await;
    let gamma_bytes =
        wait_artifact_bytes(node2_contracts.path(), &gamma_name).await;

    // CASO 1 (intacto): reinicio aislado de la red. Todo está en disco:
    // no hay refetch posible y el nodo arranca con los mismos bytes.
    // (Bootstrap sin peers: un Addressable sin boot nodes muere con
    // NoBootstrapNode — network/worker.rs — y el nodo no arranca.)
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &alpha_name, &alpha_bytes)
        .await;
    wait_artifact_bytes_eq(node2_contracts.path(), &beta_name, &beta_bytes)
        .await;
    wait_artifact_bytes_eq(node2_contracts.path(), &gamma_name, &gamma_bytes)
        .await;

    // CASO 2 (ausente): Beta borrado del disco. Al arrancar con red, el
    // nodo lo refetcheada verificado contra el ancla.
    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    fs::remove_dir_all(
        node2_contracts.path().join("contracts").join(&beta_name),
    )
    .unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &beta_name, &beta_bytes)
        .await;

    // CASO 3 (manipulado): el wasm de Gamma está corrupto y su cwasm
    // borrado. El arranque detecta el mismatch contra el ancla, descarta
    // el artefacto y lo refetcheada.
    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let gamma_dir = node2_contracts.path().join("contracts").join(&gamma_name);
    fs::write(gamma_dir.join("contract.wasm"), b"garbage").unwrap();
    fs::remove_file(gamma_dir.join("contract.cwasm")).unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &gamma_name, &gamma_bytes)
        .await;

    // Los otros artefactos no se han tocado en ningún reinicio.
    wait_artifact_bytes_eq(node2_contracts.path(), &alpha_name, &alpha_bytes)
        .await;
    wait_artifact_bytes_eq(node2_contracts.path(), &beta_name, &beta_bytes)
        .await;

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// Nodo con rol dual compiler+evaluador: compila la v1 y la sirve como
// compiler (plan A) a otro evaluador. Tras perder el rol de compiler y
// commitearse un cambio de contrato, obtiene la v2 por la vía fetch
// verificada contra el ancla, evalúa con ella y la sirve como evaluador
// (plan B) cuando el único compiler está caído.
async fn test_dual_role_serves_plan_a_and_b() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();
    let node4_contracts = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    let node2_contracts_path = node2_contracts.path().to_path_buf();
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts_path),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let (node4, _node4_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node4_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node4.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    // AveNode4 hace su primera sincronización de la gobernanza con el
    // Owner ya caído: su única fuente posible es AveNode2 (testigo del
    // gov desde SN1), así que se autoriza con ambos como sync peers.
    node4
        .api
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::Many(vec![
                PublicKey::from_str(node1.api.public_key()).unwrap(),
                PublicKey::from_str(&node2.api.public_key()).unwrap(),
            ]),
        )
        .await
        .unwrap();

    // SN 1: AveNode2 se convierte en compiler y testigo de la
    // gobernanza (todavía no hay schemas).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                },
                {
                    "name": "AveNode4",
                    "key": node4.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
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

    // SN 2: alta del schema. Los compilers son Owner y AveNode2: ambos
    // compilan la v1 localmente. Nadie fetcheada, así que la caché de
    // serving del Owner está vacía.
    let json = json!({
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
                            },
                            {
                                "name": "AveNode4",
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // PLAN A: el Owner queda con el wasm corrupto en disco (nunca ha
    // servido: su caché está vacía). AveNode3 solo puede obtener la v1
    // de AveNode2, que la sirve como compiler.
    let node1_wasm = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name)
        .join("contract.wasm");
    fs::write(&node1_wasm, b"garbage").unwrap();

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v1, node3_v1);

    // SN 3: AveNode2 pierde el rol de compiler y AveNode3 el de
    // evaluador. Sin fase compile.
    let json = json!({
        "roles": {
            "governance": {
                "remove": {
                    "compiler": ["AveNode2"]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "evaluator": [
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // SN 4: cambio de contrato a la v2. El único compiler es el Owner;
    // AveNode2, ya solo evaluador, obtiene la v2 por fetch verificado
    // contra el ancla.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // La v1 sigue en disco hasta que el Reconcile la descarta y el fetch
    // de la v2 (verificada contra el ancla) la reemplaza: esperar a que
    // los bytes cambien, no a que el fichero simplemente exista.
    let node2_v2 = {
        let path = node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .join("contract.wasm");
        let mut bytes = Vec::new();
        for _ in 0..100 {
            if let Ok(read) = fs::read(&path)
                && read != node2_v1
            {
                bytes = read;
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        assert!(
            !bytes.is_empty(),
            "timeout waiting for v2 artifact {}",
            path.display()
        );
        bytes
    };

    // AveNode2 evalúa con la v2 fetcheada: un fact solo válido con la
    // v2 (ModThree=50) commitea con los votos del Owner y AveNode2
    // (quórum 2 de 3; AveNode4 está desactualizado y no hace falta).
    let (subject_id, ..) = create_subject(
        &node1.api,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node2.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    // PLAN B: cae el Owner (único compiler). AveNode4 se incorpora y
    // necesita la v2; AveNode3 se quedó en la v1 y ya no es evaluador,
    // así que el único servidor posible es AveNode2, ahora solo
    // evaluador con el artefacto verificado.
    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    node4
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node4.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    let node4_v2 =
        wait_artifact_bytes(node4_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v2, node4_v2);

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
    node_running(&node4.api).await.unwrap();
}
