mod common;

use std::{
    collections::BTreeSet, str::FromStr, sync::atomic::Ordering,
};

use ave_common::{
    bridge::response::{
        RequestEventDB, SubjectDB, TrackerEventVisibilityDB,
        TrackerEventVisibilityRangeDB, TrackerStoredVisibilityDB,
        TrackerStoredVisibilityRangeDB, TrackerVisibilityModeDB,
    },
    identity::PublicKey,
};
use ave_core::auth::AuthWitness;
use common::{
    CreateNodeConfig, assert_tracker_fact_full,
    create_and_authorize_governance, create_node,
    create_nodes_and_connections, create_subject, emit_confirm, emit_fact,
    emit_eol, emit_fact_viewpoints, emit_reject, emit_transfer, get_events,
    get_subject, node_running, assert_tracker_visibility
};
use ave_network::{NodeType, RoutingNode};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{CreateNodesAndConnectionsConfig, PORT_COUNTER};

const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";



#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B14: planificación multi-tramo con rangos discontinuos
//
// Setup:
//   preparar witnesses con rangos cortados y huecos;
//   añadir otro caso con un witness que cubra todo.
//
// Acción:
//   lanzar update desde un `sn` intermedio.
//
// Comprobar:
//   el plan sale tramo a tramo en el orden esperado;
//   si hay un witness dominante, se usa solo ese;
//   un hueco en el `next_sn` invalida ese witness para ese tramo.
//   si un witness solo cubre el `next_sn` en `Opaque` y otro en `Clear`, gana `Clear`.
async fn test_viewpoints_update_disjoint_ranges_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B15: reinicio de ronda por objetivo real
//
// Setup:
//   preparar casos con objetivo alcanzado, no alcanzado y progreso parcial.
//
// Acción:
//   dejar vencer el timeout de la ronda.
//
// Comprobar:
//   si el objetivo ya se alcanzó, no reintenta;
//   si hubo progreso parcial, reinicia desde ahí;
//   no aparecen dos rondas activas a la vez.
async fn test_viewpoints_update_retry_target_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B16: descubrimiento de tipo con `our_sn = None`
//
// Setup:
//   usar un subject desconocido;
//   preparar ofertas remotas de governance y de tracker.
//
// Acción:
//   lanzar update sin `our_sn`.
//
// Comprobar:
//   si el subject es governance, sigue `highest sn`;
//   si es tracker, sigue planner por rangos;
//   un caso de un solo witness no deja update residual.
//   si un witness no tiene acceso útil, su oferta se ignora.
async fn test_viewpoints_update_subject_kind_discovery_battery() {}