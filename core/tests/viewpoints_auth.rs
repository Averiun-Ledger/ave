mod common;

use std::{collections::BTreeSet, str::FromStr, sync::atomic::Ordering};

use ave_common::{
    bridge::response::{
        RequestEventDB, SubjectDB, TrackerEventVisibilityDB,
        TrackerEventVisibilityRangeDB, TrackerStoredVisibilityDB,
        TrackerStoredVisibilityRangeDB, TrackerVisibilityModeDB,
    },
    identity::PublicKey,
};
use ave_core::auth::AuthWitness;
use ave_network::{NodeType, RoutingNode};
use common::{
    CreateNodeConfig, assert_tracker_fact_full,
    create_and_authorize_governance, create_node, create_nodes_and_connections,
    create_subject, emit_confirm, emit_eol, emit_fact, emit_fact_viewpoints,
    emit_reject, emit_transfer, get_events, get_subject, node_running,
};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{CreateNodesAndConnectionsConfig, PORT_COUNTER};

const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B17: subject desconocido y ownership resuelto en el mismo batch
//
// Setup:
//   usar un receptor que no conoce el subject;
//   preparar un batch con `Create`, facts y transferencias.
//
// Acción:
//   enviar el batch completo de una vez.
//
// Comprobar:
//   el acceso final no se decide solo por el `Create`;
//   manda el ownership efectivo al final del batch;
//   un sender no creator puede seguir siendo válido si el batch lo justifica.
//   si el batch empieza en `sn=0`, el cálculo usa `data.gov_version` como fallback.
async fn test_viewpoints_unknown_subject_ownership_in_batch_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B18: autorización y continuidad cuando cambia owner o witness
//
// Setup:
//   partir un histórico en dos o tres batches;
//   hacer que entre medias cambie owner, witness o governance version.
//
// Acción:
//   enviar los batches seguidos.
//
// Comprobar:
//   un batch no se autoriza solo por el primer evento;
//   el siguiente batch puede requerir otro sender;
//   un sender válido para un tramo puede dejar de serlo para el siguiente.
//   si cambia la `gov_version` en mitad del histórico, la decisión usa la versión de cada tramo.
async fn test_viewpoints_batch_auth_transition_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B19: validación de inputs de viewpoints y grants
//
// Setup:
//   preparar facts y creator witnesses con:
//   `AllViewpoints`;
//   `AllViewpoints + agua`;
//   viewpoints desconocidos;
//   viewpoints vacíos;
//   nombres repetidos o con formato raro.
//
// Acción:
//   intentar crear governance/facts/evaluations con esos datos.
//
// Comprobar:
//   `AllViewpoints` solo vale solo;
//   un viewpoint desconocido se rechaza;
//   governance fact no acepta viewpoints si no debe;
//   un input mal formado falla limpio y no deja estado parcial.
async fn test_viewpoints_input_validation_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B20: visibilidad almacenada vs visibilidad del evento
//
// Setup:
//   crear eventos con:
//   fact full;
//   fact opaque;
//   fact con viewpoints;
//   non-fact;
//   y un tracker que cambie de `Full` a `Opaque`.
//
// Acción:
//   pedir histórico y actualizar el mismo tracker varias veces.
//
// Comprobar:
//   `stored_visibility = None` fuerza respuesta opaca para facts;
//   `event_visibility = NonFact` sigue saliendo en claro;
//   un evento opaque con evaluación ok deja el tracker en modo `Opaque`;
//   si la evaluación falla, no degrada el modo por error.
//   `actual_owner`, `new_owner` y `old_owner` siguen viendo claro aunque el event
//   tenga viewpoints, respetando sus atajos de ownership.
async fn test_viewpoints_stored_vs_event_visibility_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B21: namespace y schema combinados con viewpoints
//
// Setup:
//   usar witnesses correctos por viewpoint pero incorrectos por namespace/schema;
//   y otros correctos por namespace/schema pero sin viewpoint útil.
//
// Acción:
//   pedir acceso y copia sobre los mismos facts.
//
// Comprobar:
//   hay acceso solo si coinciden namespace/schema y grant de viewpoint;
//   acertar una sola dimensión no basta;
//   `TrackerSchemas` abre por schema global solo cuando el namespace también cuadra.
async fn test_viewpoints_namespace_schema_intersection_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B22: cambio de creator con mismo schema y mismo witness
//
// Setup:
//   usar el mismo schema y namespace;
//   hacer que el subject cambie de creator efectivo o de owner relevante;
//   mantener el mismo witness con grants distintos según creator.
//
// Acción:
//   pedir histórico antes y después del cambio.
//
// Comprobar:
//   el grant del creator anterior no se arrastra al siguiente;
//   el witness solo ve en claro los tramos donde el creator correcto lo autoriza;
//   el cambio no reabre en claro histórico ajeno.
async fn test_viewpoints_creator_change_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B23: `clear_sn`, prefijo contiguo y corte del primer batch
//
// Setup:
//   preparar un witness con rango `Clear` al principio y `Opaque` después;
//   por ejemplo `0..5 Clear` y `6..20 Opaque`.
//
// Acción:
//   lanzar update desde `our_sn = None` y desde `our_sn = 3`.
//
// Comprobar:
//   el primer request corta en el último `clear_sn` contiguo;
//   no mezcla en el mismo batch el tramo claro con el opaco si hay corte natural;
//   el segundo tramo se pide después por la ruta normal.
async fn test_viewpoints_clear_prefix_cut_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B24: bordes de `sn`, `gov_version` y límites sin oferta útil
//
// Setup:
//   usar subjects donde:
//   el primer evento sea `sn=0`;
//   falte alguna entrada de ventana de governance;
//   `actual_sn` ya sea mayor o igual que el `sn` ofrecido por el witness.
//
// Acción:
//   pedir ventana, oferta y batch de distribución/update.
//
// Comprobar:
//   para `sn=0` se usa `data.gov_version` como fallback;
//   si no hay oferta útil, el nodo no fuerza update;
//   si `actual_sn >= witness_sn`, se corta limpio y no intenta pedir de más.
async fn test_viewpoints_sn_gov_version_edges_battery() {}
