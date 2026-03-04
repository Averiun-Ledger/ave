# Cambios de Red: peers efímeros, diales y reintentos

Fecha: 2026-03-03

## Alcance

Este documento justifica los cambios aplicados en red para:

- evitar diales periódicos innecesarios a nodos efímeros,
- mantener la posibilidad de despertar un efímero cuando hay mensaje real pendiente,
- evitar limpieza agresiva de peers por fallos transitorios de transporte.

Archivos de red afectados:

- `network/src/utils.rs`
- `network/src/behaviour.rs`
- `network/src/routing.rs`
- `network/src/worker.rs`

Nota: en `staged` también existe `http/src/main.rs`, pero ese cambio no pertenece a esta incidencia de networking.

## Problema original

1. Kademlia intentaba dial periódico hacia peers en k-buckets, incluidos efímeros.
2. Eso producía ruido y podía despertar instancias que deberían arrancar solo bajo demanda.
3. Al mismo tiempo, al bloquear diales a efímeros se corría el riesgo de impedir entrega real de mensajes.
4. La limpieza de peers era agresiva frente a errores transitorios (`Timeout`, `UnexpectedEof`, etc.) y podía hacer que se perdiera información útil del peer.

## Diseño aplicado

### 1) Señal explícita de tipo de nodo (Identify agent_version)

Se añade metadato `node=<tipo>` en `agent_version`:

- `bootstrap`
- `addressable`
- `ephemeral`

Cambios:

- `utils.rs`: `build_user_agent(...)` e `is_ephemeral_agent_version(...)`
- `behaviour.rs`: Identify usa `build_user_agent(&config.node_type)`

Objetivo: clasificar peers efímeros de forma explícita por protocolo, no por heurísticas frágiles.

### 2) Política de “non-dialable peer” para efímeros

`routing` mantiene:

- `non_dialable_peers`: peers que no deben recibir dial de mantenimiento,
- `allow_next_dial_to_peer`: permiso one-shot para un dial explícito.

Comportamiento:

- si peer está en `non_dialable_peers`, se deniega outbound dial,
- excepto cuando existe permiso one-shot (consumido en ese intento).

Objetivo: bloquear ruido periódico sin bloquear casos de envío real.

### 3) Excepción para envío real (message-driven dial)

En `worker`, cuando hay mensajes pendientes para un peer:

- antes de `swarm.dial(...)` se concede `allow_next_outbound_dial(peer)`,
- ante fallo, se prioriza reprogramar `Dial` (no solo `Discover`) mientras siga habiendo mensaje pendiente.

Objetivo: que retry 2/3 de distribución siga intentando llegar al peer objetivo/proxy.

### 4) Reintentos de transporte más completos

Se consideran reintentables también:

- `UnexpectedEof`
- `ConnectionReset`

Objetivo: evitar clasificar como fallo terminal errores que son transitorios en peers dormidos/proxy wakeup.

### 5) `DialError::Denied` no corta el ciclo de reintento

En `dial_error_manager`, el caso `DialError::Denied` no hace `return None`.

Se deja continuar el flujo normal para que:

- el caller pueda limpiar `peer_action`,
- y se reprograme `Dial` o `Discover` según haya mensajes pendientes.

Objetivo: evitar estados “atascados” donde no se vuelve a programar intento.

### 6) `ScheduleType::Dial(vec![])` en retries de mensaje

Cuando se usa `ScheduleType::Dial(vec![])`, no significa “dial sin dirección”.

Significa: dial por `peer_id` dejando que `libp2p` complete direcciones desde el behaviour (`extend_addresses_through_behaviour()`), es decir, desde k-buckets/peerstore/identify.

Objetivo: mantener dial dirigido al peer incluso cuando en ese instante no hay una lista explícita de direcciones candidatas.

### 7) Limpieza menos agresiva

Se ajusta limpieza para no expulsar peers válidos por inestabilidad temporal:

- se elimina la penalización automática por cada `OutgoingConnectionError` en el flujo principal de diales,
- en `routing`, si `filter_addresses` queda vacío en un intento outbound, ya no se hace `remove_peer` inmediato.

Objetivo: diferenciar “peer temporalmente inaccesible” de “peer inválido”.

## Flujo final esperado

1. Peer efímero se identifica con `agent_version ...;node=ephemeral`.
2. Se marca `non-dialable` para evitar diales periódicos/noise.
3. Si llega mensaje para ese peer:
   - se encola outbound,
   - se habilita un dial one-shot explícito,
   - si falla por transporte transitorio, se reintenta dial con backoff.
4. Si realmente cambió dirección, `Discover` sigue existiendo como fallback y para peers no conocidos/no pending.

## Qué no cambia

- No se trata un fallo de dial como prueba de “peer efímero”.
- Errores duros (`WrongPeerId`, incompatibilidades de protocolo, etc.) mantienen limpieza dura.
- La política de `RetryActor` en `core` no se cambió (sigue enviando `SendMessage` por intento según su estrategia).

## Validación ejecutada

Comandos:

- `cargo check -p ave-network`
- `cargo test -p ave-network --lib`
- `cargo clippy -p ave-network --lib`
- `cargo clippy`

Resultado:

- compilación OK,
- tests de `ave-network` OK (13/13),
- clippy OK sin warnings en el estado actual.

## Riesgos y seguimiento

1. Si un peer cambia IP real con frecuencia, puede requerir combinar retries de dial con discover periódico controlado.
2. Si el efímero publica direcciones no válidas para terceros (privadas/loopback), seguirá siendo alcanzable solo cuando él inicie.
3. Recomendado instrumentar métricas por peer:
   - `dial_attempts`,
   - `dial_denied_non_dialable`,
   - `dial_transport_failures`,
   - `discover_hits` / `discover_empty`.
