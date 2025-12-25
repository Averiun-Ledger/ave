use std::{str::FromStr, time::Duration};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction,
    FixedIntervalStrategy, Handler, Message, NotPersistentActor, RetryActor,
    RetryMessage, Strategy,
};
use ave_common::identity::{DigestIdentifier, PublicKey, Signed};
use network::ComunicateInfo;

use crate::{
    ActorMessage, Event as AveEvent, EventRequest, NetworkMessage, Node,
    NodeMessage, NodeResponse,
    auth::WitnessesAuth,
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        data::GovernanceData,
        model::{CreatorQuantity, HashThisRole, RoleTypes},
    },
    helpers::network::service::HelperService,
    model::{
        Namespace,
        common::{
            emit_fail,
            node::{get_node_subject_data, subject_old_owner, try_to_update},
            subject::{
                get_gov, get_quantity, update_last_state, update_ledger,
            },
        },
        event::{Ledger, ProtocolsSignatures},
        network::RetryNetwork,
        request::SchemaType,
    },
    subject::{LastStateData, SignedLedger},
    tracker::{Tracker, TrackerMessage, TrackerResponse},
    update::TransferResponse,
    validation::proof::ValidationProof,
};

use tracing::{error, warn};

const TARGET_DISTRIBUTOR: &str = "Ave-Distribution-Distributor";

use super::{Distribution, DistributionMessage};

pub struct AuthGovData {
    pub gov_version: Option<u64>,
    pub schema_id: SchemaType,
    pub namespace: Namespace,
    pub governance_id: DigestIdentifier,
}

pub struct Distributor {
    pub node: PublicKey,
}

// TODO QUITAR TODOS LOS &self.
impl Distributor {
    async fn down_tracker(
        &self,
        ctx: &mut ActorContext<Distributor>,
        subject_id: &str,
        owner: &str,
        new_owner: Option<String>,
        schema_id: SchemaType,
    ) -> Result<(), ActorError> {
        let up = Self::is_up_subject(
            &self.node.to_string(),
            owner,
            new_owner,
            schema_id,
        );

        if !up {
            let subject_path =
                ActorPath::from(format!("/user/node/{}", subject_id));
            let Some(subject_actor) =
                ctx.system().get_actor::<Tracker>(&subject_path).await
            else {
                return Err(ActorError::NotFound(subject_path));
            };

            return subject_actor.ask_stop().await;
        }

        Ok(())
    }

    fn is_up_subject(
        our_key: &str,
        owner: &str,
        new_owner: Option<String>,
        schema_id: SchemaType,
    ) -> bool {
        let i_new_owner = if let Some(new_owner) = new_owner.clone() {
            our_key == new_owner
        } else {
            false
        };

        our_key == owner || i_new_owner || schema_id.is_gov()
    }

    async fn create_subject(
        &self,
        ctx: &mut ActorContext<Distributor>,
        ledger: SignedLedger,
    ) -> Result<(), ActorError> {
        if let EventRequest::Create(request) =
            ledger.content.event_request.content.clone()
            && !request.schema_id.is_gov()
        {
            let gov = get_gov(ctx, &request.governance_id.to_string()).await?;

            if let Some(max_quantity) = gov.max_creations(
                &ledger.signature.signer,
                request.schema_id.clone(),
                request.namespace.clone(),
            ) {
                let quantity = get_quantity(
                    ctx,
                    request.governance_id.to_string(),
                    request.schema_id.clone(),
                    ledger.signature.signer.to_string(),
                    request.namespace.to_string(),
                )
                .await?;

                if let CreatorQuantity::Quantity(max_quantity) = max_quantity
                    && quantity >= max_quantity as usize
                {
                    return Err(ActorError::Functional("The maximum number of created subjects has been reached".to_owned()));
                }
            } else {
                return Err(ActorError::Functional("The number of subjects that can be created has not been found".to_owned()));
            };
        }

        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        let response = if let Some(node_actor) = node_actor {
            node_actor
                .ask(NodeMessage::CreateNewSubjectLedger(ledger))
                .await?
        } else {
            return Err(ActorError::NotFound(node_path));
        };
        match response {
            NodeResponse::SonWasCreated => Ok(()),
            _ => Err(ActorError::UnexpectedResponse(
                node_path,
                "NodeResponse::SonWasCreated".to_owned(),
            )),
        }
    }

    async fn get_ledger(
        &self,
        ctx: &mut ActorContext<Distributor>,
        subject_id: &str,
        last_sn: u64,
        is_gov: bool,
    ) -> Result<(Vec<SignedLedger>, Option<LastStateData>), ActorError> {
        let path = ActorPath::from(format!("/user/node/{}", subject_id));

        if is_gov {
            let Some(governance_actor) =
                ctx.system().get_actor::<Governance>(&path).await
            else {
                return Err(ActorError::NotFound(path));
            };

            let response = governance_actor
                .ask(GovernanceMessage::GetLedger { last_sn })
                .await?;

            match response {
                GovernanceResponse::Ledger { ledger, last_state } => {
                    Ok((ledger, last_state))
                }
                _ => Err(ActorError::UnexpectedResponse(
                    path,
                    "GovernanceResponse::Ledger".to_owned(),
                )),
            }
        } else {
            let response = if let Some(tracker_actor) =
                ctx.system().get_actor::<Tracker>(&path).await
            {
                tracker_actor
                    .ask(TrackerMessage::GetLedger { last_sn })
                    .await?
            } else {
                Self::up_subject(ctx, subject_id, true).await?;

                let Some(tracker_actor) =
                    ctx.system().get_actor::<Tracker>(&path).await
                else {
                    return Err(ActorError::NotFound(path));
                };

                let response = tracker_actor
                    .ask(TrackerMessage::GetLedger { last_sn })
                    .await?;

                tracker_actor.ask_stop().await?;

                response
            };

            match response {
                TrackerResponse::Ledger { ledger, last_state } => {
                    Ok((ledger, last_state))
                }
                _ => Err(ActorError::UnexpectedResponse(
                    path,
                    "TrackerResponse::Ledger".to_owned(),
                )),
            }
        }
    }

    async fn authorized_subj(
        &self,
        ctx: &mut ActorContext<Distributor>,
        subject_id: &str,
    ) -> Result<(bool, bool, bool), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        let response = if let Some(node_actor) = node_actor {
            node_actor
                .ask(NodeMessage::IsAuthorized(subject_id.to_owned()))
                .await?
        } else {
            return Err(ActorError::NotFound(node_path));
        };
        match response {
            NodeResponse::IsAuthorized { owned, auth, know } => {
                Ok((owned, auth, know))
            }
            _ => Err(ActorError::UnexpectedResponse(
                node_path,
                "NodeResponse::IsAuthorized".to_owned(),
            )),
        }
    }

    async fn check_auth(
        &self,
        ctx: &mut ActorContext<Distributor>,
        signer: PublicKey,
        info: ComunicateInfo,
        ledger: Ledger,
        auth_data: AuthGovData,
        sender: PublicKey,
    ) -> Result<(), ActorError> {
        let our_key = info.receiver.clone();
        let subject_id = ledger.subject_id.clone();
        // Si está auth o si soy el dueño del sujeto.
        let (owned, auth, know) =
            self.authorized_subj(ctx, &subject_id.to_string()).await?;

        // si es gov
        if auth_data.schema_id.is_gov() {
            // No está auth
            if !auth {
                Err(ActorError::Functional(
                    "Governance is not authorized".to_owned(),
                ))
            // está auth y tengo la copia
            } else if owned || know {
                Ok(())
            // está auth pero no tengo la copia
            } else if let EventRequest::Create(_) =
                ledger.event_request.content.clone()
            {
                Ok(())
            } else {
                try_to_update(ctx, subject_id, WitnessesAuth::Owner(signer))
                    .await?;
                Err(ActorError::Functional("Updating governance".to_owned()))
            }
        } else {
            let data =
                get_node_subject_data(ctx, &subject_id.to_string()).await?;
            let (namespace, governance_id, update) =
                if let Some((subject_data, _)) = data {
                    (
                        subject_data.namespace,
                        subject_data.governance_id.unwrap_or_default(),
                        false,
                    )
                } else if let EventRequest::Create(request) =
                    ledger.event_request.content.clone()
                {
                    (
                        request.namespace,
                        request.governance_id.to_string(),
                        false,
                    )
                } else {
                    (
                        auth_data.namespace,
                        auth_data.governance_id.to_string(),
                        true,
                    )
                };

            let gov_id_digest = DigestIdentifier::from_str(&governance_id)
                .map_err(|e| {
                    ActorError::FunctionalFail(format!(
                        "Invalid governance_id, {}",
                        e
                    ))
                })?;
            // obtenemos la gov.
            let gov = match get_gov(ctx, &governance_id).await {
                Ok(gov) => gov,
                Err(e) => {
                    if let ActorError::NotFound(_) = e {
                        try_to_update(
                            ctx,
                            gov_id_digest,
                            WitnessesAuth::Witnesses,
                        )
                        .await?;
                        return Err(ActorError::Functional(
                            "Updating governance".to_owned(),
                        ));
                    }
                    return Err(e);
                }
            };

            // Comparamos las govs, puede ser que ya no seamos testigo o que de repente seamos testigos.
            if let Some(gov_version) = auth_data.gov_version {
                Self::cmp_govs(
                    ctx,
                    gov.clone(),
                    gov_version,
                    gov_id_digest,
                    info,
                    sender,
                    &auth_data.schema_id,
                )
                .await?;
            }

            // Si no está autorizado explicitamente.
            if !auth {
                // Miramos que tengamos el rol, se comprueba que el signer sea creator y nosotros testigos
                if !gov.has_this_role(HashThisRole::SchemaWitness {
                    who: our_key,
                    creator: signer.clone(),
                    schema_id: auth_data.schema_id,
                    namespace,
                }) {
                    return Err(ActorError::Functional(
                        "We are not witness".to_string(),
                    ));
                }
            }

            if update {
                try_to_update(ctx, subject_id, WitnessesAuth::Owner(signer))
                    .await?;
                return Err(ActorError::Functional(
                    "Updating subject".to_owned(),
                ));
            }

            Ok(())
        }
    }

    async fn cmp_govs(
        ctx: &mut ActorContext<Distributor>,
        gov: GovernanceData,
        gov_version: u64,
        governance_id: DigestIdentifier,
        info: ComunicateInfo,
        sender: PublicKey,
        schema_id: &SchemaType,
    ) -> Result<(), ActorError> {
        let governance_id_string = governance_id.to_string();

        let our_gov_version = gov.version;
        match our_gov_version.cmp(&gov_version) {
            std::cmp::Ordering::Less => {
                // Mi version es menor, me actualizo. y no le envío nada
                let new_info = ComunicateInfo {
                    receiver: sender,
                    request_id: info.request_id,
                    version: info.version,
                    receiver_actor: format!(
                        "/user/node/distributor_{}",
                        governance_id_string
                    ),
                };

                let helper: Option<HelperService> =
                    ctx.system().get_helper("network").await;

                let Some(mut helper) = helper else {
                    return Err(ActorError::NotHelper("network".to_owned()));
                };

                helper
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::DistributionLedgerReq {
                                gov_version: Some(our_gov_version),
                                actual_sn: Some(our_gov_version),
                                subject_id: governance_id,
                            },
                        },
                    })
                    .await?;

                return Err(ActorError::Functional(
                    "My gov version is less than his gov version".to_owned(),
                ));
            }
            std::cmp::Ordering::Equal => {}
            std::cmp::Ordering::Greater => {
                // Su version es menor. Traslado la solicitud de actualización
                // a mi distributor gov.
                if !schema_id.is_gov() {
                    let new_info = ComunicateInfo {
                        receiver: info.receiver,
                        request_id: info.request_id,
                        version: info.version,
                        receiver_actor: format!(
                            "/user/node/distributor_{}",
                            governance_id_string
                        ),
                    };

                    let distributor_path = ActorPath::from(format!(
                        "/user/node/distributor_{}",
                        governance_id_string
                    ));

                    let Some(distributor_actor): Option<ActorRef<Distributor>> =
                        ctx.system().get_actor(&distributor_path).await
                    else {
                        let e = ActorError::NotFound(distributor_path);
                        return Err(emit_fail(ctx, e).await);
                    };

                    distributor_actor
                        .tell(DistributorMessage::SendDistribution {
                            gov_version: Some(gov_version),
                            actual_sn: Some(gov_version),
                            subject_id: governance_id_string,
                            info: new_info,
                            sender,
                        })
                        .await?;
                    warn!(
                        TARGET_DISTRIBUTOR,
                        "His gov version is less than my gov version"
                    );
                }
            }
        }

        Ok(())
    }

    async fn check_gov_version(
        &self,
        ctx: &mut ActorContext<Distributor>,
        subject_id: &str,
        gov_version: Option<u64>,
        info: &ComunicateInfo,
        sender: PublicKey,
    ) -> Result<bool, ActorError> {
        let data = get_node_subject_data(ctx, subject_id).await?;
        let (namespace, governance_id, owner, schema_id, new_owner) =
            if let Some((subject_data, new_owner)) = data {
                (
                    subject_data.namespace,
                    subject_data
                        .governance_id
                        .unwrap_or(subject_id.to_string()),
                    subject_data.owner,
                    subject_data.schema_id,
                    new_owner,
                )
            } else {
                return Err(ActorError::Functional(
                    "Can not check governance version, can not get node subject data".to_owned(),
                ));
            };

        let is_gov = schema_id.is_gov();

        let gov = match get_gov(ctx, &governance_id).await {
            Ok(gov) => gov,
            Err(e) => {
                if let ActorError::NotFound(_) = e {
                    return Err(ActorError::Functional(
                        "Can not check governance version, can not get governance".to_owned(),
                    ));
                } else {
                    return Err(e);
                }
            }
        };

        let gov_id_digest = DigestIdentifier::from_str(&governance_id)
            .map_err(|e| {
                ActorError::FunctionalFail(format!(
                    "Can not check governance version, invalid governance_id, {}",
                    e
                ))
            })?;

        if let Some(gov_version) = gov_version {
            Self::cmp_govs(
                ctx,
                gov.clone(),
                gov_version,
                gov_id_digest,
                info.clone(),
                sender.clone(),
                &schema_id,
            )
            .await?;
        }

        let sender_str = sender.to_string();
        if let Some(new_owner) = new_owner {
            if owner == sender_str || new_owner == sender_str {
                return Ok(is_gov);
            }
        } else if owner == sender_str {
            return Ok(is_gov);
        }

        let has_this_role = if is_gov {
            HashThisRole::Gov {
                who: sender.clone(),
                role: RoleTypes::Witness,
            }
        } else {
            let owner = PublicKey::from_str(&owner).map_err(|e| ActorError::FunctionalFail(format!("Can not conver owner PublicKey (String) into PublicKey: {}", e)))?;
            HashThisRole::SchemaWitness {
                who: sender.clone(),
                creator: owner,
                schema_id,
                namespace,
            }
        };

        if !gov.has_this_role(has_this_role) {
            return Err(ActorError::Functional(
                "Sender is neither a witness nor an owner nor a new owner of subject"
                    .to_owned(),
            ));
        };

        Ok(is_gov)
    }

    pub async fn up_subject(
        ctx: &mut ActorContext<Distributor>,
        subject_id: &str,
        light: bool,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        // We obtain the validator
        let node_response = if let Some(node_actor) = node_actor {
            node_actor
                .ask(NodeMessage::UpSubject(subject_id.to_owned(), light))
                .await?
        } else {
            return Err(ActorError::NotFound(node_path));
        };

        match node_response {
            NodeResponse::None => Ok(()),
            _ => Err(ActorError::UnexpectedResponse(
                node_path,
                "NodeResponse::None".to_owned(),
            )),
        }
    }
}

#[async_trait]
impl Actor for Distributor {
    type Event = ();
    type Message = DistributorMessage;
    type Response = ();
}

#[derive(Debug, Clone)]
pub enum DistributorMessage {
    // HECHO
    Transfer {
        subject_id: String,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    // HECHO
    GetLastSn {
        subject_id: String,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    // HECHO
    // Un nodo nos solicitó la copia del ledger.
    SendDistribution {
        gov_version: Option<u64>,
        actual_sn: Option<u64>,
        subject_id: String,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    // HECHO
    // Enviar a un nodo la replicación.
    NetworkDistribution {
        request_id: String,
        event: Signed<AveEvent>,
        ledger: SignedLedger,
        node_key: PublicKey,
        last_proof: ValidationProof,
        last_vali_res: Vec<ProtocolsSignatures>,
    },
    // HECHO
    // El nodo al que le enviamos la replica la recivió, parar los reintentos.
    NetworkResponse {
        sender: PublicKey,
    },
    // Nos llega una replica, guardarla en informar que la hemos recivido
    LastEventDistribution {
        event: Signed<AveEvent>,
        ledger: SignedLedger,
        last_proof: ValidationProof,
        last_vali_res: Vec<ProtocolsSignatures>,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    LedgerDistribution {
        events: Vec<SignedLedger>,
        last_state: Option<LastStateData>,
        namespace: Namespace,
        schema_id: SchemaType,
        governance_id: DigestIdentifier,
        info: ComunicateInfo,
        sender: PublicKey,
    },
}

impl Message for DistributorMessage {}

impl NotPersistentActor for Distributor {}

#[async_trait]
impl Handler<Distributor> for Distributor {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: DistributorMessage,
        ctx: &mut ActorContext<Distributor>,
    ) -> Result<(), ActorError> {
        match msg {
            DistributorMessage::Transfer {
                subject_id,
                info,
                sender,
            } => {
                let (subject_data, new_owner) = match get_node_subject_data(
                    ctx,
                    &subject_id,
                )
                .await
                {
                    Ok(data) => {
                        if let Some(data) = data {
                            data
                        } else {
                            let e = "The subject is not registered by the node"
                                .to_owned();
                            error!(
                                TARGET_DISTRIBUTOR,
                                "GetLastSn, Can not get node subject data: {}",
                                e
                            );
                            return Err(ActorError::Functional(e));
                        }
                    }
                    Err(e) => {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "GetLastSn, Can not get node subject data: {}", e
                        );

                        return Err(emit_fail(ctx, e).await);
                    }
                };

                let sender_str = sender.to_string();

                if let Some(_new_owner) = new_owner
                    && subject_data.owner == sender_str
                {
                    // Todavía no se ha emitido evento de confirm ni de reject
                    return Ok(());
                }

                let is_old_owner = match subject_old_owner(
                    ctx,
                    &subject_id.to_string(),
                    sender.clone(),
                )
                .await
                {
                    Ok(is_old_owner) => is_old_owner,
                    Err(e) => {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "Transfer, Can not know if is old owner: {}", e
                        );
                        if let ActorError::NotFound(_) = e {
                            return Err(e);
                        } else {
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                let res = if is_old_owner {
                    TransferResponse::Confirm
                } else if !is_old_owner && subject_data.owner == sender_str {
                    TransferResponse::Reject
                } else {
                    let e = "Sender is not the owner and is not a old owner";
                    error!(TARGET_DISTRIBUTOR, "Transfer, {}", e);

                    return Err(ActorError::Functional(e.to_owned()));
                };

                let new_info = ComunicateInfo {
                    receiver: sender,
                    request_id: info.request_id,
                    version: info.version,
                    receiver_actor: format!(
                        "/user/node/auth/transfer_{}/{}",
                        subject_id, info.receiver
                    ),
                };

                let helper: Option<HelperService> =
                    ctx.system().get_helper("network").await;

                let Some(mut helper) = helper else {
                    let e = ActorError::NotHelper("network".to_owned());
                    error!(
                        TARGET_DISTRIBUTOR,
                        "GetLastSn, Can not obtain network helper"
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                if let Err(e) = helper
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::TransferRes { res },
                        },
                    })
                    .await
                {
                    error!(
                        TARGET_DISTRIBUTOR,
                        "GetLastSn, can not send response to network: {}", e
                    );
                    return Err(emit_fail(ctx, e).await);
                };
            }
            DistributorMessage::GetLastSn {
                subject_id,
                info,
                sender,
            } => {
                let (subject_data, new_owner) = match get_node_subject_data(
                    ctx,
                    &subject_id,
                )
                .await
                {
                    Ok(data) => {
                        if let Some(data) = data {
                            data
                        } else {
                            let e = "The subject is not registered by the node"
                                .to_owned();
                            error!(
                                TARGET_DISTRIBUTOR,
                                "GetLastSn, Can not get node subject data: {}",
                                e
                            );
                            return Err(ActorError::Functional(e));
                        }
                    }
                    Err(e) => {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "GetLastSn, Can not get node subject data: {}", e
                        );

                        return Err(emit_fail(ctx, e).await);
                    }
                };

                let governance_id =
                    if let Some(gov_id) = subject_data.governance_id {
                        gov_id
                    } else {
                        subject_id.clone()
                    };

                let gov = match get_gov(ctx, &governance_id).await {
                    Ok(gov) => gov,
                    Err(e) => {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "GetLastSn, Can not get governance: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };
                let sender_str = sender.to_string();

                let is_owner = if let Some(new_owner) = new_owner {
                    subject_data.owner == sender_str || new_owner == sender_str
                } else {
                    subject_data.owner == sender_str
                };

                let has_this_role = if subject_data.schema_id.is_gov() {
                    HashThisRole::Gov {
                        who: sender.clone(),
                        role: RoleTypes::Witness,
                    }
                } else {
                    let owner = PublicKey::from_str(&subject_data.owner).map_err(|e| ActorError::FunctionalFail(format!("Can not conver owner PublicKey (String) into PublicKey: {}", e)))?;
                    HashThisRole::SchemaWitness {
                        who: sender.clone(),
                        creator: owner,
                        schema_id: subject_data.schema_id,
                        namespace: subject_data.namespace.clone(),
                    }
                };

                if !is_owner && !gov.has_this_role(has_this_role) {
                    let e = "Sender neither the owned nor a witness";
                    error!(TARGET_DISTRIBUTOR, "GetLastSn, {}", e);
                    return Err(ActorError::Functional(e.to_owned()));
                }

                let new_info = ComunicateInfo {
                    receiver: sender,
                    request_id: info.request_id,
                    version: info.version,
                    receiver_actor: format!(
                        "/user/node/auth/{}/{}",
                        subject_id, info.receiver
                    ),
                };

                let helper: Option<HelperService> =
                    ctx.system().get_helper("network").await;

                let Some(mut helper) = helper else {
                    let e = ActorError::NotHelper("network".to_owned());
                    error!(
                        TARGET_DISTRIBUTOR,
                        "GetLastSn, Can not obtain network helper"
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                if let Err(e) = helper
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::AuthLastSn {
                                sn: subject_data.sn,
                            },
                        },
                    })
                    .await
                {
                    error!(
                        TARGET_DISTRIBUTOR,
                        "GetLastSn, can not send response to network: {}", e
                    );
                    return Err(emit_fail(ctx, e).await);
                };
            }
            DistributorMessage::SendDistribution {
                actual_sn,
                info,
                gov_version,
                subject_id,
                sender,
            } => {
                let is_gov = match self
                    .check_gov_version(
                        ctx,
                        &subject_id,
                        gov_version,
                        &info,
                        sender.clone(),
                    )
                    .await
                {
                    Ok(is_gov) => is_gov,
                    Err(e) => {
                        error!(TARGET_DISTRIBUTOR, "SendDistribution, {}", e);
                        if let ActorError::Functional(_) = e {
                            return Err(e);
                        } else {
                            return Err(emit_fail(ctx, e).await);
                        };
                    }
                };

                let sn = actual_sn.unwrap_or_default();

                // Sacar eventos.
                let (ledger, last_state) =
                    match self.get_ledger(ctx, &subject_id, sn, is_gov).await {
                        Ok(res) => res,
                        Err(e) => {
                            error!(
                                TARGET_DISTRIBUTOR,
                                "SendDistribution, Can not obtain ledger {}", e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                let (namespace, governance_id, schema_id) =
                    match get_node_subject_data(ctx, &subject_id).await {
                        Ok(data) => {
                            if let Some((subject_data, _)) = data {
                                (
                                    subject_data.namespace,
                                    subject_data
                                        .governance_id
                                        .unwrap_or_default(),
                                    subject_data.schema_id,
                                )
                            } else {
                                let e =
                                    "Can not get node subject data".to_owned();
                                error!(
                                    TARGET_DISTRIBUTOR,
                                    "SendDistribution, {}", e
                                );

                                return Err(emit_fail(
                                    ctx,
                                    ActorError::Functional(e),
                                )
                                .await);
                            }
                        }
                        Err(e) => {
                            error!(
                                TARGET_DISTRIBUTOR,
                                "SendDistribution, Can not get node subject data {}",
                                e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                let new_info = ComunicateInfo {
                    receiver: sender,
                    request_id: info.request_id,
                    version: info.version,
                    receiver_actor: format!(
                        "/user/node/distributor_{}",
                        subject_id
                    ),
                };

                let helper: Option<HelperService> =
                    ctx.system().get_helper("network").await;

                let Some(mut helper) = helper else {
                    let e = ActorError::NotHelper("network".to_owned());
                    error!(
                        TARGET_DISTRIBUTOR,
                        "SendDistribution, Can not obtain network helper {}", e
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                let gov_id_digest = DigestIdentifier::from_str(&governance_id)
                    .map_err(|e| {
                        ActorError::FunctionalFail(format!(
                            "Invalid governance_id, {}",
                            e
                        ))
                    })?;

                if let Err(e) = helper
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::DistributionLedgerRes {
                                ledger,
                                last_state,
                                schema_id,
                                namespace: namespace.to_string(),
                                governance_id: gov_id_digest,
                            },
                        },
                    })
                    .await
                {
                    error!(
                        TARGET_DISTRIBUTOR,
                        "SendDistribution, can not send response to network: {}",
                        e
                    );
                    return Err(emit_fail(ctx, e).await);
                };
            }
            DistributorMessage::NetworkDistribution {
                request_id,
                event,
                node_key,
                ledger,
                last_proof,
                last_vali_res,
            } => {
                let receiver_actor = format!(
                    "/user/node/distributor_{}",
                    event.content.subject_id
                );

                let message = NetworkMessage {
                    info: ComunicateInfo {
                        request_id,
                        version: 0,
                        receiver: node_key,
                        receiver_actor,
                    },
                    message: ActorMessage::DistributionLastEventReq {
                        ledger: Box::new(ledger),
                        event: Box::new(event),
                        last_proof,
                        last_vali_res,
                    },
                };

                let target = RetryNetwork::default();

                #[cfg(feature = "test")]
                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(2, Duration::from_secs(2)),
                );
                #[cfg(not(feature = "test"))]
                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(2, Duration::from_secs(5)),
                );

                let retry_actor = RetryActor::new(target, message, strategy);

                let retry = match ctx
                    .create_child::<RetryActor<RetryNetwork>, _>(
                        "retry",
                        retry_actor,
                    )
                    .await
                {
                    Ok(retry) => retry,
                    Err(e) => {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "NetworkDistribution, can not create retry actor: {}",
                            e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        TARGET_DISTRIBUTOR,
                        "NetworkDistribution, can not send retry message to retry actor: {}",
                        e
                    );
                    return Err(emit_fail(ctx, e).await);
                };
            }
            DistributorMessage::NetworkResponse { sender } => {
                if sender == self.node {
                    let distribution_path = ctx.path().parent();

                    let distribution_actor: Option<ActorRef<Distribution>> =
                        ctx.system().get_actor(&distribution_path).await;

                    if let Some(distribution_actor) = distribution_actor {
                        if let Err(e) = distribution_actor
                            .tell(DistributionMessage::Response {
                                sender: self.node.clone(),
                            })
                            .await
                        {
                            error!(
                                TARGET_DISTRIBUTOR,
                                "NetworkResponse, can not send response to distribution actor: {}",
                                e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    } else {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "NetworkResponse, can not obtain distribution actor"
                        );
                        let e = ActorError::NotFound(distribution_path);
                        return Err(emit_fail(ctx, e).await);
                    }

                    'retry: {
                        let Some(retry) = ctx
                            .get_child::<RetryActor<RetryNetwork>>("retry")
                            .await
                        else {
                            // Aquí me da igual, porque al parar este actor para el hijo
                            break 'retry;
                        };

                        if let Err(e) = retry.tell(RetryMessage::End).await {
                            error!(
                                TARGET_DISTRIBUTOR,
                                "NetworkResponse, can not end retry actor: {}",
                                e
                            );
                            // Aquí me da igual, porque al parar este actor para el hijo
                            break 'retry;
                        };
                    }

                    ctx.stop(None).await;
                }
            }
            DistributorMessage::LastEventDistribution {
                event,
                ledger,
                info,
                last_proof,
                last_vali_res,
                sender,
            } => {
                let auth_data = AuthGovData {
                    gov_version: Some(ledger.content.gov_version),
                    schema_id: last_proof.schema_id.clone(),
                    namespace: last_proof.namespace.clone(),
                    governance_id: last_proof.governance_id.clone(),
                };

                let schema_id = last_proof.schema_id.clone();

                if let Err(e) = self
                    .check_auth(
                        ctx,
                        event.signature.signer.clone(),
                        info.clone(),
                        ledger.content.clone(),
                        auth_data,
                        sender.clone(),
                    )
                    .await
                {
                    error!(
                        TARGET_DISTRIBUTOR,
                        "LastEventDistribution, can not check auth: {}", e
                    );
                    if let ActorError::Functional(_) = e {
                        return Err(e);
                    } else {
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                // Llegados a este punto hemos verificado si es la primera copia o no,
                // Si es una gobernanza y está authorizada o el firmante del evento tiene el rol
                // de creator.

                // Ahora hay que crear el sujeto si no existe sn = 0, o aplicar los eventos
                // verificando los hashes y aplicando el patch.
                let subject_id = &ledger.content.subject_id.to_string();
                let (owner, new_owner) = if ledger
                    .content
                    .event_request
                    .content
                    .is_create_event()
                {
                    // Creamos el sujeto.
                    if let Err(e) =
                        self.create_subject(ctx, ledger.clone()).await
                    {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "LastEventDistribution, can not crate new subject: {}",
                            e
                        );
                        if let ActorError::Functional(_) = e {
                            return Err(e);
                        } else {
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                    (
                        ledger
                            .content
                            .event_request
                            .signature
                            .signer
                            .to_string(),
                        None,
                    )
                } else {
                    let data = match get_node_subject_data(ctx, subject_id)
                        .await
                    {
                        Ok(data) => data,
                        Err(e) => {
                            let e =
                                format!("Can not get node subject data: {}", e);
                            error!(
                                TARGET_DISTRIBUTOR,
                                "LastEventDistribution, {}", e
                            );
                            return Err(emit_fail(
                                ctx,
                                ActorError::FunctionalFail(e),
                            )
                            .await);
                        }
                    };
                    let (old_owner, old_new_owner) =
                        if let Some((subject_data, new_owner)) = data {
                            (subject_data.owner, new_owner)
                        } else {
                            return Err(ActorError::Functional(
                                "Can not get node subject data".to_owned(),
                            ));
                        };

                    if !Self::is_up_subject(
                        &self.node.to_string(),
                        &old_owner,
                        old_new_owner,
                        schema_id.clone(),
                    ) && let Err(e) =
                        Self::up_subject(ctx, subject_id, false).await
                    {
                        let e = format!("Can not up know subject: {}", e);
                        error!(
                            TARGET_DISTRIBUTOR,
                            "LastEventDistribution, {}", e
                        );
                        return Err(emit_fail(
                            ctx,
                            ActorError::FunctionalFail(e),
                        )
                        .await);
                    }

                    match update_ledger(
                        ctx,
                        subject_id,
                        vec![ledger.clone()],
                        schema_id.is_gov(),
                    )
                    .await
                    {
                        Ok((last_sn, owner, new_owner)) => {
                            let owner = owner.to_string();
                            let new_owner = new_owner.map(|x| x.to_string());

                            // NO se aplicó el evento porque tendría un sn demasiado grande, no es el que toca o ya está aplicado.
                            // Si fue demasiado grande
                            if last_sn < ledger.content.sn {
                                let gov = match get_gov(ctx, subject_id).await {
                                    Ok(gov) => gov,
                                    Err(e) => {
                                        error!(
                                            TARGET_DISTRIBUTOR,
                                            "LastEventDistribution, can not obtain governance: {}",
                                            e
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                };

                                let our_gov_version = gov.version;

                                let new_info = ComunicateInfo {
                                    receiver: sender,
                                    request_id: info.request_id,
                                    version: info.version,
                                    receiver_actor: format!(
                                        "/user/node/distributor_{}",
                                        subject_id
                                    ),
                                };

                                let helper: Option<HelperService> =
                                    ctx.system().get_helper("network").await;

                                let Some(mut helper) = helper else {
                                    error!(
                                        TARGET_DISTRIBUTOR,
                                        "LastEventDistribution, can not obtain network helper"
                                    );
                                    let e = ActorError::NotHelper(
                                        "network".to_owned(),
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };

                                // Pedimos copia del ledger.
                                if let Err(e) = helper.send_command(network::CommandHelper::SendMessage {
                                    message: NetworkMessage {
                                    info: new_info,
                                    message: ActorMessage::DistributionLedgerReq {
                                        gov_version: Some(our_gov_version),
                                        actual_sn: Some(last_sn),
                                        subject_id: ledger.content.subject_id.clone(),
                                    },
                                },
                            }).await {
                                error!(TARGET_DISTRIBUTOR, "LastEventDistribution, can not send response to network: {}", e);
                                return Err(emit_fail(ctx, e).await);
                            };

                                if let Err(e) = self
                                    .down_tracker(
                                        ctx, subject_id, &owner, new_owner,
                                        schema_id,
                                    )
                                    .await
                                {
                                    error!(
                                        TARGET_DISTRIBUTOR,
                                        "LastEventDistribution, can not down know subject: {}",
                                        e
                                    );
                                    return Err(e);
                                }

                                return Ok(());
                            }

                            (owner, new_owner)
                        }
                        Err(e) => {
                            let error =
                                format!("Can not update subject ledger: {}", e);
                            error!(
                                TARGET_DISTRIBUTOR,
                                "LastEventDistribution, {}", error
                            );

                            if let ActorError::Functional(_) = e.clone() {
                                return Err(e);
                            } else {
                                return Err(emit_fail(ctx, e).await);
                            }
                        }
                    }
                };

                'update: {
                    let update = match update_last_state(
                        ctx,
                        event.clone(),
                        last_proof,
                        last_vali_res,
                    )
                    .await
                    {
                        Ok(update) => update,
                        Err(e) => {
                            error!(
                                TARGET_DISTRIBUTOR,
                                "LastEventDistribution, can not update last state: {}",
                                e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                    if !update {
                        break 'update;
                    }

                    let objetive = if info.request_id.is_empty() {
                        format!(
                            "node/{}/distribution",
                            event.content.subject_id
                        )
                    } else {
                        info.request_id.clone()
                    };

                    let new_info = ComunicateInfo {
                        receiver: sender,
                        request_id: info.request_id,
                        version: info.version,
                        receiver_actor: format!(
                            "/user/{}/{}",
                            objetive,
                            info.receiver.clone()
                        ),
                    };

                    let helper: Option<HelperService> =
                        ctx.system().get_helper("network").await;

                    let Some(mut helper) = helper else {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "LastEventDistribution, can not obtain network helper"
                        );
                        let e = ActorError::NotHelper("network".to_owned());
                        return Err(emit_fail(ctx, e).await);
                    };

                    if let Err(e) = helper
                        .send_command(network::CommandHelper::SendMessage {
                            message: NetworkMessage {
                                info: new_info,
                                message: ActorMessage::DistributionLastEventRes,
                            },
                        })
                        .await
                    {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "LastEventDistribution, can not send response to network: {}",
                            e
                        );
                        return Err(emit_fail(ctx, e).await);
                    };
                }

                if let Err(e) = self
                    .down_tracker(ctx, subject_id, &owner, new_owner, schema_id)
                    .await
                {
                    error!(
                        TARGET_DISTRIBUTOR,
                        "LastEventDistribution, can not down know subject: {}",
                        e
                    );
                }
            }
            DistributorMessage::LedgerDistribution {
                mut events,
                info,
                last_state,
                namespace,
                schema_id,
                governance_id,
                sender,
            } => {
                if events.is_empty() {
                    warn!(
                        TARGET_DISTRIBUTOR,
                        "LedgerDistribution, events is empty"
                    );
                    return Err(ActorError::Functional(
                        "Events is empty".to_owned(),
                    ));
                }

                let auth_data = AuthGovData {
                    gov_version: None,
                    schema_id: schema_id.clone(),
                    namespace: namespace.clone(),
                    governance_id: governance_id.clone(),
                };

                if let Err(e) = self
                    .check_auth(
                        ctx,
                        events[0].signature.signer.clone(),
                        info.clone(),
                        events[0].content.clone(),
                        auth_data,
                        sender.clone(),
                    )
                    .await
                {
                    error!(
                        TARGET_DISTRIBUTOR,
                        "LedgerDistribution, can not check auth: {}", e
                    );
                    if let ActorError::Functional(_) = e {
                        return Err(e);
                    } else {
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                let subject_id_digest = events[0].content.subject_id.clone();
                let subject_id = &subject_id_digest.to_string();

                let (old_owner, old_new_owner, old_sn) = if events[0]
                    .content
                    .event_request
                    .content
                    .is_create_event()
                {
                    // Creamos el sujeto.
                    if let Err(e) =
                        self.create_subject(ctx, events[0].clone()).await
                    {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "LedgerDistribution, can not create new subject: {}",
                            e
                        );
                        if let ActorError::Functional(_) = e {
                            return Err(e);
                        } else {
                            return Err(emit_fail(ctx, e).await);
                        }
                    };
                    let event = events.remove(0);
                    (
                        event
                            .content
                            .event_request
                            .signature
                            .signer
                            .to_string(),
                        None,
                        0,
                    )
                } else {
                    let data = match get_node_subject_data(ctx, subject_id)
                        .await
                    {
                        Ok(data) => data,
                        Err(e) => {
                            let e =
                                format!("Can not get node subject data: {}", e);
                            error!(
                                TARGET_DISTRIBUTOR,
                                "LastEventDistribution, {}", e
                            );
                            return Err(emit_fail(
                                ctx,
                                ActorError::FunctionalFail(e),
                            )
                            .await);
                        }
                    };
                    let (old_owner, old_new_owner, sn) =
                        if let Some((subject_data, new_owner)) = data {
                            (subject_data.owner, new_owner, subject_data.sn)
                        } else {
                            return Err(ActorError::Functional(
                                "Can not get node subject data".to_owned(),
                            ));
                        };

                    if !Self::is_up_subject(
                        &self.node.to_string(),
                        &old_owner,
                        old_new_owner.clone(),
                        schema_id.clone(),
                    ) && let Err(e) =
                        Self::up_subject(ctx, subject_id, false).await
                    {
                        let e = format!("Can not up know subject: {}", e);
                        error!(
                            TARGET_DISTRIBUTOR,
                            "LastEventDistribution, {}", e
                        );
                        return Err(emit_fail(
                            ctx,
                            ActorError::FunctionalFail(e),
                        )
                        .await);
                    }

                    (old_owner, old_new_owner, sn)
                };

                let (actual_sn, owner, new_owner) = if !events.is_empty() {
                    let last_ledger_sn =
                        events.last().map(|x| x.content.sn).unwrap_or_default();
                    if last_ledger_sn > old_sn {
                        match update_ledger(
                            ctx,
                            subject_id,
                            events,
                            schema_id.is_gov(),
                        )
                        .await
                        {
                            Ok((last_sn, owner, new_owner)) => (
                                last_sn,
                                owner.to_string(),
                                new_owner.map(|x| x.to_string()),
                            ),
                            Err(e) => {
                                let error = format!(
                                    "Can not update subject ledger: {}",
                                    e
                                );
                                error!(
                                    TARGET_DISTRIBUTOR,
                                    "LedgerDistribution, {}", error
                                );

                                if let ActorError::Functional(_) = e.clone() {
                                    return Err(e);
                                } else {
                                    return Err(emit_fail(ctx, e).await);
                                }
                            }
                        }
                    } else {
                        (old_sn, old_owner, old_new_owner)
                    }
                } else {
                    (old_sn, old_owner, old_new_owner)
                };

                if let Some(last_state) = last_state {
                    let LastStateData {
                        event,
                        proof,
                        vali_res,
                    } = last_state;

                    match actual_sn.cmp(&event.content.sn) {
                        std::cmp::Ordering::Less => {
                            // No quiero su Event.
                        }
                        std::cmp::Ordering::Equal => {
                            if let Err(e) =
                                update_last_state(ctx, *event, *proof, vali_res)
                                    .await
                            {
                                error!(
                                    TARGET_DISTRIBUTOR,
                                    "LedgerDistribution, can not update last state: {}",
                                    e
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        }
                        std::cmp::Ordering::Greater => {
                            let our_path = ActorPath::from(format!(
                                "/user/node/distributor_{}",
                                subject_id
                            ));
                            let our_actor: Option<ActorRef<Distributor>> =
                                ctx.system().get_actor(&our_path).await;
                            if let Some(our_actor) = our_actor {
                                if let Err(e) = our_actor
                                    .tell(
                                        DistributorMessage::SendDistribution {
                                            gov_version: Some(
                                                event.content.gov_version,
                                            ),
                                            actual_sn: Some(actual_sn),
                                            subject_id: subject_id.to_string(),
                                            info,
                                            sender,
                                        },
                                    )
                                    .await
                                {
                                    return Err(emit_fail(ctx, e).await);
                                }
                            } else {
                                let e = ActorError::NotFound(our_path);
                                return Err(emit_fail(ctx, e).await);
                            }
                        }
                    };
                } else {
                    let gov_id = if governance_id.is_empty() {
                        subject_id.clone()
                    } else {
                        governance_id.to_string()
                    };

                    let gov_version = match get_gov(ctx, &gov_id.to_string())
                        .await
                    {
                        Ok(gov) => gov.version,
                        Err(e) => {
                            error!(
                                TARGET_DISTRIBUTOR,
                                "LedgerDistribution, can not obtain governance: {}",
                                e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                    let new_info = ComunicateInfo {
                        receiver: sender,
                        request_id: info.request_id,
                        version: info.version,
                        receiver_actor: format!(
                            "/user/node/distributor_{}",
                            subject_id
                        ),
                    };

                    let helper: Option<HelperService> =
                        ctx.system().get_helper("network").await;

                    let Some(mut helper) = helper else {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "LedgerDistribution, can not obtain netowrk helper"
                        );
                        let e = ActorError::NotHelper("network".to_owned());
                        return Err(emit_fail(ctx, e).await);
                    };

                    if let Err(e) = helper
                        .send_command(network::CommandHelper::SendMessage {
                            message: NetworkMessage {
                                info: new_info,
                                message: ActorMessage::DistributionLedgerReq {
                                    gov_version: Some(gov_version),
                                    actual_sn: Some(actual_sn),
                                    subject_id: subject_id_digest,
                                },
                            },
                        })
                        .await
                    {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "LedgerDistribution, can not send response to network: {}",
                            e
                        );
                        return Err(emit_fail(ctx, e).await);
                    };
                }

                // Bajar al sujeto.
                if let Err(e) = self
                    .down_tracker(ctx, subject_id, &owner, new_owner, schema_id)
                    .await
                {
                    error!(
                        TARGET_DISTRIBUTOR,
                        "LedgerDistribution, can not down know subject: {}", e
                    );
                }
            }
        };

        Ok(())
    }

    async fn on_child_error(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Distributor>,
    ) {
        match error {
            ActorError::ReTry => {
                let distribuiton_path = ctx.path().parent();

                // Replication actor.
                let distribuiton_actor: Option<ActorRef<Distribution>> =
                    ctx.system().get_actor(&distribuiton_path).await;

                if let Some(distribuiton_actor) = distribuiton_actor {
                    if let Err(e) = distribuiton_actor
                        .tell(DistributionMessage::Response {
                            sender: self.node.clone(),
                        })
                        .await
                    {
                        error!(
                            TARGET_DISTRIBUTOR,
                            "OnChildError, can not send response to Distribution actor: {}",
                            e
                        );
                        emit_fail(ctx, e).await;
                    }
                } else {
                    let e = ActorError::NotFound(distribuiton_path);
                    error!(
                        TARGET_DISTRIBUTOR,
                        "OnChildError, can not obtain Distribution actor: {}",
                        e
                    );
                    emit_fail(ctx, e).await;
                }
                ctx.stop(None).await;
            }
            _ => {
                error!(TARGET_DISTRIBUTOR, "OnChildError, unexpected error");
            }
        };
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Distributor>,
    ) -> ChildAction {
        error!(TARGET_DISTRIBUTOR, "OnChildFault, {}", error);
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
