//! Shared verification of approval evidence.
//!
//! The same rules are checked by validators accepting an approval
//! request, validators verifying the closed evidence inside a
//! validation request, and nodes applying a committed governance
//! event: the approval request is rebuilt from anchored data, every
//! vote signature is verified against it, double votes are excluded
//! from both tallies, and the outcome must follow the quorum rules of
//! the approver set.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use ave_common::{
    ValueWrapper,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signature, Signed,
        TimeStamp, hash_borsh,
    },
};

use crate::{
    approval::{request::ApprovalReq, response::ApprovalRes},
    governance::role_register::RoleDataRegister,
    model::event::ApprovalData,
    validation::response::ValidatorError,
};

/// Clock skew tolerated when evaluating time-based approval rules: the
/// deadline comparison must not reject an honest tally because the
/// verifier's clock lags a few seconds behind the signers'.
pub const CLOCK_SKEW: Duration = Duration::from_secs(60);

fn now_plus_skew(now: TimeStamp) -> TimeStamp {
    TimeStamp::from_nanos(
        now.as_nanos().saturating_add(CLOCK_SKEW.as_nanos() as u64),
    )
}

/// Rebuilds the approval request from the data every verifier can anchor
/// independently: the evidence carries the signature and the timestamps,
/// everything else comes from the event under verification.
pub fn rebuild_approval_req(
    approval: &ApprovalData,
    subject_id: &DigestIdentifier,
    sn: u64,
    gov_version: u64,
    patch: &ValueWrapper,
    signer: &PublicKey,
) -> ApprovalReq {
    ApprovalReq {
        subject_id: subject_id.clone(),
        sn,
        gov_version,
        patch: patch.clone(),
        signer: signer.clone(),
        issued_at: approval.issued_at,
        deadline: approval.deadline,
    }
}

fn sorted_unique_by_signer(signatures: &[Signature]) -> bool {
    signatures
        .windows(2)
        .all(|pair| pair[0].signer < pair[1].signer)
}

/// Terminal condition of an approval collection, evaluated over the
/// votes observed so far. Returns `None` while the collection must keep
/// waiting: acceptance needs `agrees >= quorum`, rejection needs the
/// remaining approvers unable to reach quorum, and past the deadline the
/// absent approvers are counted as acceptances — but only the ones whose
/// absence is proven: double voters (their conflicting pair is the
/// evidence) and approvers with a timeout attested by at least the
/// validation quorum of validators. An unaccounted approver never counts.
///
/// The deadline comparison uses the caller's clock as-is: the owner who
/// closes the collection must not close early. Verifiers tolerate clock
/// lag through [`CLOCK_SKEW`] in [`verify_approval_data`].
pub fn terminal_outcome(
    approvers: &RoleDataRegister,
    agrees: usize,
    disagrees: usize,
    double_voters: usize,
    attested_timeouts: usize,
    deadline: TimeStamp,
    now: TimeStamp,
) -> Option<bool> {
    let total = approvers.workers.len() as u32;
    let quorum = approvers.quorum.get_signers(total, total);
    let agrees = agrees as u32;
    let disagrees = disagrees as u32;
    let double_voters = double_voters as u32;
    let attested_timeouts = attested_timeouts as u32;

    if approvers.quorum.check_quorum(total, agrees) {
        return Some(true);
    }

    if total.saturating_sub(disagrees + double_voters) < quorum {
        return Some(false);
    }

    if now >= deadline {
        let absent = double_voters + attested_timeouts;
        return Some(approvers.quorum.check_quorum(total, agrees + absent));
    }

    None
}

/// Builds the canonical tally from the votes collected by the requester:
/// one vote per approver, double voters excluded with their conflicting
/// pair as evidence, validator-signed timeout attestations grouped per
/// absent approver, every list ordered by signer public key so all
/// validators reconstruct (and hash) the exact same `ApprovalData`.
///
/// Answer-wins is enforced here too: timeout attestations for an approver
/// that voted (or double voted) are dropped, so a vote and a timeout for
/// the same approver never coexist in the evidence.
pub fn build_canonical_tally(
    hash: &HashAlgorithm,
    approval_req: &Signed<ApprovalReq>,
    votes: &HashMap<PublicKey, Signed<ApprovalRes>>,
    double_votes: &[(Signed<ApprovalRes>, Signed<ApprovalRes>)],
    timeouts: &HashMap<PublicKey, Vec<Signed<ApprovalRes>>>,
    approved: bool,
) -> Result<ApprovalData, ValidatorError> {
    let approval_req_hash = hash_borsh(&*hash.hasher(), approval_req.content())
        .map_err(|e| ValidatorError::InternalError {
            problem: e.to_string(),
        })?;

    let mut agrees: Vec<Signature> = Vec::new();
    let mut disagrees: Vec<Signature> = Vec::new();
    for vote in votes.values() {
        let ApprovalRes::Response { agrees: yes, .. } = vote.content() else {
            continue;
        };
        if *yes {
            agrees.push(vote.signature().clone());
        } else {
            disagrees.push(vote.signature().clone());
        }
    }
    agrees.sort_by(|a, b| a.signer.cmp(&b.signer));
    disagrees.sort_by(|a, b| a.signer.cmp(&b.signer));

    let mut doubles: Vec<(Signature, Signature)> = double_votes
        .iter()
        .map(|(accept, reject)| {
            (accept.signature().clone(), reject.signature().clone())
        })
        .collect();
    doubles.sort_by(|a, b| a.0.signer.cmp(&b.0.signer));

    let mut approvers_timeouts: Vec<(PublicKey, Vec<Signature>)> = timeouts
        .iter()
        .filter(|(approver, _)| {
            !votes.contains_key(*approver)
                && !double_votes
                    .iter()
                    .any(|(accept, _)| accept.signature().signer == **approver)
        })
        .map(|(approver, attestations)| {
            let mut sigs: Vec<Signature> = attestations
                .iter()
                .map(|signed| signed.signature().clone())
                .collect();
            sigs.sort_by(|a, b| a.signer.cmp(&b.signer));
            (approver.clone(), sigs)
        })
        .collect();
    approvers_timeouts.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(ApprovalData {
        approval_req_signature: approval_req.signature().clone(),
        approval_req_hash,
        issued_at: approval_req.content().issued_at,
        deadline: approval_req.content().deadline,
        approvers_agrees_signatures: agrees,
        approvers_disagrees_signatures: disagrees,
        double_votes: doubles,
        approvers_timeouts,
        approved,
    })
}

/// Everything needed to verify an `ApprovalData` against the event it
/// belongs to. All inputs are anchored in the ledger event or in the
/// pre-event governance state, so verification is deterministic.
pub struct ApprovalVerification<'a> {
    pub hash: &'a HashAlgorithm,
    pub approval: &'a ApprovalData,
    pub approvers: &'a RoleDataRegister,
    pub validators: &'a RoleDataRegister,
    pub req_subject_data_hash: &'a DigestIdentifier,
    pub subject_id: &'a DigestIdentifier,
    pub sn: u64,
    pub gov_version: u64,
    pub patch: &'a ValueWrapper,
    pub signer: &'a PublicKey,
    pub now: TimeStamp,
}

pub fn verify_approval_data(
    input: ApprovalVerification,
) -> Result<(), ValidatorError> {
    let approval = input.approval;

    if input.signer != &approval.approval_req_signature.signer {
        return Err(ValidatorError::InvalidSigner {
            signer: input.signer.to_string(),
        });
    }

    // The approval request is fully determined by the event under
    // verification and the verified evaluation evidence (the patch), so
    // it is rebuilt here: the stored request signature must verify
    // cryptographically over it and the stored request hash must
    // reproduce exactly. The approval evidence hashes the request
    // CONTENT, not the signed envelope (unlike compilation and
    // evaluation).
    let approval_req = rebuild_approval_req(
        approval,
        input.subject_id,
        input.sn,
        input.gov_version,
        input.patch,
        input.signer,
    );
    let signed_approval_req = Signed::from_parts(
        approval_req.clone(),
        approval.approval_req_signature.clone(),
    );
    if signed_approval_req.verify().is_err() {
        return Err(ValidatorError::InvalidSignature {
            data: "approval request",
        });
    }
    let recomputed_req_hash = hash_borsh(&*input.hash.hasher(), &approval_req)
        .map_err(|e| ValidatorError::InternalError {
            problem: e.to_string(),
        })?;
    if recomputed_req_hash != approval.approval_req_hash {
        return Err(ValidatorError::InvalidData {
            value: "approval request hash",
        });
    }

    if approval.deadline <= approval.issued_at {
        return Err(ValidatorError::InvalidData {
            value: "approval deadline",
        });
    }

    // The tally is canonical: every list is ordered by signer public key
    // and holds each signer at most once, so its hash is unambiguous. The
    // timeouts are ordered by approver key and each attestation list by
    // validator key.
    if !sorted_unique_by_signer(&approval.approvers_agrees_signatures)
        || !sorted_unique_by_signer(&approval.approvers_disagrees_signatures)
        || !approval
            .double_votes
            .windows(2)
            .all(|pair| pair[0].0.signer < pair[1].0.signer)
        || !approval
            .approvers_timeouts
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
        || !approval
            .approvers_timeouts
            .iter()
            .all(|(_, sigs)| sorted_unique_by_signer(sigs))
    {
        return Err(ValidatorError::InvalidData {
            value: "approval votes order",
        });
    }

    let workers = &input.approvers.workers;

    let agrees_res = ApprovalRes::Response {
        approval_req_hash: approval.approval_req_hash.clone(),
        agrees: true,
        req_subject_data_hash: input.req_subject_data_hash.clone(),
    };
    let disagrees_res = ApprovalRes::Response {
        approval_req_hash: approval.approval_req_hash.clone(),
        agrees: false,
        req_subject_data_hash: input.req_subject_data_hash.clone(),
    };

    let mut agreed: HashSet<PublicKey> = HashSet::new();
    for signature in approval.approvers_agrees_signatures.iter() {
        if !workers.contains(&signature.signer) {
            return Err(ValidatorError::InvalidOperation {
                action: "verify approval signers",
            });
        }
        let signed_res =
            Signed::from_parts(agrees_res.clone(), signature.clone());
        if signed_res.verify().is_err() {
            return Err(ValidatorError::InvalidSignature {
                data: "approval agrees",
            });
        }
        agreed.insert(signature.signer.clone());
    }

    let mut disagreed: HashSet<PublicKey> = HashSet::new();
    for signature in approval.approvers_disagrees_signatures.iter() {
        if !workers.contains(&signature.signer) {
            return Err(ValidatorError::InvalidOperation {
                action: "verify approval signers",
            });
        }
        let signed_res =
            Signed::from_parts(disagrees_res.clone(), signature.clone());
        if signed_res.verify().is_err() {
            return Err(ValidatorError::InvalidSignature {
                data: "approval disagrees",
            });
        }
        if agreed.contains(&signature.signer) {
            return Err(ValidatorError::InvalidData {
                value: "approval votes overlap",
            });
        }
        disagreed.insert(signature.signer.clone());
    }

    // Each double-vote pair is verified as evidence: same signer, same
    // request hash, opposite votes, both signatures valid. The signer is
    // excluded from both tallies and counts as absent.
    let mut double_signers: HashSet<PublicKey> = HashSet::new();
    for (accept, reject) in approval.double_votes.iter() {
        if accept.signer != reject.signer {
            return Err(ValidatorError::InvalidData {
                value: "approval double vote pair",
            });
        }
        if !workers.contains(&accept.signer) {
            return Err(ValidatorError::InvalidOperation {
                action: "verify approval signers",
            });
        }
        if agreed.contains(&accept.signer) || disagreed.contains(&accept.signer)
        {
            return Err(ValidatorError::InvalidData {
                value: "approval votes overlap",
            });
        }
        if Signed::from_parts(agrees_res.clone(), accept.clone())
            .verify()
            .is_err()
            || Signed::from_parts(disagrees_res.clone(), reject.clone())
                .verify()
                .is_err()
        {
            return Err(ValidatorError::InvalidSignature {
                data: "approval double vote",
            });
        }
        double_signers.insert(accept.signer.clone());
    }

    // Each timeout attestation is verified as evidence: the attested
    // approver belongs to the approver set and did NOT vote (a late answer
    // wins over the timeout, so both can never coexist), every attesting
    // signature verifies over `ApprovalRes::TimeOut` for this request and
    // approver, every attester belongs to the validator set, and the
    // attestation count reaches the validation quorum — below it a single
    // malicious validator could fabricate absences. This is what blocks
    // owner censorship: an approver whose vote is missing from the
    // evidence must appear here, or the accounting below fails.
    let validator_workers = &input.validators.workers;
    let validators_total = validator_workers.len() as u32;
    let mut timed_out: HashSet<PublicKey> = HashSet::new();
    for (approver, attestations) in approval.approvers_timeouts.iter() {
        if !workers.contains(approver) {
            return Err(ValidatorError::InvalidOperation {
                action: "verify approval signers",
            });
        }
        if agreed.contains(approver)
            || disagreed.contains(approver)
            || double_signers.contains(approver)
        {
            return Err(ValidatorError::InvalidData {
                value: "approval timeout overlaps vote",
            });
        }
        let timeout_res = ApprovalRes::TimeOut {
            approval_req_hash: approval.approval_req_hash.clone(),
            who: approver.clone(),
        };
        for signature in attestations.iter() {
            if !validator_workers.contains(&signature.signer) {
                return Err(ValidatorError::InvalidOperation {
                    action: "verify approval timeout signers",
                });
            }
            if Signed::from_parts(timeout_res.clone(), signature.clone())
                .verify()
                .is_err()
            {
                return Err(ValidatorError::InvalidSignature {
                    data: "approval timeout",
                });
            }
        }
        if !input
            .validators
            .quorum
            .check_quorum(validators_total, attestations.len() as u32)
        {
            return Err(ValidatorError::InvalidOperation {
                action: "verify approval timeout quorum",
            });
        }
        timed_out.insert(approver.clone());
    }

    let total = workers.len() as u32;
    let quorum = input.approvers.quorum.get_signers(total, total);
    let n_agrees = agreed.len() as u32;
    let n_disagrees = disagreed.len() as u32;
    let n_doubles = double_signers.len() as u32;
    let n_timeouts = timed_out.len() as u32;
    let deadline_passed = now_plus_skew(input.now) >= approval.deadline;

    // Full accounting: every approver must be explained by a vote, a
    // double-vote pair or an attested timeout. Without it the owner could
    // censor a received vote by making the approver pass as absent.
    let accounting_complete =
        n_agrees + n_disagrees + n_doubles + n_timeouts == total;

    // Timeout attestations only exist in a deadline closure: an early
    // closure carrying them is contradictory evidence.
    if !approval.approvers_timeouts.is_empty() && !deadline_passed {
        return Err(ValidatorError::InvalidData {
            value: "approval timeouts before deadline",
        });
    }

    // The absent counted by the deadline rule are the proven ones:
    // double voters and attested timeouts.
    let absent = n_doubles + n_timeouts;

    let early_valid = if approval.approved {
        input.approvers.quorum.check_quorum(total, n_agrees)
    } else {
        total.saturating_sub(n_disagrees + n_doubles) < quorum
    };

    let deadline_valid = deadline_passed
        && accounting_complete
        && if approval.approved {
            input
                .approvers
                .quorum
                .check_quorum(total, n_agrees + absent)
        } else {
            !input
                .approvers
                .quorum
                .check_quorum(total, n_agrees + absent)
        };

    let valid = if approval.approvers_timeouts.is_empty() {
        // No attestations: an early closure, or a deadline closure where
        // every absent is a double voter.
        early_valid || deadline_valid
    } else {
        deadline_valid
    };

    if !valid {
        return Err(ValidatorError::InvalidOperation {
            action: "verify approval quorum",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::model::Quorum;
    use ave_common::identity::{KeyPair, keys::Ed25519Signer};

    fn key(signer: &Ed25519Signer) -> PublicKey {
        KeyPair::Ed25519(signer.clone()).public_key()
    }

    fn approvers(
        signers: &[Ed25519Signer],
        quorum: Quorum,
    ) -> RoleDataRegister {
        RoleDataRegister {
            workers: signers.iter().map(key).collect(),
            quorum,
        }
    }

    fn three_approvers() -> Vec<Ed25519Signer> {
        vec![
            Ed25519Signer::generate().unwrap(),
            Ed25519Signer::generate().unwrap(),
            Ed25519Signer::generate().unwrap(),
        ]
    }

    struct ApprovalFixture {
        hash: HashAlgorithm,
        owner: Ed25519Signer,
        approvers: Vec<Ed25519Signer>,
        validators: Vec<Ed25519Signer>,
        subject_id: DigestIdentifier,
        patch: ValueWrapper,
        req_subject_data_hash: DigestIdentifier,
        issued_at: TimeStamp,
        deadline: TimeStamp,
        sn: u64,
        gov_version: u64,
    }

    impl ApprovalFixture {
        fn new(window_nanos: u64) -> Self {
            let owner = Ed25519Signer::generate().unwrap();
            let issued_at = TimeStamp::now();
            let deadline =
                TimeStamp::from_nanos(issued_at.as_nanos() + window_nanos);
            Self {
                hash: HashAlgorithm::Blake3,
                owner,
                approvers: three_approvers(),
                validators: three_approvers(),
                subject_id: hash_borsh(
                    &*HashAlgorithm::Blake3.hasher(),
                    &b"subject".to_vec(),
                )
                .unwrap(),
                patch: ValueWrapper(serde_json::json!([
                    { "op": "replace", "path": "/version", "value": 1 }
                ])),
                req_subject_data_hash: hash_borsh(
                    &*HashAlgorithm::Blake3.hasher(),
                    &b"subject data".to_vec(),
                )
                .unwrap(),
                issued_at,
                deadline,
                sn: 1,
                gov_version: 0,
            }
        }

        fn signed_req(&self) -> Signed<ApprovalReq> {
            Signed::new(
                ApprovalReq {
                    subject_id: self.subject_id.clone(),
                    sn: self.sn,
                    gov_version: self.gov_version,
                    patch: self.patch.clone(),
                    signer: key(&self.owner),
                    issued_at: self.issued_at,
                    deadline: self.deadline,
                },
                &self.owner,
            )
            .unwrap()
        }

        fn approval_req_hash(&self) -> DigestIdentifier {
            hash_borsh(&*self.hash.hasher(), self.signed_req().content())
                .unwrap()
        }

        fn vote(
            &self,
            approver: &Ed25519Signer,
            agrees: bool,
        ) -> Signed<ApprovalRes> {
            Signed::new(
                ApprovalRes::Response {
                    approval_req_hash: self.approval_req_hash(),
                    agrees,
                    req_subject_data_hash: self.req_subject_data_hash.clone(),
                },
                approver,
            )
            .unwrap()
        }

        fn timeout(
            &self,
            validator: &Ed25519Signer,
            approver: &Ed25519Signer,
        ) -> Signed<ApprovalRes> {
            Signed::new(
                ApprovalRes::TimeOut {
                    approval_req_hash: self.approval_req_hash(),
                    who: key(approver),
                },
                validator,
            )
            .unwrap()
        }

        /// Timeout attestations for `approver` signed by enough validators
        /// to reach the validation quorum (majority of 3 = 2).
        fn attested_timeouts(
            &self,
            approver: &Ed25519Signer,
        ) -> HashMap<PublicKey, Vec<Signed<ApprovalRes>>> {
            HashMap::from([(
                key(approver),
                self.validators
                    .iter()
                    .take(2)
                    .map(|v| self.timeout(v, approver))
                    .collect(),
            )])
        }

        fn verify(
            &self,
            approval: &ApprovalData,
            now: TimeStamp,
        ) -> Result<(), ValidatorError> {
            verify_approval_data(ApprovalVerification {
                hash: &self.hash,
                approval,
                approvers: &approvers(&self.approvers, Quorum::Majority),
                validators: &approvers(&self.validators, Quorum::Majority),
                req_subject_data_hash: &self.req_subject_data_hash,
                subject_id: &self.subject_id,
                sn: self.sn,
                gov_version: self.gov_version,
                patch: &self.patch,
                signer: &key(&self.owner),
                now,
            })
        }
    }

    /// Item 1: quorum rules of the terminal condition — early acceptance,
    /// early rejection, waiting, and the deadline counting only the proven
    /// absent (double voters and attested timeouts).
    #[test]
    fn terminal_outcome_quorum_rules() {
        let set = approvers(&three_approvers(), Quorum::Majority);
        let issued_at = TimeStamp::now();
        let deadline = TimeStamp::from_nanos(issued_at.as_nanos() + 1_000);
        let before = issued_at;

        // Early acceptance: agrees reach quorum (2 of 3).
        assert_eq!(
            terminal_outcome(&set, 2, 0, 0, 0, deadline, before),
            Some(true)
        );
        // Waiting: 1 agree, 0 disagrees, deadline not reached.
        assert_eq!(terminal_outcome(&set, 1, 0, 0, 0, deadline, before), None);
        // Early rejection: 2 disagrees leave 1 possible vote < quorum.
        assert_eq!(
            terminal_outcome(&set, 0, 2, 0, 0, deadline, before),
            Some(false)
        );
        // A double voter counts against the remaining possible votes:
        // 1 disagree + 1 double leave 1 < quorum -> early rejection.
        assert_eq!(
            terminal_outcome(&set, 0, 1, 1, 0, deadline, before),
            Some(false)
        );
        // Deadline: the proven absent count as acceptances (1 agree + 1
        // double + 1 attested timeout).
        assert_eq!(
            terminal_outcome(&set, 1, 0, 1, 1, deadline, deadline),
            Some(true)
        );
        // Deadline without proven absences does not count them: 1 agree +
        // 0 proven < quorum.
        assert_eq!(
            terminal_outcome(&set, 1, 0, 0, 0, deadline, deadline),
            Some(false)
        );
        // Deadline: 5 approvers, quorum 3; 1 agree, 1 disagree, 1 double,
        // 1 attested timeout -> 1 + 2 reach the quorum.
        let five = approvers(
            &[
                Ed25519Signer::generate().unwrap(),
                Ed25519Signer::generate().unwrap(),
                Ed25519Signer::generate().unwrap(),
                Ed25519Signer::generate().unwrap(),
                Ed25519Signer::generate().unwrap(),
            ],
            Quorum::Majority,
        );
        assert_eq!(
            terminal_outcome(&five, 1, 1, 1, 1, deadline, deadline),
            Some(true)
        );
        // Same votes before the deadline keep waiting (5 - 2 = 3 >= 3).
        assert_eq!(terminal_outcome(&five, 1, 1, 1, 0, deadline, before), None);
    }

    /// Items 2 and 3: the canonical tally excludes double voters with
    /// their pair as evidence, orders every list by signer and is
    /// deterministic regardless of vote insertion order.
    #[test]
    fn canonical_tally_excludes_doubles_and_is_deterministic() {
        let fixture = ApprovalFixture::new(1_000);
        let signed_req = fixture.signed_req();

        let accept_a = fixture.vote(&fixture.approvers[0], true);
        let accept_b = fixture.vote(&fixture.approvers[1], true);
        let reject_b = fixture.vote(&fixture.approvers[1], false);

        let mut votes = HashMap::new();
        votes.insert(key(&fixture.approvers[0]), accept_a.clone());
        let double_votes = vec![(accept_b.clone(), reject_b.clone())];

        let tally = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &double_votes,
            &HashMap::new(),
            true,
        )
        .unwrap();

        // The double voter is excluded from both tallies; only the honest
        // vote remains, and the pair travels as evidence.
        assert_eq!(
            tally.approvers_agrees_signatures.len(),
            1,
            "double voter must be excluded from agrees"
        );
        assert_eq!(
            tally.approvers_agrees_signatures[0].signer,
            key(&fixture.approvers[0])
        );
        assert!(tally.approvers_disagrees_signatures.is_empty());
        assert_eq!(tally.double_votes.len(), 1);
        assert_eq!(tally.double_votes[0].0.signer, key(&fixture.approvers[1]));

        // Deterministic: rebuilding from a differently ordered map yields
        // the same hash.
        let mut votes_reversed = HashMap::new();
        votes_reversed.insert(key(&fixture.approvers[0]), accept_a);
        let tally2 = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes_reversed,
            &double_votes,
            &HashMap::new(),
            true,
        )
        .unwrap();
        assert_eq!(
            hash_borsh(&*fixture.hash.hasher(), &tally).unwrap(),
            hash_borsh(&*fixture.hash.hasher(), &tally2).unwrap()
        );

        // Several honest votes come out ordered by signer key.
        let accept_c = fixture.vote(&fixture.approvers[2], true);
        let mut votes_all = HashMap::new();
        votes_all.insert(key(&fixture.approvers[2]), accept_c);
        votes_all.insert(
            key(&fixture.approvers[0]),
            fixture.vote(&fixture.approvers[0], true),
        );
        let tally_all = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes_all,
            &[],
            &HashMap::new(),
            true,
        )
        .unwrap();
        let signers: Vec<_> = tally_all
            .approvers_agrees_signatures
            .iter()
            .map(|s| s.signer.clone())
            .collect();
        let mut sorted = signers.clone();
        sorted.sort();
        assert_eq!(signers, sorted, "tally must be ordered by signer");

        // Timeout attestations come out ordered by approver and by
        // validator, and a vote for the same approver drops its timeouts
        // (answer wins).
        let timeout_approver = fixture.approvers[2].clone();
        let mut timeouts = HashMap::new();
        timeouts.insert(
            key(&timeout_approver),
            vec![
                fixture.timeout(&fixture.validators[2], &timeout_approver),
                fixture.timeout(&fixture.validators[0], &timeout_approver),
            ],
        );
        let tally_to = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &HashMap::new(),
            &[],
            &timeouts,
            true,
        )
        .unwrap();
        assert_eq!(tally_to.approvers_timeouts.len(), 1);
        assert_eq!(tally_to.approvers_timeouts[0].0, key(&timeout_approver));
        let attesters: Vec<_> = tally_to.approvers_timeouts[0]
            .1
            .iter()
            .map(|s| s.signer.clone())
            .collect();
        let mut attesters_sorted = attesters.clone();
        attesters_sorted.sort();
        assert_eq!(attesters, attesters_sorted);

        let votes_with_timeout_approver: HashMap<
            PublicKey,
            Signed<ApprovalRes>,
        > = HashMap::from([(
            key(&timeout_approver),
            fixture.vote(&timeout_approver, true),
        )]);
        let tally_aw = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes_with_timeout_approver,
            &[],
            &timeouts,
            true,
        )
        .unwrap();
        assert!(
            tally_aw.approvers_timeouts.is_empty(),
            "answer must win over the timeout attestations"
        );
    }

    /// Item 5: the evidence verification accepts an honest tally and
    /// rejects every tampering class.
    #[test]
    fn verify_approval_data_accepts_honest_and_rejects_tampering() {
        // A wide window keeps the deadline in the future (even with the
        // verifier clock skew), so early-acceptance rules are exercised.
        let fixture = ApprovalFixture::new(86_400_000_000_000);
        let signed_req = fixture.signed_req();

        let votes: HashMap<PublicKey, Signed<ApprovalRes>> = fixture
            .approvers
            .iter()
            .map(|a| (key(a), fixture.vote(a, true)))
            .collect();
        let honest = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &[],
            &HashMap::new(),
            true,
        )
        .unwrap();

        assert!(
            fixture.verify(&honest, TimeStamp::now()).is_ok(),
            "honest tally must verify"
        );

        // Signer of the request is not the expected one.
        let other = Ed25519Signer::generate().unwrap();
        let wrong_signer = ApprovalVerification {
            hash: &fixture.hash,
            approval: &honest,
            approvers: &approvers(&fixture.approvers, Quorum::Majority),
            validators: &approvers(&fixture.validators, Quorum::Majority),
            req_subject_data_hash: &fixture.req_subject_data_hash,
            subject_id: &fixture.subject_id,
            sn: fixture.sn,
            gov_version: fixture.gov_version,
            patch: &fixture.patch,
            signer: &key(&other),
            now: TimeStamp::now(),
        };
        assert!(matches!(
            verify_approval_data(wrong_signer),
            Err(ValidatorError::InvalidSigner { .. })
        ));

        // Tampered request hash.
        let mut tampered = honest.clone();
        tampered.approval_req_hash =
            hash_borsh(&*fixture.hash.hasher(), &b"tampered".to_vec()).unwrap();
        assert!(matches!(
            fixture.verify(&tampered, TimeStamp::now()),
            Err(ValidatorError::InvalidData { .. })
        ));

        // A vote from outside the approver set.
        let outsider = Ed25519Signer::generate().unwrap();
        let mut outside_votes = votes.clone();
        outside_votes.insert(key(&outsider), fixture.vote(&outsider, true));
        let outside_tally = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &outside_votes,
            &[],
            &HashMap::new(),
            true,
        )
        .unwrap();
        assert!(matches!(
            fixture.verify(&outside_tally, TimeStamp::now()),
            Err(ValidatorError::InvalidOperation { .. })
        ));

        // Duplicated signer breaks the canonical order rule.
        let mut duplicated = honest.clone();
        duplicated
            .approvers_agrees_signatures
            .push(honest.approvers_agrees_signatures[0].clone());
        assert!(matches!(
            fixture.verify(&duplicated, TimeStamp::now()),
            Err(ValidatorError::InvalidData { .. })
        ));

        // Unordered lists break the canonical order rule (three distinct
        // signers reversed are never in ascending order).
        let mut unordered = honest.clone();
        unordered.approvers_agrees_signatures.reverse();
        assert!(matches!(
            fixture.verify(&unordered, TimeStamp::now()),
            Err(ValidatorError::InvalidData { .. })
        ));

        // Quorum not reached: a single agree of three (Majority = 2)
        // claimed as approved before the deadline.
        let one_vote: HashMap<PublicKey, Signed<ApprovalRes>> =
            HashMap::from([(
                key(&fixture.approvers[0]),
                fixture.vote(&fixture.approvers[0], true),
            )]);
        let weak_tally = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &one_vote,
            &[],
            &HashMap::new(),
            true,
        )
        .unwrap();
        assert!(matches!(
            fixture.verify(&weak_tally, TimeStamp::now()),
            Err(ValidatorError::InvalidOperation { .. })
        ));

        // A vote signed over a different request hash: replace the
        // signature of its signer, keep the other two honest votes.
        let mut forged = honest.clone();
        let bad_vote = Signed::new(
            ApprovalRes::Response {
                approval_req_hash: hash_borsh(
                    &*fixture.hash.hasher(),
                    &b"other request".to_vec(),
                )
                .unwrap(),
                agrees: true,
                req_subject_data_hash: fixture.req_subject_data_hash.clone(),
            },
            &fixture.approvers[2],
        )
        .unwrap();
        let bad_signer = key(&fixture.approvers[2]);
        forged.approvers_agrees_signatures = honest
            .approvers_agrees_signatures
            .iter()
            .filter(|s| s.signer != bad_signer)
            .cloned()
            .chain(std::iter::once(bad_vote.signature().clone()))
            .collect();
        forged
            .approvers_agrees_signatures
            .sort_by(|a, b| a.signer.cmp(&b.signer));
        assert!(matches!(
            fixture.verify(&forged, TimeStamp::now()),
            Err(ValidatorError::InvalidSignature { .. })
        ));

        // Deadline not after issued_at: only reachable when the owner
        // signs a request with an invalid window, so the whole evidence
        // is rebuilt with deadline == issued_at.
        let zero_window = ApprovalFixture::new(0);
        let zero_votes: HashMap<PublicKey, Signed<ApprovalRes>> = zero_window
            .approvers
            .iter()
            .map(|a| (key(a), zero_window.vote(a, true)))
            .collect();
        let zero_tally = build_canonical_tally(
            &zero_window.hash,
            &zero_window.signed_req(),
            &zero_votes,
            &[],
            &HashMap::new(),
            true,
        )
        .unwrap();
        assert!(matches!(
            zero_window.verify(&zero_tally, TimeStamp::now()),
            Err(ValidatorError::InvalidData {
                value: "approval deadline"
            })
        ));
    }

    /// Item 2 (verification side): a verified double-vote pair excludes
    /// the signer, who counts as absent without needing timeouts; past the
    /// deadline the tally with the remaining absent attested by validators
    /// verifies.
    #[test]
    fn verify_approval_data_double_vote_counts_absent_after_deadline() {
        let fixture = ApprovalFixture::new(86_400_000_000_000);
        let signed_req = fixture.signed_req();

        let accept = fixture.vote(&fixture.approvers[1], true);
        let reject = fixture.vote(&fixture.approvers[1], false);
        let votes: HashMap<PublicKey, Signed<ApprovalRes>> = HashMap::from([(
            key(&fixture.approvers[0]),
            fixture.vote(&fixture.approvers[0], true),
        )]);
        let timeouts = fixture.attested_timeouts(&fixture.approvers[2]);

        let tally = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &[(accept, reject)],
            &timeouts,
            true,
        )
        .unwrap();

        // Before the deadline: 1 agree of 3 does not reach quorum 2, and
        // timeout attestations are only valid in a deadline closure.
        assert!(fixture.verify(&tally, TimeStamp::now()).is_err());

        // At the deadline: the double voter counts as absent by its pair,
        // the silent approver by the attested timeout; 1 agree + 2 proven
        // absent reach quorum.
        assert!(fixture.verify(&tally, fixture.deadline).is_ok());

        // A forged pair (same side twice) is rejected.
        let forged_pair = vec![(
            fixture.vote(&fixture.approvers[1], true),
            fixture.vote(&fixture.approvers[1], true),
        )];
        let forged_tally = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &forged_pair,
            &timeouts,
            true,
        )
        .unwrap();
        assert!(matches!(
            fixture.verify(&forged_tally, fixture.deadline),
            Err(ValidatorError::InvalidSignature { .. })
        ));
    }

    /// Item 35: owner censorship is blocked — an approver whose vote is
    /// missing from a deadline closure must carry attested timeouts, and
    /// every class of invalid attestation is rejected.
    #[test]
    fn verify_approval_data_blocks_censorship_and_bad_timeouts() {
        let fixture = ApprovalFixture::new(86_400_000_000_000);
        let signed_req = fixture.signed_req();

        // 1 agree of 3 (quorum 2), approver[1] silent. At the deadline
        // the tally needs the silent approver attested to be approved.
        let votes: HashMap<PublicKey, Signed<ApprovalRes>> = HashMap::from([(
            key(&fixture.approvers[0]),
            fixture.vote(&fixture.approvers[0], true),
        )]);

        // Censorship: the silent approver has no vote, no double-vote
        // pair and no timeout — incomplete accounting.
        let censored = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &[],
            &HashMap::new(),
            true,
        )
        .unwrap();
        assert!(matches!(
            fixture.verify(&censored, fixture.deadline),
            Err(ValidatorError::InvalidOperation { .. })
        ));

        // Same censorship claimed as rejected at the deadline: the
        // accounting is still incomplete.
        let censored_reject = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &[],
            &HashMap::new(),
            false,
        )
        .unwrap();
        assert!(matches!(
            fixture.verify(&censored_reject, fixture.deadline),
            Err(ValidatorError::InvalidOperation { .. })
        ));

        // Attestation below the validation quorum (1 of 3, majority 2).
        let weak_timeouts: HashMap<PublicKey, Vec<Signed<ApprovalRes>>> =
            HashMap::from([(
                key(&fixture.approvers[1]),
                vec![
                    fixture
                        .timeout(&fixture.validators[0], &fixture.approvers[1]),
                ],
            )]);
        let weak = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &[],
            &weak_timeouts,
            true,
        )
        .unwrap();
        assert!(matches!(
            fixture.verify(&weak, fixture.deadline),
            Err(ValidatorError::InvalidOperation { .. })
        ));

        // Attester outside the validator set.
        let outsider = Ed25519Signer::generate().unwrap();
        let outside_timeouts: HashMap<PublicKey, Vec<Signed<ApprovalRes>>> =
            HashMap::from([(
                key(&fixture.approvers[1]),
                vec![
                    fixture
                        .timeout(&fixture.validators[0], &fixture.approvers[1]),
                    fixture.timeout(&outsider, &fixture.approvers[1]),
                ],
            )]);
        let outside = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &[],
            &outside_timeouts,
            true,
        )
        .unwrap();
        assert!(matches!(
            fixture.verify(&outside, fixture.deadline),
            Err(ValidatorError::InvalidOperation { .. })
        ));

        // Timeout signed over a different request hash.
        let mut forged_timeouts =
            fixture.attested_timeouts(&fixture.approvers[1]);
        let forged_sig = Signed::new(
            ApprovalRes::TimeOut {
                approval_req_hash: hash_borsh(
                    &*fixture.hash.hasher(),
                    &b"other request".to_vec(),
                )
                .unwrap(),
                who: key(&fixture.approvers[1]),
            },
            &fixture.validators[1],
        )
        .unwrap();
        forged_timeouts
            .get_mut(&key(&fixture.approvers[1]))
            .unwrap()[1] = forged_sig;
        let forged = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &[],
            &forged_timeouts,
            true,
        )
        .unwrap();
        assert!(matches!(
            fixture.verify(&forged, fixture.deadline),
            Err(ValidatorError::InvalidSignature { .. })
        ));

        // Timeout for an approver that also voted: answer wins, both can
        // never coexist. build_canonical_tally drops the timeouts, so
        // craft the overlap by hand to check the verification rejects it.
        let mut overlap_votes = votes.clone();
        overlap_votes.insert(
            key(&fixture.approvers[1]),
            fixture.vote(&fixture.approvers[1], false),
        );
        let mut overlap = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &overlap_votes,
            &[],
            &fixture.attested_timeouts(&fixture.approvers[1]),
            true,
        )
        .unwrap();
        overlap.approvers_timeouts = fixture
            .attested_timeouts(&fixture.approvers[1])
            .into_iter()
            .map(|(who, signed)| {
                let mut sigs: Vec<Signature> =
                    signed.iter().map(|s| s.signature().clone()).collect();
                sigs.sort_by(|a, b| a.signer.cmp(&b.signer));
                (who, sigs)
            })
            .collect();
        assert!(matches!(
            fixture.verify(&overlap, fixture.deadline),
            Err(ValidatorError::InvalidData { .. })
        ));

        // Timeouts in an early closure (deadline not passed) are
        // contradictory evidence.
        let early_with_timeouts = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &[],
            &fixture.attested_timeouts(&fixture.approvers[1]),
            true,
        )
        .unwrap();
        assert!(matches!(
            fixture.verify(&early_with_timeouts, TimeStamp::now()),
            Err(ValidatorError::InvalidData { .. })
        ));

        // The honest deadline closure with attested timeouts verifies:
        // 1 agree + 1 attested timeout reach quorum 2 (approver[2]
        // double-voted).
        let honest = build_canonical_tally(
            &fixture.hash,
            &signed_req,
            &votes,
            &[(
                fixture.vote(&fixture.approvers[2], true),
                fixture.vote(&fixture.approvers[2], false),
            )],
            &fixture.attested_timeouts(&fixture.approvers[1]),
            true,
        )
        .unwrap();
        assert!(
            fixture.verify(&honest, fixture.deadline).is_ok(),
            "deadline closure with attested timeouts must verify"
        );
    }
}
