// Single source lives in ave-common (feature `verify`), tests included;
// this re-export keeps every core caller on identical behavior.
pub use ave_common::verify::{
    ApprovalVerification, CLOCK_SKEW, build_canonical_tally,
    rebuild_approval_req, terminal_outcome, verify_approval_data,
};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ave_common::{
        ValueWrapper,
        identity::{DigestIdentifier, HashAlgorithm, PublicKey, Signed, TimeStamp},
        verify::{
            ApprovalData, ApprovalReq, ApprovalRes, ApprovalVerification,
            RoleDataRegister, ValidatorError,
        },
    };

    // Pins that the core paths ARE the common functions: any local
    // redefinition instead of the re-export fails here.
    type RebuildFn = fn(
        &ApprovalData,
        &DigestIdentifier,
        u64,
        u64,
        &ValueWrapper,
        &PublicKey,
    ) -> ApprovalReq;
    type VerifyFn =
        for<'x> fn(ApprovalVerification<'x>) -> Result<(), ValidatorError>;
    type OutcomeFn = fn(
        &RoleDataRegister,
        usize,
        usize,
        usize,
        usize,
        TimeStamp,
        TimeStamp,
    ) -> Option<bool>;
    type TallyFn = fn(
        &HashAlgorithm,
        &Signed<ApprovalReq>,
        &HashMap<PublicKey, Signed<ApprovalRes>>,
        &[(Signed<ApprovalRes>, Signed<ApprovalRes>)],
        &HashMap<PublicKey, Vec<Signed<ApprovalRes>>>,
        bool,
    ) -> Result<ApprovalData, ValidatorError>;

    #[test]
    fn reexports_are_common_fns() {
        const CORE_REBUILD: RebuildFn =
            crate::approval::verify::rebuild_approval_req;
        const COMMON_REBUILD: RebuildFn =
            ave_common::verify::rebuild_approval_req;
        assert!(std::ptr::fn_addr_eq(CORE_REBUILD, COMMON_REBUILD));

        const CORE_VERIFY: VerifyFn =
            crate::approval::verify::verify_approval_data;
        const COMMON_VERIFY: VerifyFn =
            ave_common::verify::verify_approval_data;
        assert!(std::ptr::fn_addr_eq(CORE_VERIFY, COMMON_VERIFY));

        const CORE_OUTCOME: OutcomeFn =
            crate::approval::verify::terminal_outcome;
        const COMMON_OUTCOME: OutcomeFn =
            ave_common::verify::terminal_outcome;
        assert!(std::ptr::fn_addr_eq(CORE_OUTCOME, COMMON_OUTCOME));

        const CORE_TALLY: TallyFn =
            crate::approval::verify::build_canonical_tally;
        const COMMON_TALLY: TallyFn =
            ave_common::verify::build_canonical_tally;
        assert!(std::ptr::fn_addr_eq(CORE_TALLY, COMMON_TALLY));
    }
}
