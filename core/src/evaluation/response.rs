// Single source lives in ave-common (feature `verify`), wire test included;
// this re-export keeps every core caller on identical behavior.
pub use ave_common::verify::{
    EvalRunnerError, EvaluationRes, EvaluationResult, EvaluatorError,
    EvaluatorResponse, ResponseSummary,
};
