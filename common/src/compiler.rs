//! Compiler service protobuf types.
//!
//! Generated from `proto/ave/compiler/v1/compiler.proto` (see
//! `common/build.rs`).
//!
//! Single source of truth of the gRPC compiler contract: the compiler
//! service implements `compiler_service_server` and the node builds its
//! client from `compiler_service_client`.
//!
//! Only available with the `compiler-grpc` feature: tonic does not compile
//! for the wasm32 target used by the contract SDK, which depends on this
//! crate.
#[cfg(feature = "compiler-grpc")]
pub mod pb {
    tonic::include_proto!("ave.compiler.v1");
}
