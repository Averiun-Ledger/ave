# ave-compiler

Pure contract compilation pipeline for the Averiun Ledger: project
preparation, cargo build to `wasm32-unknown-unknown`, precompilation and
validation of artifacts through the `ave-contract-sdk` runtime, and artifact
metadata records.

This crate knows how to compile contracts; it has no dependency on the actor
system or on `ave-core`.
