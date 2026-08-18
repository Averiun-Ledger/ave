fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The gRPC sink protobuf types are only needed by the node (feature
    // `sink-grpc`); the contract SDK builds this crate for wasm32 where
    // tonic is not available, so codegen and its build dependencies are
    // compiled out unless the feature is enabled.
    #[cfg(feature = "sink-grpc")]
    {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        // SAFETY: single-threaded build script; the variable is set before
        // any protoc invocation and read only by prost-build.
        unsafe { std::env::set_var("PROTOC", protoc) };
        // prost 0.14 derives `Eq` on its own for Eq-capable messages (no
        // floats), keeping the generated code free of
        // `clippy::derive_partial_eq_without_eq` warnings.
        tonic_prost_build::configure()
            .compile_protos(&["proto/ave/sink/v1/sink.proto"], &["proto"])?;

        // tonic-build (even 0.14) does not emit the server's message-size
        // builder methods as `const fn`, which trips
        // `clippy::missing_const_for_fn`. Their bodies are const-compatible
        // (the client's same-named methods delegate to `self.inner` and are
        // not, so the replacement pins the exact const-compatible body). If
        // a future tonic-build changes the emitted code the replacement
        // becomes a no-op and the warning reappears — visible, never silent
        // breakage.
        let generated = std::path::Path::new(&std::env::var("OUT_DIR")?)
            .join("ave.sink.v1.rs");
        let code = std::fs::read_to_string(&generated)?;
        let code = code
            .replace(
                "pub fn max_decoding_message_size(mut self, limit: usize) -> Self {\n            self.max_decoding_message_size = Some(limit);",
                "pub const fn max_decoding_message_size(mut self, limit: usize) -> Self {\n            self.max_decoding_message_size = Some(limit);",
            )
            .replace(
                "pub fn max_encoding_message_size(mut self, limit: usize) -> Self {\n            self.max_encoding_message_size = Some(limit);",
                "pub const fn max_encoding_message_size(mut self, limit: usize) -> Self {\n            self.max_encoding_message_size = Some(limit);",
            );
        std::fs::write(&generated, code)?;
    }
    Ok(())
}
