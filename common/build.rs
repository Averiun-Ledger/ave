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
        tonic_build::configure()
            .compile_protos(&["proto/ave/sink/v1/sink.proto"], &["proto"])?;
    }
    Ok(())
}
