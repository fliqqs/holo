fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only the client is generated: the dataplane agent is the server, and it
    // lives in its own repository with a copy of this same .proto.
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(&["../proto/spb_dataplane.proto"], &["../proto"])?;
    Ok(())
}
