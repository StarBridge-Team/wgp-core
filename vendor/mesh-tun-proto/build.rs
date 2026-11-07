fn main() {
    prost_build::Config::new()
        .compile_protos(
            &["proto/mesh_proto.proto"],
            &["proto/"],
        )
        .unwrap();
}
