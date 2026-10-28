//! Registry pins as JSON (`{id: {rustc_version, sdk_version}}`).
//!
//! Machine-readable single source of truth for build scripts
//! (`http/docker/build.sh`): shell never parses `registry.rs` nor
//! reads `ave-pin` audit records as authority. Anything this prints
//! comes straight from the in-tree registry.
fn main() {
    let mut pins = serde_json::Map::new();
    for id in ave_common::governance::registry_ids() {
        if let Some(info) = ave_common::governance::toolchain_info(id) {
            pins.insert(
                (*id).to_owned(),
                serde_json::json!({
                    "rustc_version": info.rustc_version,
                    "sdk_version": info.sdk_version,
                }),
            );
        }
    }
    println!("{}", serde_json::Value::Object(pins));
}
