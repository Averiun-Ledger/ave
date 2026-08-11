//! Dump the OpenAPI specification to stdout.
//!
//! Regenerate the committed snapshot with:
//!
//! ```sh
//! cargo run -p ave-http --example dump_openapi > http/openapi.json
//! ```

use ave_http::doc::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let json = ApiDoc::openapi()
        .to_pretty_json()
        .expect("failed to serialize OpenAPI specification");
    println!("{json}");
}
