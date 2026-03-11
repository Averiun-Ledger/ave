#[cfg(all(feature = "sqlite", feature = "rocksdb"))]
compile_error!("Select only one: 'sqlite' or 'rocksdb'");

#[cfg(not(any(feature = "sqlite", feature = "rocksdb")))]
compile_error!("You must enable 'sqlite' or 'rocksdb'");

#[cfg(not(feature = "ext-sqlite"))]
compile_error!("You must enable 'ext-sqlite'");

#[tokio::main]
async fn main() {
    match ave_http::startup::run().await {
        Ok(()) => {}
        Err(error) => {
            eprintln!("ave-http failed: {error}");
            std::process::exit(1);
        }
    }
}
