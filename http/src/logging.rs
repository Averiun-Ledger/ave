use ave_bridge::{LoggingConfig, LoggingRotation};
use file_rotate::TimeFrequency;
use file_rotate::compression::Compression;
use file_rotate::{ContentLimit, FileRotate, suffix::AppendCount};
use reqwest::Client;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::fmt::{self, writer::BoxMakeWriter};
use tracing_subscriber::{EnvFilter, Registry, prelude::*};

pub struct LoggingHandle {
    _vec: Vec<WorkerGuard>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Secrets embedded in a log endpoint URL must never reach stderr.
    #[test]
    fn log_forwarder_hides_url_secrets() {
        let with_userinfo = sanitize_url_for_log(
            "https://user:token123@logs.example.com/events",
        );
        assert!(!with_userinfo.contains("token123"), "{with_userinfo}");
        assert!(with_userinfo.contains("logs.example.com"), "{with_userinfo}");

        let with_query = sanitize_url_for_log(
            "https://logs.example.com/events?token=abc123",
        );
        assert!(!with_query.contains("abc123"), "{with_query}");
        assert!(with_query.ends_with("?***"), "{with_query}");

        let clean =
            sanitize_url_for_log("https://logs.example.com/events");
        assert_eq!(clean, "https://logs.example.com/events");
    }
}

/// Redacted URL identity for logs: keeps scheme/host/path, hides
/// userinfo and query which may carry tokens.
fn sanitize_url_for_log(url: &str) -> String {
    let without_userinfo = match url.split_once("://") {
        Some((scheme, rest)) => {
            let host_part = match rest.split_once('@') {
                Some((_, after)) => {
                    // Only treat as userinfo when it precedes any / ? #.
                    let user = &rest[..rest.len() - after.len() - 1];
                    if user.contains('/') || user.contains('?') || user.contains('#')
                    {
                        rest.to_string()
                    } else {
                        format!("***@{after}")
                    }
                }
                None => rest.to_string(),
            };
            format!("{scheme}://{host_part}")
        }
        None => url.to_string(),
    };
    match without_userinfo.split_once('?') {
        Some((base, _)) => format!("{base}?***"),
        None => without_userinfo,
    }
}

struct ApiEventWriter {
    buf: Vec<u8>,
    tx: Arc<mpsc::Sender<Vec<u8>>>,
}

impl Write for ApiEventWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Buffer in memory to avoid fragmenting the event
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            // Non-blocking send; drop if the channel is full
            let _ = self.tx.try_send(std::mem::take(&mut self.buf));
        }
        Ok(())
    }
}

impl Drop for ApiEventWriter {
    fn drop(&mut self) {
        // Ensure the event is pushed even if flush() is never called
        let _ = self.flush();
    }
}

pub async fn init_logging(cfg: &LoggingConfig) -> Option<LoggingHandle> {
    if !cfg.logs() {
        return None;
    }

    let LoggingConfig {
        output,
        api_url,
        file_path,
        rotation,
        max_size,
        max_files,
        level,
    } = cfg.clone();

    let mut guards: Vec<WorkerGuard> = Vec::new();

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&level));

    let stdout_layer = output.stdout.then(|| {
        let (stdout_nb, guard) = NonBlocking::new(io::stdout());
        guards.push(guard);

        let mw = {
            let nb = stdout_nb;
            BoxMakeWriter::new(move || -> Box<dyn Write + Send + Sync> {
                Box::new(nb.clone())
            })
        };

        fmt::layer()
            .with_target(true)
            .with_ansi(true)
            .with_writer(mw)
    });

    let file_layer = output.file.then(|| {
        std::fs::create_dir_all(&file_path).ok();

        let limit = match rotation {
            LoggingRotation::Size => ContentLimit::Bytes(max_size),
            LoggingRotation::Hourly => {
                ContentLimit::Time(TimeFrequency::Hourly)
            }
            LoggingRotation::Daily => ContentLimit::Time(TimeFrequency::Daily),
            LoggingRotation::Weekly => {
                ContentLimit::Time(TimeFrequency::Weekly)
            }
            LoggingRotation::Monthly => {
                ContentLimit::Time(TimeFrequency::Monthly)
            }
            LoggingRotation::Yearly => {
                ContentLimit::Time(TimeFrequency::Yearly)
            }
            LoggingRotation::Never => ContentLimit::None,
        };

        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).append(true);

        let full = file_path.join("ave.log");
        let fr = FileRotate::new(
            &full,
            AppendCount::new(max_files),
            limit,
            Compression::None,
            Some(opts),
        );

        let (file_nb, guard) = NonBlocking::new(fr);
        guards.push(guard);

        let mw = {
            let nb = file_nb;
            BoxMakeWriter::new(move || -> Box<dyn Write + Send + Sync> {
                Box::new(nb.clone())
            })
        };

        fmt::layer()
            .with_target(true)
            .with_ansi(false)
            .with_writer(mw)
    });

    let mut api_rx: Option<mpsc::Receiver<Vec<u8>>> = None;
    let mut api_url_final: Option<String> = None;

    let api_layer = (output.api && api_url.is_some()).then(|| {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(512);
        api_rx = Some(rx);
        api_url_final = api_url.clone();

        let tx = Arc::new(tx);
        let mw = {
            let tx = tx;
            BoxMakeWriter::new(move || -> Box<dyn Write + Send + Sync> {
                Box::new(ApiEventWriter {
                    buf: Vec::with_capacity(512),
                    tx: tx.clone(),
                })
            })
        };

        fmt::layer()
            .with_target(true)
            .with_ansi(false)
            .with_writer(mw)
    });

    let subscriber = Registry::default()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .with(api_layer);

    // If a subscriber is running (e.g. tests)
    if subscriber.try_init().is_err() {
        return None;
    }

    if let (Some(mut rx), Some(url)) = (api_rx, api_url_final) {
        tokio::spawn(async move {
            // Bounded waits: an endpoint that accepts and never answers must
            // not stall the only consumer until the channel fills and every
            // log line gets silently dropped.
            let client = match Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(10))
                .build()
            {
                Ok(client) => client,
                Err(err) => {
                    eprintln!(
                        "log forwarder disabled: failed to build HTTP client: {err}"
                    );
                    return;
                }
            };
            while let Some(bytes) = rx.recv().await {
                if let Err(err) = client.post(&url).body(bytes).send().await {
                    // stderr on purpose: reporting through tracing would
                    // re-enter this forwarder recursively. Never print the
                    // raw URL: it may embed tokens in userinfo or query.
                    let safe_url = sanitize_url_for_log(&url);
                    eprintln!(
                        "log forwarder: delivery to {safe_url} failed: {err}"
                    );
                }
            }
        });
    }

    Some(LoggingHandle { _vec: guards })
}
