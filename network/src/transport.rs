//! Transport layer.
//!

use std::time::Duration;

use crate::{
    Error,
    utils::{LimitsConfig, NOISE_PROTOCOL},
};

use libp2p::{
    PeerId, Transport,
    core::{
        muxing::StreamMuxerBox,
        transport::{Boxed, upgrade::Version},
    },
    identity::Keypair,
    noise, yamux,
};

#[cfg(feature = "test")]
use libp2p::core::transport::memory;

#[cfg(not(feature = "test"))]
use libp2p::{
    dns,
    tcp::{self, Config},
};

pub type AveTransport = Boxed<(PeerId, StreamMuxerBox)>;

/// Builds the transport.
///
/// # Arguments
///
/// * `peer_id` - The peer ID.
/// * `keys` - The keypair.
///
/// # Returns
///
/// The transport and relay client.
///
/// # Errors
///
/// If the transport cannot be built.
///
pub fn build_transport(
    keys: &Keypair,
    limits: LimitsConfig,
) -> Result<AveTransport, Error> {
    let noise = noise::Config::new(keys)
        .map_err(|e| Error::NoiseBuild(e.to_string()))?
        .with_prologue(NOISE_PROTOCOL.as_bytes().to_vec());

    let mut binding = yamux::Config::default();
    let yamux = binding.set_max_num_streams(limits.yamux_max_num_streams);

    #[cfg(not(feature = "test"))]
    let transport = {
        let tcp = tcp::tokio::Transport::new(
            Config::default()
                .listen_backlog(limits.tcp_listen_backlog)
                .nodelay(limits.tcp_nodelay),
        )
        .upgrade(Version::V1Lazy)
        .authenticate(noise)
        .multiplex(yamux.clone())
        .timeout(Duration::from_secs(20))
        .boxed();

        dns::tokio::Transport::system(tcp)
            .map_err(|e| Error::DnsBuild(e.to_string()))?
    };

    #[cfg(feature = "test")]
    let transport = memory::MemoryTransport::default()
        .upgrade(Version::V1Lazy)
        .authenticate(noise)
        .multiplex(yamux.clone())
        .timeout(Duration::from_secs(10))
        .boxed();

    Ok(transport.boxed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_transport() {
        let keypair = Keypair::generate_ed25519();
        let limit = LimitsConfig::build(4, 4);
        let result = build_transport(&keypair, limit);

        assert!(result.is_ok());
    }
}
