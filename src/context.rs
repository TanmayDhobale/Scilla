use {
    crate::config::ScillaConfig,
    solana_commitment_config::CommitmentConfig,
    solana_keypair::{EncodableKey, Keypair, Signer},
    solana_pubkey::Pubkey,
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
};

pub struct ScillaContext {
    rpc_client: RpcClient,
    rpc_url: String,
    keypair: Keypair,
    pubkey: Pubkey,
}

impl ScillaContext {
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn rpc(&self) -> &RpcClient {
        &self.rpc_client
    }

    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

impl ScillaContext {
    pub fn from_config(config: ScillaConfig) -> anyhow::Result<Self> {
        let rpc_url = config.rpc_url.clone();
        let rpc_client = RpcClient::new_with_commitment(
            config.rpc_url,
            CommitmentConfig {
                commitment: config.commitment_level,
            },
        );

        use anyhow::anyhow;

        let keypair = Keypair::read_from_file(&config.keypair_path).map_err(|e| {
            anyhow!(
                "Failed to read keypair from {}: {}",
                config.keypair_path.display(),
                e
            )
        })?;

        let pubkey = keypair.pubkey();

        Ok(Self {
            rpc_client,
            rpc_url,
            keypair,
            pubkey,
        })
    }
}
