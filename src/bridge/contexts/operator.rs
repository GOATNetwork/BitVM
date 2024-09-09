use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Network, PublicKey, XOnlyPublicKey,
};
use crate::signatures::winternitz::{self, PublicKey as W_PublicKey};
use crate::bridge::commitment;

use super::base::{generate_keys_from_secret, BaseContext};

pub struct OperatorContext {
    pub network: Network,
    pub secp: Secp256k1<All>,

    pub operator_keypair: Keypair,
    pub operator_public_key: PublicKey,
    pub operator_taproot_public_key: XOnlyPublicKey,

    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,

    pub operator_commitment_pubkey: W_PublicKey,
    pub operator_commitment_seckey: [u8; 20],
}

impl BaseContext for OperatorContext {
    fn network(&self) -> Network { self.network }
    fn secp(&self) -> &Secp256k1<All> { &self.secp }
}

impl OperatorContext {
    pub fn new(
        network: Network,
        operator_secret: &str,
        n_of_n_public_key: &PublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
    ) -> Self {
        let (secp, keypair, public_key, taproot_public_key) =
            generate_keys_from_secret(network, operator_secret);

        let operator_commitment_pubkey = commitment::seed_to_pubkey(operator_secret.as_bytes());
        let operator_commitment_seckey = commitment::seed_to_secret(operator_secret.as_bytes());

        OperatorContext {
            network,
            secp,

            operator_keypair: keypair,
            operator_public_key: public_key,
            operator_taproot_public_key: taproot_public_key,

            n_of_n_public_key: n_of_n_public_key.clone(),
            n_of_n_taproot_public_key: n_of_n_taproot_public_key.clone(),

            operator_commitment_pubkey,
            operator_commitment_seckey,
        }
    }
}
