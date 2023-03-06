use bip39::{Language, Mnemonic, MnemonicType, Seed};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use std::str::FromStr;

pub struct Crypto;

impl Crypto {
    pub fn generate_mnemonic() -> String {
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        mnemonic.into_phrase()
    }

    /// # Returns
    /// keypair (Private Key, Public key)
    ///
    /// # Accept
    /// `mnemonic` - Mnemonic in string format from bip39
    /// `bip32_path` - BIP32Path in string format. Default: "m/0'"
    pub fn generate_keypair(
        mnemonic: &str,
        bip32_path: Option<&str>,
    ) -> Result<(String, String), anyhow::Error> {
        let mnemonic_object = Mnemonic::from_phrase(mnemonic, Language::English)?;
        let seed = Seed::new(&mnemonic_object, "");

        let path = if let Some(bip_path) = bip32_path {
            slip10::BIP32Path::from_str(bip_path).unwrap()
        } else {
            slip10::BIP32Path::from_str("m/0'").unwrap()
        };

        let derived_private_key =
            slip10::derive_key_from_path(seed.as_bytes(), slip10::Curve::Ed25519, &path).unwrap(); // Change unwrap to check

        let keypair = {
            let secret = SecretKey::from_bytes(&derived_private_key.key).unwrap();
            let public = PublicKey::from(&secret);
            Keypair { secret, public }
        };
        Ok((
            hex::encode(keypair.secret),
            format!("NATURE{}", hex::encode(keypair.public)),
        ))
    }

    pub fn keypair_from_secret(secret: SecretKey) -> Keypair {
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    /// Returning signature
    pub fn sign(message: impl Into<String>, private_key: impl Into<String>) -> String {
        let private_key_bytes = hex::decode(private_key.into()).unwrap();
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&private_key_bytes).unwrap();
        let keypair = Self::keypair_from_secret(secret_key);

        let sign = keypair.sign(Into::<String>::into(message).as_bytes());
        hex::encode(sign.to_bytes())
    }

    pub fn is_valid(expected_message: String, signature: String, public_key: String) -> bool {
        let trimed_public_bytes = hex::decode(public_key.trim_start_matches("NATURE")).unwrap();
        let pub_key = PublicKey::from_bytes(&trimed_public_bytes).unwrap();

        let signature_bytes = hex::decode(signature).unwrap();
        let signature = Signature::from_bytes(&signature_bytes).unwrap();
        pub_key
            .verify(expected_message.as_bytes(), &signature)
            .is_ok()
    }
}
