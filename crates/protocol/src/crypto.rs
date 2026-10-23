//! Account keys, signed public-key bundles, fingerprints, OPAQUE parameters,
//! session tokens and the signup proof of work.

use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opaque_ke::rand::RngCore;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{CipherSuite, Identifiers, Ristretto255, TripleDh};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::Username;
use crate::text::{b64d_array, b64e};

/// OPAQUE configuration. Argon2id (default parameters) stretches the
/// password on the client before anything derived from it leaves the device.
#[derive(Debug)]
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = opaque_ke::argon2::Argon2<'static>;
}

pub const OPAQUE_CONTEXT: &[u8] = b"o2ee/v1/opaque";

/// OPAQUE identifiers bind every registration and login to both the account
/// name and the server's onion address.
pub fn identifiers<'a>(username: &'a Username, server: &'a str) -> Identifiers<'a> {
    Identifiers {
        client: Some(username.as_str().as_bytes()),
        server: Some(server.as_bytes()),
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Bearer token both sides derive from the OPAQUE session key. It is never
/// sent by the server, so only a client that completed login knows it.
pub fn session_token(session_key: &[u8]) -> Zeroizing<String> {
    let mut token = Zeroizing::new([0u8; 32]);
    let hk = Hkdf::<Sha256>::new(None::<&[u8]>, session_key);
    // 32 bytes is far below the HKDF-SHA256 output limit.
    let _ = hk.expand(b"o2ee/v1/session-token", &mut token[..]);
    Zeroizing::new(hex::encode(&token[..]))
}

pub fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// A device's private keys. Lives only on the user's device, encrypted with
/// the account password.
pub struct Identity {
    signing: SigningKey,
    age: age::x25519::Identity,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Identity(..)")
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u8,
    signing_key: String,
    age_identity: String,
}

impl Drop for IdentityFile {
    fn drop(&mut self) {
        self.signing_key.zeroize();
        self.age_identity.zeroize();
    }
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new(random_bytes::<32>());
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self {
            signing,
            age: age::x25519::Identity::generate(),
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn age_identity(&self) -> &age::x25519::Identity {
        &self.age
    }

    pub fn public_bundle(&self, username: &Username, server: &str) -> SignedBundle {
        let bundle = Bundle {
            version: 1,
            username: username.to_string(),
            server: server.to_owned(),
            signing_key: b64e(self.signing.verifying_key().as_bytes()),
            age_recipient: self.age.to_public().to_string(),
        };
        let signature = self.signing.sign(&bundle.signing_bytes());
        SignedBundle {
            bundle,
            signature: b64e(signature.to_bytes()),
        }
    }

    /// Serialises and encrypts the keys with `password` (age scrypt).
    pub fn seal(&self, password: &SecretString) -> Result<Vec<u8>, CryptoError> {
        let file = IdentityFile {
            version: 1,
            signing_key: b64e(self.signing.to_bytes()),
            age_identity: self.age.to_string().expose_secret().to_owned(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&file).map_err(|_| CryptoError::KeyFile)?);
        let encryptor = age::Encryptor::with_user_passphrase(password.clone());
        let mut out = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|_| CryptoError::KeyFile)?;
        std::io::Write::write_all(&mut writer, &plain).map_err(|_| CryptoError::KeyFile)?;
        writer.finish().map_err(|_| CryptoError::KeyFile)?;
        Ok(out)
    }

    pub fn unseal(sealed: &[u8], password: &SecretString) -> Result<Self, CryptoError> {
        let decryptor = age::Decryptor::new(sealed).map_err(|_| CryptoError::KeyFile)?;
        if !decryptor.is_scrypt() {
            return Err(CryptoError::KeyFile);
        }
        let identity = age::scrypt::Identity::new(password.clone());
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|_| CryptoError::WrongPassword)?;
        let mut plain = Zeroizing::new(Vec::new());
        std::io::Read::read_to_end(&mut reader, &mut plain).map_err(|_| CryptoError::KeyFile)?;
        let file: IdentityFile =
            serde_json::from_slice(&plain).map_err(|_| CryptoError::KeyFile)?;
        if file.version != 1 {
            return Err(CryptoError::KeyFile);
        }
        let mut seed =
            Zeroizing::new(b64d_array::<32>(&file.signing_key).ok_or(CryptoError::KeyFile)?);
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let age = age::x25519::Identity::from_str(&file.age_identity)
            .map_err(|_| CryptoError::KeyFile)?;
        Ok(Self { signing, age })
    }
}

/// An account's public keys as the account itself signed them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub version: u8,
    pub username: String,
    pub server: String,
    pub signing_key: String,
    pub age_recipient: String,
}

impl Bundle {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = b"o2ee/v1/bundle\0".to_vec();
        out.push(self.version);
        for field in [
            &self.username,
            &self.server,
            &self.signing_key,
            &self.age_recipient,
        ] {
            push_field(&mut out, field.as_bytes());
        }
        out
    }
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBundle {
    pub bundle: Bundle,
    pub signature: String,
}

/// A bundle whose self-signature, account name and server binding checked
/// out.
#[derive(Clone, Debug)]
pub struct VerifiedBundle {
    pub username: Username,
    pub signing_key: VerifyingKey,
    pub age_recipient: age::x25519::Recipient,
    pub signed: SignedBundle,
}

impl VerifiedBundle {
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint(&self.signing_key, &self.signed.bundle.age_recipient)
    }
}

impl SignedBundle {
    /// Checks the self-signature and that the bundle names `server`. When
    /// `expected` is given the bundle must also belong to that account.
    pub fn verify(
        &self,
        server: &str,
        expected: Option<&Username>,
    ) -> Result<VerifiedBundle, CryptoError> {
        let b = &self.bundle;
        if b.version != 1 || b.server != server {
            return Err(CryptoError::Bundle);
        }
        let username = Username::parse(&b.username).map_err(|_| CryptoError::Bundle)?;
        if username.as_str() != b.username || expected.is_some_and(|e| *e != username) {
            return Err(CryptoError::Bundle);
        }
        let key_bytes = b64d_array::<32>(&b.signing_key).ok_or(CryptoError::Bundle)?;
        let signing_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::Bundle)?;
        let sig = b64d_array::<64>(&self.signature).ok_or(CryptoError::Bundle)?;
        signing_key
            .verify_strict(&b.signing_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| CryptoError::Bundle)?;
        if b.age_recipient.len() > 100 {
            return Err(CryptoError::Bundle);
        }
        let age_recipient =
            age::x25519::Recipient::from_str(&b.age_recipient).map_err(|_| CryptoError::Bundle)?;
        Ok(VerifiedBundle {
            username,
            signing_key,
            age_recipient,
            signed: self.clone(),
        })
    }
}

/// Short, human-comparable digest of an account's public keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint([u8; 16]);

pub fn fingerprint(signing_key: &VerifyingKey, age_recipient: &str) -> Fingerprint {
    let mut h = Sha256::new();
    h.update(b"o2ee/v1/fingerprint\0");
    h.update(signing_key.as_bytes());
    h.update(age_recipient.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    Fingerprint(out)
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode_upper(self.0);
        for (i, chunk) in hex.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                f.write_str("-")?;
            }
            // Hex digits are ASCII.
            f.write_str(std::str::from_utf8(chunk).map_err(|_| std::fmt::Error)?)?;
        }
        Ok(())
    }
}

/// Signup proof of work: the client must find a nonce for a server-issued
/// challenge so that SHA-256(domain || challenge || username || nonce) starts
/// with `difficulty` zero bits.
pub mod pow {
    use super::*;

    pub const DIFFICULTY: u8 = 20;
    pub const CHALLENGE_LEN: usize = 16 + 8 + 16;

    type HmacSha256 = Hmac<Sha256>;

    fn mac(key: &[u8; 32], body: &[u8]) -> [u8; 16] {
        // HMAC accepts keys of any length.
        let mut m = <HmacSha256 as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
        m.update(b"o2ee/v1/pow-challenge\0");
        m.update(body);
        let tag = m.finalize().into_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag[..16]);
        out
    }

    /// Stateless challenge: random || expiry || MAC(server key).
    pub fn issue(key: &[u8; 32], expires_at: u64) -> [u8; CHALLENGE_LEN] {
        let mut out = [0u8; CHALLENGE_LEN];
        out[..16].copy_from_slice(&random_bytes::<16>());
        out[16..24].copy_from_slice(&expires_at.to_be_bytes());
        let tag = mac(key, &out[..24]);
        out[24..].copy_from_slice(&tag);
        out
    }

    /// Returns the challenge's expiry if it was issued with `key`.
    pub fn check_issued(key: &[u8; 32], challenge: &[u8; CHALLENGE_LEN]) -> Option<u64> {
        let tag = mac(key, &challenge[..24]);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&tag[..], &challenge[24..])) {
            return None;
        }
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&challenge[16..24]);
        Some(u64::from_be_bytes(expiry))
    }

    fn leading_zero_bits(digest: &[u8]) -> u32 {
        let mut bits = 0;
        for byte in digest {
            if *byte == 0 {
                bits += 8;
            } else {
                return bits + byte.leading_zeros();
            }
        }
        bits
    }

    fn digest(challenge: &[u8], username: &Username, nonce: u64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"o2ee/v1/pow\0");
        h.update(challenge);
        h.update(username.as_str().as_bytes());
        h.update(nonce.to_be_bytes());
        h.finalize().into()
    }

    pub fn verify(challenge: &[u8], username: &Username, nonce: u64, difficulty: u8) -> bool {
        leading_zero_bits(&digest(challenge, username, nonce)) >= u32::from(difficulty)
    }

    pub fn solve(challenge: &[u8], username: &Username, difficulty: u8) -> u64 {
        (0u64..)
            .find(|n| verify(challenge, username, *n, difficulty))
            .unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    KeyFile,
    WrongPassword,
    Bundle,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::KeyFile => "Key file is damaged",
            Self::WrongPassword => "Wrong password",
            Self::Bundle => "Invalid public key bundle",
        })
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "example.onion";

    fn user(name: &str) -> Username {
        Username::parse(name).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn bundle_signature_and_binding() {
        let id = Identity::generate();
        let alice = user("alice");
        let signed = id.public_bundle(&alice, SERVER);
        let verified = signed
            .verify(SERVER, Some(&alice))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(verified.username, alice);
        assert!(signed.verify("other.onion", None).is_err());
        assert!(signed.verify(SERVER, Some(&user("bob"))).is_err());

        let mut renamed = signed.clone();
        renamed.bundle.username = "mallory".into();
        assert!(renamed.verify(SERVER, None).is_err());

        let mut swapped = signed.clone();
        swapped.bundle.age_recipient = Identity::generate().age.to_public().to_string();
        assert!(swapped.verify(SERVER, None).is_err());
    }

    #[test]
    fn fingerprint_format_and_uniqueness() {
        let a = Identity::generate().public_bundle(&user("alice"), SERVER);
        let b = Identity::generate().public_bundle(&user("alice"), SERVER);
        let fa = a.verify(SERVER, None).map(|v| v.fingerprint().to_string());
        let fb = b.verify(SERVER, None).map(|v| v.fingerprint().to_string());
        let fa = fa.unwrap_or_default();
        assert_eq!(fa.len(), 39);
        assert_eq!(fa.matches('-').count(), 7);
        assert_ne!(Ok(fa), fb);
    }

    #[test]
    fn key_file_round_trip() {
        let id = Identity::generate();
        let pw = SecretString::from("correct horse battery".to_owned());
        let sealed = id.seal(&pw).unwrap_or_default();
        let back = Identity::unseal(&sealed, &pw).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back.signing.to_bytes(), id.signing.to_bytes());
        assert_eq!(
            back.age.to_public().to_string(),
            id.age.to_public().to_string()
        );
        let wrong = SecretString::from("wrong horse battery".to_owned());
        assert_eq!(
            Identity::unseal(&sealed, &wrong).err(),
            Some(CryptoError::WrongPassword)
        );
    }

    #[test]
    fn pow_challenge() {
        let key = random_bytes::<32>();
        let challenge = pow::issue(&key, 1234);
        assert_eq!(pow::check_issued(&key, &challenge), Some(1234));
        let mut forged = challenge;
        forged[20] ^= 1;
        assert_eq!(pow::check_issued(&key, &forged), None);
        assert_eq!(pow::check_issued(&random_bytes::<32>(), &challenge), None);

        let alice = user("alice");
        let nonce = pow::solve(&challenge, &alice, 8);
        assert!(pow::verify(&challenge, &alice, nonce, 8));
        // A solution is tied to the account name it was solved for.
        let other = (0..64).all(|n| pow::verify(&challenge, &user("bob"), nonce + n, 8));
        assert!(!other);
    }

    #[test]
    fn session_token_is_deterministic() {
        assert_eq!(*session_token(b"key"), *session_token(b"key"));
        assert_ne!(*session_token(b"key"), *session_token(b"other"));
        assert_eq!(session_token(b"key").len(), 64);
    }
}
