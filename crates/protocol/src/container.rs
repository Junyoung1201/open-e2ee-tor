//! The encrypted payload of a transfer.
//!
//! Plaintext layout (everything below is inside one age X25519 stream):
//!
//! ```text
//! "O2EE-C1\n" | u32 header_len | header JSON | Ed25519 signature (64)
//! | content (header.size bytes) | zero padding to a multiple of 1 MiB
//! ```
//!
//! The signature covers the header, which names the transfer id, sender,
//! recipient, server, file name, size and SHA-256 of the content. The server
//! only ever sees the age ciphertext, whose length depends on nothing but
//! the padded plaintext length.

use std::io::{self, Read, Write};

use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::VerifiedBundle;
use crate::text::{b64d_array, b64e};
use crate::{MAX_FILE_BYTES, PADDING_UNIT_BYTES, Username, padded_len};

const MAGIC: &[u8; 8] = b"O2EE-C1\n";
pub const MAX_HEADER_LEN: usize = 16 * 1024;
pub const MAX_NAME_BYTES: usize = 255;
const SIG_DOMAIN: &[u8] = b"o2ee/v1/container\0";
const COPY_BUF: usize = 64 * 1024;

/// Bytes of plaintext a transfer id stands for: 16 random bytes, hex.
pub const TRANSFER_ID_LEN: usize = 32;

pub fn new_transfer_id() -> String {
    hex::encode(crate::crypto::random_bytes::<16>())
}

pub fn valid_transfer_id(id: &str) -> bool {
    id.len() == TRANSFER_ID_LEN && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Upper bound on the age ciphertext of any valid transfer.
pub fn max_ciphertext_len() -> u64 {
    let plain = padded_len(MAX_FILE_BYTES + MAX_HEADER_LEN as u64 + 1024).unwrap_or(u64::MAX);
    plain + (plain / (64 * 1024) + 1) * 16 + 4096
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Zip,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u8,
    pub transfer_id: String,
    pub sender: String,
    pub recipient: String,
    pub server: String,
    pub kind: Kind,
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

impl Header {
    fn check_shape(&self) -> Result<(), ContainerError> {
        let ok = self.version == 1
            && valid_transfer_id(&self.transfer_id)
            && Username::parse(&self.sender).is_ok_and(|u| u.as_str() == self.sender)
            && Username::parse(&self.recipient).is_ok_and(|u| u.as_str() == self.recipient)
            && !self.name.is_empty()
            && self.name.len() <= MAX_NAME_BYTES
            && self.size <= MAX_FILE_BYTES
            && b64d_array::<32>(&self.sha256).is_some();
        if ok {
            Ok(())
        } else {
            Err(ContainerError::Malformed)
        }
    }
}

/// Plaintext length of the container for a header of `header_len` bytes
/// and `size` bytes of content.
pub fn container_len(header_len: usize, size: u64) -> Option<u64> {
    let raw = (MAGIC.len() + 4 + header_len + 64) as u64 + size;
    padded_len(raw)
}

/// Writes the whole container into `out`, encrypted to `recipient`.
/// `content` must yield exactly `header.size` bytes whose SHA-256 is
/// `header.sha256`; otherwise nothing valid is produced.
pub fn seal<R: Read, W: Write>(
    header: &Header,
    signer: &SigningKey,
    recipient: &age::x25519::Recipient,
    mut content: R,
    out: W,
) -> Result<W, ContainerError> {
    header.check_shape()?;
    let json = serde_json::to_vec(header).map_err(|_| ContainerError::Malformed)?;
    if json.len() > MAX_HEADER_LEN {
        return Err(ContainerError::Malformed);
    }
    let total = container_len(json.len(), header.size).ok_or(ContainerError::Malformed)?;
    let signature = signer.sign(&signed_bytes(&json));

    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .map_err(|_| ContainerError::Encrypt)?;
    let mut w = encryptor.wrap_output(out)?;
    w.write_all(MAGIC)?;
    w.write_all(&(json.len() as u32).to_be_bytes())?;
    w.write_all(&json)?;
    w.write_all(&signature.to_bytes())?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; COPY_BUF];
    let mut copied = 0u64;
    loop {
        let n = content.read(&mut buf)?;
        if n == 0 {
            break;
        }
        copied += n as u64;
        if copied > header.size {
            return Err(ContainerError::SizeMismatch);
        }
        hasher.update(&buf[..n]);
        w.write_all(&buf[..n])?;
    }
    if copied != header.size || b64e(hasher.finalize()) != header.sha256 {
        return Err(ContainerError::SizeMismatch);
    }
    let mut written = (MAGIC.len() + 4 + json.len() + 64) as u64 + copied;
    buf.fill(0);
    while written < total {
        let n = (total - written).min(COPY_BUF as u64) as usize;
        w.write_all(&buf[..n])?;
        written += n as u64;
    }
    Ok(w.finish()?)
}

fn signed_bytes(json: &[u8]) -> Vec<u8> {
    let mut out = SIG_DOMAIN.to_vec();
    out.extend_from_slice(json);
    out
}

/// A decrypted container whose header has been read but not yet trusted.
pub struct Opened<R: Read> {
    pub header: Header,
    header_len: usize,
    signature: Signature,
    json: Vec<u8>,
    reader: R,
}

impl<R: Read> std::fmt::Debug for Opened<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

/// Decrypts `ciphertext` with `identity` and parses the header. Works on a
/// prefix of the ciphertext too, as long as it covers the header.
pub fn open<'a, R: Read + 'a>(
    ciphertext: R,
    identity: &age::x25519::Identity,
) -> Result<Opened<impl Read + 'a>, ContainerError> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(|_| ContainerError::Decrypt)?;
    if decryptor.is_scrypt() {
        return Err(ContainerError::Decrypt);
    }
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| ContainerError::Decrypt)?;
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(ContainerError::Malformed);
    }
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let header_len = u32::from_be_bytes(len) as usize;
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(ContainerError::Malformed);
    }
    let mut json = vec![0u8; header_len];
    reader.read_exact(&mut json)?;
    let mut sig = [0u8; 64];
    reader.read_exact(&mut sig)?;
    let header: Header = serde_json::from_slice(&json).map_err(|_| ContainerError::Malformed)?;
    header.check_shape()?;
    Ok(Opened {
        header,
        header_len,
        signature: Signature::from_bytes(&sig),
        json,
        reader,
    })
}

impl<R: Read> Opened<R> {
    /// Checks the signature against the sender's pinned keys and that the
    /// header was made for this exact transfer, recipient and server.
    pub fn verify(
        &self,
        sender: &VerifiedBundle,
        recipient: &Username,
        transfer_id: &str,
        server: &str,
    ) -> Result<(), ContainerError> {
        let h = &self.header;
        if h.sender != sender.username.as_str()
            || h.recipient != recipient.as_str()
            || h.transfer_id != transfer_id
            || h.server != server
        {
            return Err(ContainerError::WrongContext);
        }
        sender
            .signing_key
            .verify_strict(&signed_bytes(&self.json), &self.signature)
            .map_err(|_| ContainerError::BadSignature)
    }

    /// Streams the content into `out` and checks length, hash, padding and
    /// the end of the age stream. `out` holds unverified data until this
    /// returns `Ok`; callers write to a temporary file and only keep it then.
    pub fn copy_content<W: Write>(
        mut self,
        out: &mut W,
        mut progress: impl FnMut(u64),
    ) -> Result<(), ContainerError> {
        let size = self.header.size;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; COPY_BUF];
        let mut left = size;
        while left > 0 {
            let want = left.min(COPY_BUF as u64) as usize;
            self.reader.read_exact(&mut buf[..want])?;
            hasher.update(&buf[..want]);
            out.write_all(&buf[..want])?;
            left -= want as u64;
            progress(size - left);
        }
        if b64e(hasher.finalize()) != self.header.sha256 {
            return Err(ContainerError::SizeMismatch);
        }
        let total = container_len(self.header_len, size).ok_or(ContainerError::Malformed)?;
        let mut pad_left = total - ((MAGIC.len() + 4 + self.header_len + 64) as u64 + size);
        while pad_left > 0 {
            let want = pad_left.min(COPY_BUF as u64) as usize;
            self.reader.read_exact(&mut buf[..want])?;
            if buf[..want].iter().any(|b| *b != 0) {
                return Err(ContainerError::Malformed);
            }
            pad_left -= want as u64;
        }
        // Anything after the padding, or a truncated/forged final age chunk,
        // is an error.
        if self.reader.read(&mut buf[..1])? != 0 {
            return Err(ContainerError::Malformed);
        }
        debug_assert_eq!(total % PADDING_UNIT_BYTES, 0);
        Ok(())
    }
}

#[derive(Debug)]
pub enum ContainerError {
    Io(io::Error),
    Encrypt,
    Decrypt,
    Malformed,
    WrongContext,
    BadSignature,
    SizeMismatch,
}

impl From<io::Error> for ContainerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for ContainerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                f.write_str("File is truncated")
            }
            Self::Io(_) => f.write_str("File is damaged or was tampered with"),
            Self::Encrypt => f.write_str("Encryption failed"),
            Self::Decrypt => f.write_str("Cannot decrypt (not addressed to this account)"),
            Self::Malformed => f.write_str("File is damaged or was tampered with"),
            Self::WrongContext => f.write_str("File was not sent for this transfer"),
            Self::BadSignature => f.write_str("Sender signature is invalid"),
            Self::SizeMismatch => f.write_str("File content does not match its signature"),
        }
    }
}

impl std::error::Error for ContainerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    const SERVER: &str = "example.onion";

    struct Party {
        id: Identity,
        name: Username,
        bundle: VerifiedBundle,
    }

    fn party(name: &str) -> Party {
        let id = Identity::generate();
        let name = Username::parse(name).unwrap_or_else(|e| panic!("{e}"));
        let bundle = id
            .public_bundle(&name, SERVER)
            .verify(SERVER, Some(&name))
            .unwrap_or_else(|e| panic!("{e}"));
        Party { id, name, bundle }
    }

    fn header(from: &Party, to: &Party, content: &[u8]) -> Header {
        Header {
            version: 1,
            transfer_id: new_transfer_id(),
            sender: from.name.to_string(),
            recipient: to.name.to_string(),
            server: SERVER.into(),
            kind: Kind::File,
            name: "report.pdf".into(),
            size: content.len() as u64,
            sha256: b64e(crate::crypto::sha256(content)),
        }
    }

    fn sealed(from: &Party, to: &Party, content: &[u8]) -> (Header, Vec<u8>) {
        let h = header(from, to, content);
        let ct = seal(
            &h,
            from.id.signing_key(),
            &to.id.age_identity().to_public(),
            content,
            Vec::new(),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        (h, ct)
    }

    fn receive(ct: &[u8], h: &Header, from: &Party, to: &Party) -> Result<Vec<u8>, ContainerError> {
        let opened = open(ct, to.id.age_identity())?;
        opened.verify(&from.bundle, &to.name, &h.transfer_id, SERVER)?;
        let mut out = Vec::new();
        opened.copy_content(&mut out, |_| {})?;
        Ok(out)
    }

    #[test]
    fn round_trip_and_padding() {
        let (alice, bob) = (party("alice"), party("bob"));
        for content in [&b""[..], b"hello", &vec![7u8; 3 * 1024 * 1024 + 5]] {
            let (h, ct) = sealed(&alice, &bob, content);
            assert_eq!(
                receive(&ct, &h, &alice, &bob).ok().as_deref(),
                Some(content)
            );
        }
        // The server sees whole MiB of plaintext plus fixed age overhead and
        // age's random-length "grease" stanza, never the exact file size.
        let (_, small) = sealed(&alice, &bob, &[1u8; 10]);
        let (_, larger) = sealed(&alice, &bob, &vec![1u8; 900_000]);
        let (_, two) = sealed(&alice, &bob, &vec![1u8; 1_100_000]);
        let mib = crate::MIB as usize;
        assert!(small.len().abs_diff(larger.len()) < 1024);
        assert!(two.len() - small.len() > mib - 1024);
    }

    #[test]
    fn rejects_other_recipient_and_wrong_context() {
        let (alice, bob, eve) = (party("alice"), party("bob"), party("eve"));
        let (h, ct) = sealed(&alice, &bob, b"secret");
        assert!(matches!(
            receive(&ct, &h, &alice, &eve),
            Err(ContainerError::Decrypt)
        ));
        let opened = open(&ct[..], bob.id.age_identity()).unwrap_or_else(|e| panic!("{e}"));
        // Replayed under another transfer id.
        assert!(matches!(
            opened.verify(&alice.bundle, &bob.name, &new_transfer_id(), SERVER),
            Err(ContainerError::WrongContext)
        ));
        // Claimed to come from someone else.
        assert!(matches!(
            opened.verify(&eve.bundle, &bob.name, &h.transfer_id, SERVER),
            Err(ContainerError::WrongContext)
        ));
    }

    #[test]
    fn rejects_forged_signature() {
        let (alice, bob, mallory) = (party("alice"), party("bob"), party("mallory"));
        // Mallory signs a header that claims to be from Alice.
        let content = b"pay mallory";
        let h = header(&alice, &bob, content);
        let ct = seal(
            &h,
            mallory.id.signing_key(),
            &bob.id.age_identity().to_public(),
            &content[..],
            Vec::new(),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            receive(&ct, &h, &alice, &bob),
            Err(ContainerError::BadSignature)
        ));
    }

    #[test]
    fn rejects_tampering_and_truncation() {
        let (alice, bob) = (party("alice"), party("bob"));
        let (h, ct) = sealed(&alice, &bob, &vec![3u8; 200_000]);
        for pos in [ct.len() / 2, ct.len() - 1, 300] {
            let mut bad = ct.clone();
            bad[pos] ^= 0x40;
            assert!(receive(&bad, &h, &alice, &bob).is_err(), "flip at {pos}");
        }
        assert!(receive(&ct[..ct.len() - 1000], &h, &alice, &bob).is_err());
        let mut longer = ct.clone();
        longer.extend_from_slice(&[0u8; 16]);
        assert!(receive(&longer, &h, &alice, &bob).is_err());
    }

    #[test]
    fn seal_checks_declared_content() {
        let (alice, bob) = (party("alice"), party("bob"));
        let mut h = header(&alice, &bob, b"abc");
        let r = bob.id.age_identity().to_public();
        assert!(seal(&h, alice.id.signing_key(), &r, &b"abcd"[..], Vec::new()).is_err());
        h.sha256 = b64e([0u8; 32]);
        assert!(seal(&h, alice.id.signing_key(), &r, &b"abc"[..], Vec::new()).is_err());
    }

    #[test]
    fn header_is_readable_from_prefix() {
        let (alice, bob) = (party("alice"), party("bob"));
        let (h, ct) = sealed(&alice, &bob, &vec![9u8; 2 * 1024 * 1024]);
        let opened =
            open(&ct[..128 * 1024], bob.id.age_identity()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(opened.header, h);
        assert!(
            opened
                .verify(&alice.bundle, &bob.name, &h.transfer_id, SERVER)
                .is_ok()
        );
    }

    #[test]
    fn transfer_ids() {
        assert!(valid_transfer_id(&new_transfer_id()));
        assert!(!valid_transfer_id("ABCDEF0123456789abcdef0123456789"));
        assert!(!valid_transfer_id("../../etc/passwd"));
        assert!(max_ciphertext_len() > MAX_FILE_BYTES);
    }
}
