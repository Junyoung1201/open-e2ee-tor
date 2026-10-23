//! JSON bodies of the client/server API (`/v1/...`). Binary fields are
//! base64url without padding. Both sides parse with `deny_unknown_fields`
//! and a size cap before decoding.

use serde::{Deserialize, Serialize};

use crate::crypto::SignedBundle;

/// Largest JSON request or response body either side accepts.
pub const MAX_JSON_BODY: usize = 64 * 1024;
/// Largest body of one upload request.
pub const MAX_UPLOAD_CHUNK: usize = 4 * 1024 * 1024;
/// Most entries an inbox listing returns.
pub const MAX_INBOX_ENTRIES: usize = 200;
/// Longest error message a client prints from the server.
pub const MAX_ERROR_CHARS: usize = 200;

pub const UPLOAD_KEY_HEADER: &str = "x-o2ee-upload-key";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub challenge: String,
    pub difficulty: u8,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignupStart {
    pub username: String,
    pub challenge: String,
    pub nonce: u64,
    pub registration_request: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignupStartReply {
    pub registration_response: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignupFinish {
    pub username: String,
    pub challenge: String,
    pub nonce: u64,
    pub registration_upload: String,
    pub bundle: SignedBundle,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStart {
    pub username: String,
    pub credential_request: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartReply {
    pub login_id: String,
    pub credential_response: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinish {
    pub login_id: String,
    pub credential_finalization: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishReply {
    pub username: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Me {
    pub username: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTransfer {
    pub id: String,
    pub recipient: String,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTransferReply {
    pub upload_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadState {
    pub received: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxEntry {
    pub id: String,
    pub size: u64,
    /// Seconds until the server deletes the transfer.
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbox {
    pub transfers: Vec<InboxEntry>,
}
