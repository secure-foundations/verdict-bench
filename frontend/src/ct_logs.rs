use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CTLogEntry {
    pub cert_base64: String,
    pub hash: String, // SHA-256 hash of the entire certificate
    pub domain: String,
    pub interm_certs: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CTLogResult {
    pub hash: String,
    pub domain: String,
    pub result: String,
}
