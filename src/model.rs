use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateReq {
    pub target: String,
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub expires_at: Option<u64>, // epoch seconds (DynamoDB TTL is number)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Link {
    pub slug: String,
    pub target: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub visits: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateResp {
    pub slug: String,
    pub short_url: String,
    pub target: String,
    pub expires_at: Option<u64>,
}
