use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::serde_hex::{hex_32, opt_hex_32, opt_hex_vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    Intent,
    Memory,
}

impl ObjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectType::Intent => "intent",
            ObjectType::Memory => "memory",
        }
    }

    pub fn from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "intent" => Ok(ObjectType::Intent),
            "memory" => Ok(ObjectType::Memory),
            other => Err(format!("invalid obj_type: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatus {
    Active,
    Revoked,
    Expired,
    Superseded,
}

impl LifecycleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            LifecycleStatus::Active => "active",
            LifecycleStatus::Revoked => "revoked",
            LifecycleStatus::Expired => "expired",
            LifecycleStatus::Superseded => "superseded",
        }
    }

    pub fn from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "active" => Ok(LifecycleStatus::Active),
            "revoked" => Ok(LifecycleStatus::Revoked),
            "expired" => Ok(LifecycleStatus::Expired),
            "superseded" => Ok(LifecycleStatus::Superseded),
            other => Err(format!("invalid lifecycle_status: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredObject {
    pub id: Uuid,
    pub tenant_id: String,
    pub obj_type: ObjectType,
    pub scope: String,
    pub lifecycle_status: LifecycleStatus,
    pub priority: i32,
    pub importance: f32,
    pub tags: Vec<String>,
    pub body: serde_json::Value,
    #[serde(with = "hex_32")]
    pub content_hash: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
    pub version: i32,
    pub predecessor_id: Option<Uuid>,
    #[serde(default, with = "opt_hex_vec", skip_serializing_if = "Option::is_none")]
    pub client_signature: Option<Vec<u8>>,
    #[serde(default, with = "opt_hex_32", skip_serializing_if = "Option::is_none")]
    pub client_public_key: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_seq_num: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RankedMemory {
    pub object: StoredObject,
    pub hybrid_score: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SelectedObjectRef {
    pub id: Uuid,
    pub obj_type: ObjectType,
    pub version: i32,
    #[serde(with = "hex_32")]
    pub content_hash: [u8; 32],
}

impl From<&StoredObject> for SelectedObjectRef {
    fn from(obj: &StoredObject) -> Self {
        Self {
            id: obj.id,
            obj_type: obj.obj_type,
            version: obj.version,
            content_hash: obj.content_hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngestObjectRequest {
    #[serde(default)]
    pub id: Option<Uuid>,
    pub tenant_id: String,
    pub obj_type: ObjectType,
    pub scope: String,
    #[serde(default = "default_active_lifecycle")]
    pub lifecycle_status: LifecycleStatus,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_importance")]
    pub importance: f32,
    #[serde(default)]
    pub tags: Vec<String>,
    pub body: serde_json::Value,
    #[serde(default)]
    pub embedding: Option<Vec<f32>>,
    #[serde(default)]
    pub predecessor_id: Option<Uuid>,
    #[serde(default)]
    pub client_signature_hex: Option<String>,
    #[serde(default)]
    pub client_public_key_hex: Option<String>,
}

fn default_active_lifecycle() -> LifecycleStatus {
    LifecycleStatus::Active
}

fn default_importance() -> f32 {
    0.5
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestObjectResponse {
    pub id: Uuid,
    pub version: i32,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_seq_num: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_public_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_by: Option<String>,
    pub created_at: DateTime<Utc>,
}
