use serde::{Deserialize, Serialize};
use chrono::NaiveDateTime;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct User {
    pub user_id: i64,                  // Corresponds to SERIAL PRIMARY KEY
    pub username: String,              // Corresponds to VARCHAR(50) UNIQUE NOT NULL
    pub email: String,                 // Corresponds to VARCHAR(100) UNIQUE NOT NULL
    pub password_hash: String,         // Corresponds to VARCHAR(255) NOT NULL
    pub first_name: Option<String>,    // Corresponds to VARCHAR(50), nullable
    pub last_name: Option<String>,     // Corresponds to VARCHAR(50), nullable
    pub created_at: NaiveDateTime,     // Corresponds to TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    pub updated_at: NaiveDateTime,     // Corresponds to TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    pub last_login: Option<NaiveDateTime>, // Corresponds to TIMESTAMP, nullable
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UserInfo {
    pub user_id: i64,                  // Corresponds to SERIAL PRIMARY KEY
    pub username: String,              // Corresponds to VARCHAR(50) UNIQUE NOT NULL
    pub email: String,                 // Corresponds to VARCHAR(100) UNIQUE NOT NULL
    // pub password_hash: String,         // Corresponds to VARCHAR(255) NOT NULL
    pub first_name: String,    // Corresponds to VARCHAR(50), nullable
    pub last_name: String,     // Corresponds to VARCHAR(50), nullable
}