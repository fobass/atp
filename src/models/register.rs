use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegisterInfo {
    pub user_id: i64,
    pub username: String,
    pub email: String,
    pub password: String,
    pub first_name: String,    // Corresponds to VARCHAR(50), nullable
    pub last_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LoginInfo {
    pub username: String,
    pub password: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PwdChange {
    pub user_id: i64,
    pub current_password: String,
    pub new_password: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DepositUser {
    pub user_id: i64,
    pub amount: f64
}
