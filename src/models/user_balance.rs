use serde::{Deserialize, Serialize};
use chrono::NaiveDateTime;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UserBalance {
    pub user_id: i64,
    pub cash_balance: f64,
    pub reserved_balance: f64,
    pub total_balance: f64,
    pub updated_at: NaiveDateTime
}