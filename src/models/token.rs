use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub user_id: i64,
    pub exp: usize, // Expiration time (in seconds since UNIX epoch)
}