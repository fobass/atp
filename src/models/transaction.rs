use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionType{
    DEPOSIT, 
    WITHDRAWAL,
    BUY, 
    SELL
}

impl TransactionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionType::DEPOSIT => "DEPOSIT",
            TransactionType::WITHDRAWAL => "WITHDRAWAL",
            TransactionType::BUY => "BUY",
            TransactionType::SELL => "SELL",
        }
    }
}


impl FromStr for TransactionType {
    type Err = (); // You can use a custom error type if needed

    fn from_str(input: &str) -> Result<TransactionType, Self::Err> {
        match input {
            "DEPOSIT" => Ok(TransactionType::DEPOSIT),
            "WITHDRAWAL" => Ok(TransactionType::WITHDRAWAL),
            "BUY" => Ok(TransactionType::BUY),
            "SELL" => Ok(TransactionType::SELL),
            _ => Err(()), // Handle unknown value as an error
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UserTransaction {
    pub transaction_id: i64,
    pub user_id: i64,
    pub transaction_type: TransactionType,
    pub instrument_id: i64,
    pub quantity: f64,
    pub amount: f64,
    pub balance_after: f64,
    pub created_at: String
}