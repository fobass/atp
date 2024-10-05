use std::{str::FromStr, sync::{Arc, Mutex}};
use bigdecimal::{ToPrimitive, BigDecimal};
use chrono::NaiveDateTime;
use num_traits::FromPrimitive;
use pg_bigdecimal::PgNumeric;
use postgres::{ NoTls, Row};
use tokio_postgres::types::ToSql;
use models::user;
use bcrypt::{hash, verify, DEFAULT_COST};
use tokio_postgres::Error as DbError;
use crate::models::{self, register::PwdChange, transaction::{ TransactionType, UserTransaction}, user::UserInfo, user_balance::UserBalance};
use thiserror::Error;
use std::env;
use dotenv::dotenv;
use tokio_postgres::Client;

#[derive(Error, Debug)]
pub enum MyError {
    #[error("Database error: {0}")]
    DbError(#[from] DbError),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("Error - getting user balance")]
    UserBalanceError,

    #[error("Error - deposit to user balance")]
    DepositUserError,

    #[error("Failed to convert value to big decimal")]
    ConversionError,

    #[error("Database error - register user")]
    ErrorRegisterUser
}
pub struct Database {
    pub users: Arc<Mutex<Vec<user::User>>>,
}

impl Database {
    pub fn new() -> Self {
        let users = Arc::new(Mutex::new(vec![]));
        Database { users }
    }
    
    async fn get_db_client() -> Result<Client, MyError> {
        dotenv().ok();
        let connection_string = env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set");
    
        let (client, connection) = tokio_postgres::connect(&connection_string, NoTls)
            .await?;
    
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });
    
        Ok(client)
    }

    fn to_pg_numeric(value: f64) -> Result<PgNumeric, MyError> {
        let big_decimal = BigDecimal::from_f64(value).ok_or(MyError::ConversionError)?;
        Ok(PgNumeric { n: Some(big_decimal) })
    }
    
    pub async fn get_user_id(&self, user_id: &i64) -> Result<i64, MyError> {
        let client = Database::get_db_client().await?;

        client.query_opt("SELECT user_id FROM users WHERE user_id = $1 LIMIT 1", &[user_id])
            .await?
            .map(|row| row.get(0))
            .ok_or(MyError::UserNotFound)
    }

    pub async fn get_all_user(&self) -> Result<Vec<UserInfo>, MyError> {
        let client = Database::get_db_client().await?;

        let rows = client.query("SELECT user_id, username, email, first_name, last_name FROM users", &[]).await?;
        let users: Result<Vec<UserInfo>, MyError> = rows.iter()
            .map(|row| {
                Ok(UserInfo {
                    user_id: row.get("user_id"),
                    username: row.get("username"),
                    email: row.get("email"),
                    first_name: row.get("first_name"),
                    last_name: row.get("last_name"),
                })
            })
            .collect();
        users
    }
    

    pub async fn new_user_profile(&self, username: &String, email: &String, hashed_password: &String, first_name: &String, last_name: &String) -> Result<i64, MyError> {
         let client = Database::get_db_client().await?;

        let row = client
            .query_one(
                "INSERT INTO users (username, email, password_hash, first_name, last_name)
                VALUES ($1, $2, $3, $4, $5) RETURNING user_id",
                &[&username, &email, &hashed_password, &first_name, &last_name]
            )
            .await
            .map_err(|_e| MyError::ErrorRegisterUser)?; // Handle query execution errors

        let user_id: i64 = row.get(0);

        self.init_default_user_balance(user_id.into())
            .await
            .map_err(|_e| MyError::UserBalanceError)?; // Handle balance initialization errors

        Ok(user_id)
    }

    pub async fn get_user_profile(&self, user_id: i64) -> Result<UserInfo, MyError> {
        let client = Database::get_db_client().await?;

        let row = client.query_one("SELECT user_id, username, email, first_name, last_name  FROM users WHERE user_id = $1 LIMIT 1", &[&user_id])
            .await
            .map_err(|e| {
                println!("Database query error: {:?}", e); // Log the error for debugging
                MyError::UserNotFound
            })?; 

        let user_info = UserInfo {
            user_id: row.get(0),
            username: row.get(1),
            email: row.get(2),
            first_name: row.get(3),
            last_name: row.get(4),
        };

        Ok(user_info)
    }

    pub async fn update_user_profile(&self, user_id: &i64, username: &String, email: &String, first_name: &String, last_name: &String) -> Result<i64, MyError> {
        match Database::get_user_profile(&self, *user_id).await {
            Ok(exist_user_info) => {
                let mut changes: Vec<(&str, &(dyn ToSql + Sync))> = vec![];

                if &exist_user_info.username != username {
                    changes.push(("username", username as &(dyn ToSql + Sync)));
                }
                if &exist_user_info.email != email {
                    changes.push(("email", email as &(dyn ToSql + Sync)));
                }
                if &exist_user_info.first_name != first_name {
                    changes.push(("first_name", first_name as &(dyn ToSql + Sync)));
                }
                if &exist_user_info.last_name != last_name {
                    changes.push(("last_name", last_name as &(dyn ToSql + Sync)));
                }

                // If no changes, return success without updating
                if changes.is_empty() {
                    return Ok(exist_user_info.user_id.into());
                }

                let mut update_query = "UPDATE users SET ".to_string();
                let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();

                for (i, (field, value)) in changes.iter().enumerate() {
                    if i > 0 {
                        update_query.push_str(", ");
                    }
                    update_query.push_str(&format!("{} = ${}", field, i + 1));
                    params.push(*value);  
                }
                update_query.push_str(&format!(" WHERE user_id = ${}", params.len() + 1));
                params.push(user_id as &(dyn ToSql + Sync));

                let client = Database::get_db_client().await?;
                let _ = client.execute(&update_query, &*params).await.map_err(|_| MyError::DbError);
    
                Ok(exist_user_info.user_id.into())
            }
            Err(e) => Err(e),
        }
    }
    
    pub async fn password_change(&self, pwd_info: PwdChange) -> Result<i64, MyError> {
        let client = Database::get_db_client().await?;

        let row = client.query_one("SELECT password_hash FROM users WHERE user_id = $1 LIMIT 1", &[&pwd_info.user_id])
            .await
            .map_err(|_e| MyError::UserNotFound)?; 

        let current_password_hash: String = row.get(0);
       
        if !verify(&pwd_info.current_password, &current_password_hash).is_ok() {
            return Err(MyError::InvalidCredentials);
        }

        let hashed_new_password = hash(pwd_info.new_password, DEFAULT_COST).expect("Error hashing password");
        let update_query = "UPDATE users SET password_hash = $1 WHERE user_id = $2;";

        client.execute(update_query, &[&hashed_new_password, &pwd_info.user_id])
            .await
            .map_err(|_| MyError::InvalidCredentials)?;


        Ok(pwd_info.user_id)
    }
    
    pub async fn init_default_user_balance(&self, user_id: i64) -> Result<i64, MyError> {
        let client = Database::get_db_client().await?;

        // SQL query to insert a new user and return the user_id
        let query = "
            INSERT INTO user_balances (user_id, cash_balance, reserved_balance, total_balance)
            VALUES ($1, $2, $3, $4)
            RETURNING user_id
        ";

       let balance: f64 = 0.0;
       let cash_balance = Database::to_pg_numeric(balance)?;
       let reserved_balance = Database::to_pg_numeric(balance)?;
       let total_balance = Database::to_pg_numeric(balance)?;
       
        // Parameters to be passed to the query
        let params: &[&(dyn ToSql + Sync)] = &[
            &user_id,
            &cash_balance,
            &reserved_balance,
            &total_balance
        ];
        
        // Execute the query and retrieve the user_id
        let _: Row = client.query_one(query, params).await?;
       
        Ok(0)
    }

    pub async fn validate_user(&self, username: &String, password: &String) -> Result<UserInfo, MyError> {
        let client = Database::get_db_client().await?;

        // Query to retrieve the user by username
        let query = "SELECT user_id, username, email, password_hash, first_name, last_name  FROM users WHERE username = $1 LIMIT 1";
        let row = client.query_opt(query, &[&username]).await?;

        // If no user is found, return an error
        if let Some(row) = row {
            let password_hash: String = row.get(3);
            if verify(password, &password_hash).is_ok() {
                let _user = UserInfo {
                    user_id: row.get(0),
                    username: row.get(1),
                    email: row.get(2),
                    first_name: row.get(4),
                    last_name: row.get(5)
                };
                Ok(_user) // Return user_id if password matches
                
            } else {
                Err(MyError::InvalidCredentials)
            }
        } else {
            Err(MyError::UserNotFound)
        }
    }

  

    // fn update_user_profile(user_id: u64, email: Option<&str>, first_name: Option<&str>, last_name: Option<&str>) -> Result<(), String> {
    //     // Build query based on which fields are provided...
    //     let query = "UPDATE users SET email = ?, first_name = ?, last_name = ? WHERE user_id = ?";
    //     // Execute query using your database client...
    
    //     Ok(())
    // }
        
    pub async fn get_user_balance(&self, user_id: i64) -> Result<UserBalance, MyError>{
        let client = Database::get_db_client().await?;

        let query = "SELECT user_id, cash_balance, reserved_balance, total_balance, updated_at FROM user_balances WHERE user_id = $1 LIMIT 1";
        let row = client.query_opt(query, &[&user_id]).await?;

        if let Some(row) = row {
            let created_at: NaiveDateTime = row.get("updated_at");  // Assuming it's a NaiveDateTime
            // let created_at_str = created_at.format("%Y-%m-%d %H:%M:%S").to_string();  // Format as string
            let _cash_balance: PgNumeric = row.get("cash_balance");
            let _reserved_balance: PgNumeric = row.get("reserved_balance");
            let _total_balance: PgNumeric = row.get("total_balance");
            let user_balance = UserBalance {
                user_id: row.get("user_id"),
                cash_balance: _cash_balance.n.unwrap().clone().to_f64().unwrap(),
                reserved_balance: _reserved_balance.n.unwrap().clone().to_f64().unwrap(),
                total_balance: _total_balance.n.unwrap().clone().to_f64().unwrap(),
                updated_at: created_at
            };
            Ok(user_balance)
        } else {
            Err(MyError::UserBalanceError)
        }
    }

    pub async fn set_deposit_to_user(&self, user_id: i64, deposit_amount: f64) -> Result<UserBalance, MyError> {
        let client = Database::get_db_client().await?;

        let amount = Database::to_pg_numeric(deposit_amount)?;
        let update_query = "
            UPDATE user_balances
            SET cash_balance = cash_balance + $1,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $2;
        ";
        
        client.execute(update_query, &[&amount, &user_id])
            .await
            .map_err(|_| MyError::DepositUserError)?;

        let updated_balance = self.get_user_balance(user_id)
            .await
            .map_err(|_| MyError::DepositUserError)?;

        Ok(updated_balance)
    }

    pub async fn set_transaction(&self, transaction: UserTransaction) -> Result<i64, MyError> {
        let client = Database::get_db_client().await?;

        let row = client
        .query_one(
            "INSERT INTO transactions (user_id, transaction_type, instrument_id, quantity, amount, balance_after)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING transaction_id",
            &[&transaction.user_id, &transaction.transaction_type.as_str(), &transaction.instrument_id, &transaction.quantity, &transaction.amount, &transaction.balance_after]
        )
        .await
        .map_err(|_e| MyError::ErrorRegisterUser)?; 

        let transaction_id = row.get("transaction_id");
        Ok(transaction_id)
    }

    pub async fn get_transactions(&self, user_id: i64) -> Result<Vec<UserTransaction>, MyError> {
        let client = Database::get_db_client().await?;

        let query = "SELECT transaction_id, user_id, transaction_type, instrument_id, quantity, amount, balance_after, created_at FROM transactions WHERE user_id = $1";
        let params: &[&(dyn ToSql + Sync)] = &[&user_id];
        let rows = client.query(query, params).await?;
        let mut transactions = Vec::new();

        for row in rows { 
            let _transaction_type: String = row.get(2);
            let transaction = UserTransaction {
                transaction_id: row.get(0),
                user_id,
                transaction_type: TransactionType::from_str(&_transaction_type).expect("Error to covert trasaction type"),
                instrument_id:row.get(3),
                quantity: row.get(4),
                amount: row.get(5),
                balance_after: row.get(6),
                created_at: row.get(7),
            };
            transactions.push(transaction);
        }

        Ok(transactions)
    }
}
