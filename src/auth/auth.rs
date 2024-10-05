// use actix_web::body::BoxBody;
// use actix_web::dev::{Service, Transform};
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
// use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::models::token::Claims;
use crate::repository;
use jsonwebtoken::{decode, Validation, DecodingKey};
// use serde::{Serialize, Deserialize};
use actix_web::error::ErrorUnauthorized;
// use actix_web::HttpResponse;
use repository::database::Database;
use actix_web::Result;
use actix_web::{web, HttpRequest};


pub fn create_jwt(user_id: i64) -> Result<String, Box<dyn std::error::Error>> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() + 60 * 60; // 1 hour expiration
    
    let claims = Claims {
        user_id,
        exp: expiration as usize,
    };
    
    let secret = "thisisnojoke"; // Store this securely (in environment variables or config)
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))?;
    
    Ok(token)
}

pub async fn verify_jwt(req: HttpRequest, db: web::Data<Database>) -> Result<i64, Box<dyn std::error::Error>> {
    let token = extract_token(&req)?;
    
    let secret = "thisisnojoke"; // Same key used for encoding
    let decoded = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256)
    ).map_err(|_| ErrorUnauthorized("Invalid token"))?;
    
    let user_id = decoded.claims.user_id;

    // Fetch the user from the database based on the user_id extracted from the token
    match db.get_user_id(&user_id).await {
        Ok(user) => Ok(user),
        Err(_) => Err(Box::new(ErrorUnauthorized("Invalid user"))),
    }
    // Ok(user_id)
}

// Helper function to extract the JWT from the Authorization header
fn extract_token(req: &HttpRequest) -> Result<String, actix_web::Error> {
    if let Some(auth_header) = req.headers().get("Authorization") {
        let auth_header = auth_header.to_str().map_err(|_| ErrorUnauthorized("Invalid Authorization header"))?;
        if auth_header.starts_with("Bearer ") {
            Ok(auth_header[7..].to_string())
        } else {
            Err(ErrorUnauthorized("Invalid token format"))
        }
    } else {
        Err(ErrorUnauthorized("Missing Authorization header"))
    }
}