
use actix_web::web::Json;
use actix_web::{get, post, web, HttpRequest};
use actix_web::HttpResponse;
use repository::database::Database;
use serde_json::json;
use crate::models::register::{DepositUser, LoginInfo, RegisterInfo, PwdChange};
use crate::models::transaction::UserTransaction;
use crate::{auth, repository};
use bcrypt::{hash, DEFAULT_COST};



#[post("/user_profile")]
pub async fn set_user_profile(db: web::Data<Database>, req: HttpRequest, info: web::Json<RegisterInfo>) -> HttpResponse {
    match auth::auth::verify_jwt(req, db.clone()).await {
        Ok(_) => {
            if info.user_id == 0 { // new user
                let password = &info.password;
                let hashed_password = hash(password, DEFAULT_COST).expect("Error hashing password");
                match db.new_user_profile(&info.username, &info.email, &hashed_password, &info.first_name, &info.last_name).await {
                    Ok(user_id) => {
                        HttpResponse::Ok().json(json!(user_id))
                    },
                    Err(e) => HttpResponse::Unauthorized().body(e.to_string())
                }
            } else { // update user profile
                match db.update_user_profile(&info.user_id, &info.username, &info.email, &info.first_name, &info.last_name).await {
                    Ok(user_id) => {
                        HttpResponse::Ok().json(json!(user_id))
                    },
                    Err(e) => HttpResponse::Unauthorized().body(e.to_string())
                }
            }
        },
        Err(_) => HttpResponse::Unauthorized().body("User not found."),
    }

}


#[get("/user_balance/{id}")]
pub async fn get_user_balance(db: web::Data<Database>, req: HttpRequest, id: web::Path<i64>) -> HttpResponse {

    match auth::auth::verify_jwt(req, db.clone()).await {
        Ok(_) => {
            let user_id = id.into_inner();
            match db.get_user_balance(user_id).await {
                Ok(user_balance) => {
                    HttpResponse::Ok().json(user_balance)
                },
                Err(e) => {
                    HttpResponse::NotFound().body(e.to_string())
                }
            }
        },
        Err(_) => HttpResponse::Unauthorized().body("User not found."),
    }

}


#[get("/user_profile/{id}")]
pub async fn get_user_profile(db: web::Data<Database>, req: HttpRequest, id: web::Path<i64>) -> HttpResponse {
    match auth::auth::verify_jwt(req, db.clone()).await {
        Ok(_) => {
            match db.get_user_profile(id.into_inner()).await {
                Ok(user_info) => {
                    HttpResponse::Ok().json(json!(user_info))
                },
                Err(e) => { 
                    println!("err {:?}", e.to_string());
                    HttpResponse::Unauthorized().body(e.to_string()) 
                }
            }
        },
        Err(_) => HttpResponse::Unauthorized().body("User not found."),
    }
    
}

#[post("/change_password")]
pub async fn change_password(db: web::Data<Database>, req: HttpRequest, pwd_info: Json<PwdChange>) -> HttpResponse {

    match auth::auth::verify_jwt(req, db.clone()).await {
        Ok(_) => {
            if pwd_info.new_password.len() < 8 {
                return HttpResponse::Unauthorized().body("Invalid password");
            }
        
            match db.password_change(pwd_info.into_inner()).await {
                Ok(_) => {
                    HttpResponse::Ok().json("Password changed successfully")
                },
                Err(e) => HttpResponse::Unauthorized().body(e.to_string())
            }
        },
        Err(_) => HttpResponse::Unauthorized().body("User not found."),
    }
  
}

#[post("/login")]
pub async fn login(db: web::Data<Database>, info: web::Json<LoginInfo>) -> HttpResponse {

        match db.validate_user(&info.username, &info.password).await {
            Ok(user) => {
                if let Ok(token) = auth::auth::create_jwt(user.user_id) {
                    let response_body = json!({
                        "access_token": token,
                        "user_id": user.user_id,
                        // "username": user.username,
                        // "email": user.email,
                        // "first_name": user.first_name,
                        // "last_name": user.last_name,
                    });
                    HttpResponse::Ok().json(response_body)
                } else {
                    HttpResponse::Unauthorized().body("Invalid credentials")
                }
            },
            Err(_) => HttpResponse::Unauthorized().body("User not found."),
        }
    
}

#[post("/verify_token")]
pub async fn verify_jwt(db: web::Data<Database>, req: HttpRequest) -> HttpResponse {

    match auth::auth::verify_jwt(req, db).await {
        Ok(user_id) => {
            HttpResponse::Ok().json(json!({ "user_id": user_id}))
        },
        Err(_) => HttpResponse::Unauthorized().body("User not found."),
    }
}

#[post("/deposit")]
pub async fn set_deposit(db: web::Data<Database>, req: HttpRequest, info: web::Json<DepositUser>) -> HttpResponse {
    match auth::auth::verify_jwt(req, db.clone()).await {
        Ok(_) => {
            match db.set_deposit_to_user(info.user_id, info.amount).await {
                Ok(balance) => HttpResponse::Ok().json(balance),
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        },
        Err(_) => HttpResponse::Unauthorized().body("User not found."),
    }

}

#[get("/transaction/{id}")]
pub async fn get_transaction(db: web::Data<Database>, req: HttpRequest, info: web::Json<UserTransaction>) -> HttpResponse {
    match auth::auth::verify_jwt(req, db.clone()).await {
        Ok(_) => {
            match db.get_transactions(info.user_id).await {
                Ok(transactions) => HttpResponse::Ok().json(transactions),
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        },
        Err(_) => HttpResponse::Unauthorized().body("User not found."),
    }
    
}

#[post("/transaction")]
pub async fn set_transaction(db: web::Data<Database>, req: HttpRequest, info: web::Json<UserTransaction>) -> HttpResponse {
    match auth::auth::verify_jwt(req, db.clone()).await {
        Ok(_) => {
            match db.set_transaction(info.into_inner()).await {
                Ok(transaction_id) => HttpResponse::Ok().json(transaction_id),
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        },
        Err(_) => HttpResponse::Unauthorized().body("User not found."),
    }

}

#[get("/users")]
pub async fn get_all_user(db: web::Data<Database>) -> HttpResponse {
    // match auth::auth::verify_jwt(req, db.clone()).await {
        // Ok(_) => {
            match db.get_all_user().await {
                Ok(users) => HttpResponse::Ok().json(users),
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        // },
        // Err(_) => HttpResponse::Unauthorized().body("User not found."),
    // }
    
}


pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(set_user_profile)
            .service(get_user_profile)
            .service(login)
            .service(verify_jwt)
            .service(get_user_balance)
            .service(set_deposit)
            .service(set_transaction)
            .service(get_transaction)
            .service(get_all_user)
    );
}
