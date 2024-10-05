use actix_web::{web, App, HttpServer};
use atp::{repository, api::api};
use actix_cors::Cors;
use local_ip_address::local_ip;



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let addr: String;
    let port = "7777";
    
    match local_ip() {
        Ok(ip) => {
            let ip_str = ip.to_string();
            addr = ip_str.clone() +":"+ port;              

            println!("Local Wi-Fi IP: {}", ip)
        },
        Err(_e) => {
            addr = "192.168.0.101:7777".to_string();  
        },
    }
    let user_data = repository::database::Database::new();
    let app_data = web::Data::new(user_data);
    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .configure(api::config)
            // .default_service(web::route().to(not_found))
            .wrap(actix_web::middleware::Logger::default())
            .wrap(Cors::permissive())
    })
    .bind(addr.clone())?;
    
    println!("atp server running at http://{}", addr.clone());
    tokio::spawn(server.run());

    tokio::signal::ctrl_c().await.expect("Failed to wait for Ctrl+C");
    println!("Shutting down...");

    Ok(())
}


// fn not_found() -> Result<HttpResponse> {
//     let response = Response {
//         message: "Resource not found".to_string(),
//     };
//     Ok(HttpResponse::NotFound().json(response))
// }