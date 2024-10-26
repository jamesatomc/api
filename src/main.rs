use actix_web::{web::Data, App, HttpServer};

use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

mod services;
mod jwt;

use services::{
    get_user, get_all_users, init_db, register_user, login_user, add_product, list_products,
    add_to_cart, remove_from_cart, checkout, delete_product, update_product
};

pub struct AppState {
    db: Pool<Postgres>
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");

    // Initialize the database tables
    init_db(Data::new(AppState { db: pool.clone() })).await.expect("Failed to initialize the database");

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppState { db: pool.clone() }))
            // Users
            .service(get_user)
            .service(get_all_users)
            
            // Authentication
            .service(register_user)
            .service(login_user)
            
            // Cart
            .service(add_to_cart)
            .service(remove_from_cart)
            
            // Checkout
            .service(checkout)
            
             // Products
            .service(add_product)
            .service(list_products)
            .service(delete_product)
            .service(update_product)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}