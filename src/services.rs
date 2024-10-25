use actix_web::{
    get, post,
    web::{Data, Json, Path},
    Responder, HttpResponse
};
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow, Executor};
use crate::AppState;
use bcrypt::{hash, verify, DEFAULT_COST};

#[derive(Serialize, FromRow)]
struct User {
    id: i32,
    first_name: String,
    last_name: String,
    email: String,
    password: String,
}

#[derive(Serialize, FromRow)]
struct Product {
    id: i32,
    name: String,
    category: String,
    brand: String,
    quantity: i32,
    price: f64,
}

#[derive(Serialize, FromRow)]
struct Purchase {
    id: i32,
    user_id: i32,
    product_id: i32,
    quantity: i32,
}

#[derive(Deserialize)]
pub struct RegisterUserBody {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginUserBody {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct AddProductBody {
    pub name: String,
    pub category: String,
    pub brand: String,
    pub quantity: i32,
    pub price: f64,
}

#[derive(Deserialize)]
pub struct PurchaseBody {
    pub user_id: i32,
    pub product_id: i32,
    pub quantity: i32,
}

async fn create_tables_if_not_exist(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    pool.execute(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            first_name VARCHAR(255) NOT NULL,
            last_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        );
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            category VARCHAR(255) NOT NULL,
            brand VARCHAR(255) NOT NULL,
            quantity INT NOT NULL,
            price FLOAT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS purchases (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            product_id INT NOT NULL,
            quantity INT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        "#,
    ).await?;
    Ok(())
}

#[post("/register")]
pub async fn register_user(state: Data<AppState>, body: Json<RegisterUserBody>) -> impl Responder {
    let hashed_password = hash(&body.password, DEFAULT_COST).unwrap();

    match sqlx::query_as::<_, User>(
        "INSERT INTO users (first_name, last_name, email, password) VALUES ($1, $2, $3, $4) RETURNING id, first_name, last_name, email, password"
    )
    .bind(&body.first_name)
    .bind(&body.last_name)
    .bind(&body.email)
    .bind(&hashed_password)
    .fetch_one(&state.db)
    .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(e) => {
            eprintln!("Error registering user: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to register user")
        },
    }
}

#[post("/login")]
pub async fn login_user(state: Data<AppState>, body: Json<LoginUserBody>) -> impl Responder {
    match sqlx::query_as::<_, User>(
        "SELECT id, first_name, last_name, email, password FROM users WHERE email = $1"
    )
    .bind(&body.email)
    .fetch_one(&state.db)
    .await
    {
        Ok(user) => {
            if verify(&body.password, &user.password).unwrap() {
                HttpResponse::Ok().json(user)
            } else {
                HttpResponse::Unauthorized().json("Invalid credentials")
            }
        },
        Err(_) => HttpResponse::Unauthorized().json("Invalid credentials"),
    }
}

#[post("/add_product")]
pub async fn add_product(state: Data<AppState>, body: Json<AddProductBody>) -> impl Responder {
    match sqlx::query_as::<_, Product>(
        "INSERT INTO products (name, category, brand, quantity, price) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, category, brand, quantity, price"
    )
    .bind(&body.name)
    .bind(&body.category)
    .bind(&body.brand)
    .bind(&body.quantity)
    .bind(&body.price)
    .fetch_one(&state.db)
    .await
    {
        Ok(product) => HttpResponse::Ok().json(product),
        Err(e) => {
            eprintln!("Error adding product: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to add product")
        },
    }
}

#[get("/products")]
pub async fn list_products(state: Data<AppState>) -> impl Responder {
    match sqlx::query_as::<_, Product>(
        "SELECT id, name, category, brand, quantity, price FROM products"
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(products) => HttpResponse::Ok().json(products),
        Err(e) => {
            eprintln!("Error fetching products: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to fetch products")
        },
    }
}

#[post("/purchase")]
pub async fn purchase_product(state: Data<AppState>, body: Json<PurchaseBody>) -> impl Responder {
    match sqlx::query_as::<_, Purchase>(
        "INSERT INTO purchases (user_id, product_id, quantity) VALUES ($1, $2, $3) RETURNING id, user_id, product_id, quantity"
    )
    .bind(&body.user_id)
    .bind(&body.product_id)
    .bind(&body.quantity)
    .fetch_one(&state.db)
    .await
    {
        Ok(purchase) => HttpResponse::Ok().json(purchase),
        Err(e) => {
            eprintln!("Error making purchase: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to make purchase")
        },
    }
}

#[get("/user/{id}")]
pub async fn get_user(state: Data<AppState>, user_id: Path<i32>) -> impl Responder {
    match sqlx::query_as::<_, User>(
        "SELECT id, first_name, last_name, email, password FROM users WHERE id = $1"
    )
    .bind(user_id.into_inner())
    .fetch_one(&state.db)
    .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(_) => HttpResponse::NotFound().json("User not found"),
    }
}

pub async fn init_db(state: Data<AppState>) -> Result<(), sqlx::Error> {
    create_tables_if_not_exist(&state.db).await
}