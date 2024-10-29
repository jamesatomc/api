use actix_web::{get, post, delete, web::{Data, Json, Path}, Responder, HttpResponse, put};
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow, Executor};
use crate::AppState;
use argon2::{self, Config};
use crate::jwt::generate_jwt;

#[derive(Serialize, FromRow)]
struct User {
    id: i32,
    first_name: String,
    last_name: String,
    username: String,
    email: String,
    password: String,
}

#[derive(Serialize, FromRow)]
struct ShippingAddress {
    id: i32,
    user_id: i32,
    username: String,
    address_line1: String,
    address_line2: Option<String>,
    city: String,
    state: String,
    postal_code: String,
    country: String,
    mobile_number: String,
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

#[derive(Serialize, FromRow)]
struct CartItem {
    id: i32,
    user_id: i32,
    product_id: i32,
    quantity: i32,
}

#[derive(Deserialize)]
pub struct RegisterUserBody {
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginUserBody {
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ShippingAddressBody {
    pub user_id: i32,
    pub username: String,
    pub address_line1: String,
    pub address_line2: Option<String>,
    pub city: String,
    pub state: String,
    pub postal_code: String,
    pub country: String,
    pub mobile_number: String,
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
}

#[derive(Deserialize)]
pub struct CartItemBody {
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
            username VARCHAR(255) NOT NULL UNIQUE,
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
        CREATE TABLE IF NOT EXISTS cart_items (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            product_id INT NOT NULL,
            quantity INT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        CREATE TABLE IF NOT EXISTS shipping_addresses (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            username VARCHAR(255) NOT NULL,
            address_line1 VARCHAR(255) NOT NULL,
            address_line2 VARCHAR(255),
            city VARCHAR(255) NOT NULL,
            state VARCHAR(255) NOT NULL,
            postal_code VARCHAR(20) NOT NULL,
            country VARCHAR(255) NOT NULL,
            mobile_number VARCHAR(20) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (username) REFERENCES users(username)
        );
        "#,
    ).await?;
    Ok(())
}

#[get("/user/{id}")]
pub async fn get_user(state: Data<AppState>, user_id: Path<i32>) -> impl Responder {
    match sqlx::query_as::<_, User>(
        "SELECT id, first_name, last_name, username, email, password FROM users WHERE id = $1"
    )
        .bind(user_id.into_inner())
        .fetch_one(&state.db)
        .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(_) => HttpResponse::NotFound().json("User not found"),
    }
}

#[get("/users")]
pub async fn get_all_users(state: Data<AppState>) -> impl Responder {
    match sqlx::query_as::<_, User>(
        "SELECT id, first_name, last_name, username, email, password FROM users"
    )
        .fetch_all(&state.db)
        .await
    {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => {
            eprintln!("Error fetching users: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to fetch users")
        },
    }
}

#[post("/register")]
pub async fn register_user(state: Data<AppState>, body: Json<RegisterUserBody>) -> impl Responder {
    let config = Config::default();
    let salt = b"randomsalt"; // In a real application, generate a unique salt for each user
    let hashed_password = argon2::hash_encoded(body.password.as_bytes(), salt, &config).unwrap();

    // ตรวจสอบว่ามี email หรือ username ซ้ำกันหรือไม่
    let existing_user = sqlx::query_as::<_, User>(
        "SELECT id, first_name, last_name, username, email, password FROM users WHERE email = $1 OR username = $2"
    )
    .bind(&body.email)
    .bind(&body.username)
    .fetch_optional(&state.db)
    .await;

    match existing_user {
        Ok(Some(_)) => {
            // หากมีการซ้ำกัน ส่งข้อความแสดงข้อผิดพลาดกลับไป
            HttpResponse::BadRequest().json("Email or username already exists")
        },
        Ok(None) => {
            // หากไม่มีการซ้ำกัน ดำเนินการลงทะเบียนผู้ใช้ใหม่
            match sqlx::query_as::<_, User>(
                "INSERT INTO users (first_name, last_name, username, email, password) VALUES ($1, $2, $3, $4, $5) RETURNING id, first_name, last_name, username, email, password"
            )
            .bind(&body.first_name)
            .bind(&body.last_name)
            .bind(&body.username)
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
        },
        Err(e) => {
            eprintln!("Error checking existing user: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to check existing user")
        },
    }
}

#[post("/login")]
pub async fn login_user(state: Data<AppState>, body: Json<LoginUserBody>) -> impl Responder {
    let user_query = if let Some(email) = &body.email {
        sqlx::query_as::<_, User>(
            "SELECT id, first_name, last_name, username, email, password FROM users WHERE email = $1"
        )
        .bind(email)
    } else if let Some(username) = &body.username {
        sqlx::query_as::<_, User>(
            "SELECT id, first_name, last_name, username, email, password FROM users WHERE username = $1"
        )
        .bind(username)
    } else {
        return HttpResponse::BadRequest().json("Either email or username must be provided");
    };

    let user = user_query.fetch_one(&state.db).await;

    match user {
        Ok(user) => {
            if argon2::verify_encoded(&user.password, body.password.as_bytes()).unwrap() {
                let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
                let token = generate_jwt(&user.username, &secret);
                HttpResponse::Ok().json(token)
            } else {
                HttpResponse::Unauthorized().json("Invalid credentials")
            }
        },
        Err(_) => HttpResponse::Unauthorized().json("Invalid credentials"),
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

#[delete("/product/{id}")]
pub async fn delete_product(state: Data<AppState>, product_id: Path<i32>) -> impl Responder {
    match sqlx::query("DELETE FROM products WHERE id = $1")
        .bind(product_id.into_inner())
        .execute(&state.db)
        .await
    {
        Ok(_) => HttpResponse::Ok().json("Product deleted successfully"),
        Err(e) => {
            eprintln!("Error deleting product: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to delete product")
        },
    }
}

#[put("/product/{id}")]
pub async fn update_product(
    state: Data<AppState>,
    product_id: Path<i32>,
    body: Json<AddProductBody>,
) -> impl Responder {
    match sqlx::query_as::<_, Product>(
        "UPDATE products SET name = $1, category = $2, brand = $3, quantity = $4, price = $5 WHERE id = $6 RETURNING id, name, category, brand, quantity, price"
    )
    .bind(&body.name)
    .bind(&body.category)
    .bind(&body.brand)
    .bind(&body.quantity)
    .bind(&body.price)
    .bind(product_id.into_inner())
    .fetch_one(&state.db)
    .await
    {
        Ok(product) => HttpResponse::Ok().json(product),
        Err(e) => {
            eprintln!("Error updating product: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to update product")
        },
    }
}

#[post("/cart/add")]
pub async fn add_to_cart(state: Data<AppState>, body: Json<CartItemBody>) -> impl Responder {
    match sqlx::query_as::<_, CartItem>(
        "INSERT INTO cart_items (user_id, product_id, quantity) VALUES ($1, $2, $3) RETURNING id, user_id, product_id, quantity"
    )
    .bind(&body.user_id)
    .bind(&body.product_id)
    .bind(&body.quantity)
    .fetch_one(&state.db)
    .await
    {
        Ok(cart_item) => HttpResponse::Ok().json(cart_item),
        Err(e) => {
            eprintln!("Error adding to cart: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to add to cart")
        },
    }
}

#[delete("/cart/remove")]
pub async fn remove_from_cart(state: Data<AppState>, body: Json<CartItemBody>) -> impl Responder {
    match sqlx::query(
        "DELETE FROM cart_items WHERE user_id = $1 AND product_id = $2"
    )
    .bind(&body.user_id)
    .bind(&body.product_id)
    .execute(&state.db)
    .await
    {
        Ok(_) => HttpResponse::Ok().json("Item removed from cart"),
        Err(e) => {
            eprintln!("Error removing from cart: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to remove from cart")
        },
    }
}

#[post("/checkout")]
pub async fn checkout(state: Data<AppState>, body: Json<PurchaseBody>) -> impl Responder {
    let mut transaction = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Error starting transaction: {:?}", e);
            return HttpResponse::InternalServerError().json("Failed to start transaction");
        }
    };

    let cart_items: Vec<CartItem> = match sqlx::query_as::<_, CartItem>(
        "SELECT id, user_id, product_id, quantity FROM cart_items WHERE user_id = $1"
    )
    .bind(&body.user_id)
    .fetch_all(&mut *transaction)
    .await
    {
        Ok(items) => items,
        Err(e) => {
            eprintln!("Error fetching cart items: {:?}", e);
            let _ = transaction.rollback().await;
            return HttpResponse::InternalServerError().json("Failed to fetch cart items");
        },
    };

    for item in cart_items {
        if let Err(e) = sqlx::query_as::<_, Purchase>(
            "INSERT INTO purchases (user_id, product_id, quantity) VALUES ($1, $2, $3) RETURNING id, user_id, product_id, quantity"
        )
        .bind(&item.user_id)
        .bind(&item.product_id)
        .bind(&item.quantity)
        .fetch_one(&mut *transaction)
        .await
        {
            eprintln!("Error making purchase: {:?}", e);
            let _ = transaction.rollback().await;
            return HttpResponse::InternalServerError().json("Failed to make purchase");
        }

        if let Err(e) = sqlx::query(
            "DELETE FROM cart_items WHERE id = $1"
        )
        .bind(&item.id)
        .execute(&mut *transaction)
        .await
        {
            eprintln!("Error clearing cart: {:?}", e);
            let _ = transaction.rollback().await;
            return HttpResponse::InternalServerError().json("Failed to clear cart");
        }
    }

    if let Err(e) = transaction.commit().await {
        eprintln!("Error committing transaction: {:?}", e);
        return HttpResponse::InternalServerError().json("Failed to commit transaction");
    }

    HttpResponse::Ok().json("Checkout successful")
}

#[post("/shipping_address/add")]
pub async fn add_shipping_address(state: Data<AppState>, body: Json<ShippingAddressBody>) -> impl Responder {
    match sqlx::query_as::<_, ShippingAddress>(
        "INSERT INTO shipping_addresses (user_id, username, address_line1, address_line2, city, state, postal_code, country, mobile_number) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, user_id, username, address_line1, address_line2, city, state, postal_code, country, mobile_number"
    )
        .bind(&body.user_id)
        .bind(&body.username)
        .bind(&body.address_line1)
        .bind(&body.address_line2)
        .bind(&body.city)
        .bind(&body.state)
        .bind(&body.postal_code)
        .bind(&body.country)
        .bind(&body.mobile_number)
        .fetch_one(&state.db)
        .await
    {
        Ok(address) => HttpResponse::Ok().json(address),
        Err(e) => {
            eprintln!("Error adding shipping address: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to add shipping address")
        },
    }
}

#[get("/shipping_address/{username}")]
pub async fn get_shipping_address(state: Data<AppState>, username: Path<String>) -> impl Responder {
    match sqlx::query_as::<_, ShippingAddress>(
        "SELECT id, user_id, username, address_line1, address_line2, city, state, postal_code, country, mobile_number FROM shipping_addresses WHERE username = $1"
    )
        .bind(username.into_inner())
        .fetch_all(&state.db)
        .await
    {
        Ok(addresses) => HttpResponse::Ok().json(addresses),
        Err(e) => {
            eprintln!("Error fetching shipping addresses: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to fetch shipping addresses")
        },
    }
}

pub async fn init_db(state: Data<AppState>) -> Result<(), sqlx::Error> {
    create_tables_if_not_exist(&state.db).await
}