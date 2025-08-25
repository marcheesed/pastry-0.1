use actix_files::Files;
use actix_session::{storage::RedisSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, middleware::Logger, web, App, HttpServer};
use std::fs;
use std::sync::Arc;
mod common;
mod handlers;
mod jws;
mod models;
mod state;

use crate::handlers::{dashboard, paste, profile, user};
use env_logger;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let app_state = state::create_app_state().expect("Failed to create app state");
    let app_state = Arc::new(app_state);
    let secret_key = {
        if let Ok(key_bytes) = fs::read("secret.key") {
            Key::from(&key_bytes)
        } else {
            let key = Key::generate();
            fs::write("secret.key", key.master()).expect("Failed to write key");
            key
        }
    };

    let jwt_secret = if let Ok(secret_str) = fs::read_to_string("jwt_secret.key") {
        secret_str.trim().to_owned()
    } else {
        use rand::{distributions::Alphanumeric, Rng};
        let new_secret: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        fs::write("jwt_secret.key", &new_secret).expect("Failed to write jwt_secret.key");
        new_secret
    };

    let redis_store = RedisSessionStore::new("redis://127.0.0.1:6379")
        .await
        .expect("Failed to connect to Redis");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(SessionMiddleware::new(
                redis_store.clone(),
                secret_key.clone(),
            ))
            .app_data(web::Data::from(app_state.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .service(Files::new("/static", "./static").show_files_listing())
            .route("/", web::get().to(paste::index))
            .route("/save", web::post().to(paste::save_paste))
            .route("/raw/{token}/css", web::get().to(paste::view_raw_css))
            .route("/register", web::get().to(user::register_form))
            .route("/register", web::post().to(user::register))
            .route("/welcome", web::get().to(user::register_success))
            .route("/login", web::get().to(user::login_form))
            .route("/login", web::post().to(user::login))
            .route("/logout", web::get().to(user::logout))
            .route("/profile/{username}", web::get().to(profile::view_profile))
            .route("/profile/edit", web::post().to(profile::update_profile))
            .route(
                "/api/profile/{username}/friends",
                web::get().to(profile::api_profile_friends),
            )
            .route(
                "/friend/add/{username}",
                web::post().to(profile::add_friend),
            )
            .route(
                "/friend/remove/{username}",
                web::post().to(profile::remove_friend),
            )
            .route("/dashboard", web::get().to(dashboard::view_dashboard))
            .route("/admin/users", web::get().to(user::admin_users))
            .route("/admin/ban", web::post().to(user::ban_user))
            .route("/admin/unban", web::post().to(user::unban_user))
            .route("/api/pastes", web::get().to(dashboard::api_search_pastes))
            .route("/{token}", web::get().to(paste::view_paste))
            .route("/edit/{token}", web::get().to(paste::edit_paste_form))
            .route("/edit/{token}", web::post().to(paste::edit_paste))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
