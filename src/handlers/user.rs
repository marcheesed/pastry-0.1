use crate::common::prelude::*;
use crate::common::utils::{
    render_template, set_csrf_token, set_flash_message, setup_user_context, validate_username,
    with_csrf_validation, with_db_conn, get_user_id_from_jwt, is_user_admin, is_user_banned, get_db_conn,
};
use crate::common::constants::{ALLOWED_REGISTER_USERS};
use crate::jws::generate_jwt;
use crate::models::{LoginForm, RegisterForm};
use actix_web::cookie::{time::Duration as ActixDuration, Cookie};
use bcrypt::{hash, verify, DEFAULT_COST};
use rand::rngs::OsRng;
use rand::{distributions::Alphanumeric, Rng};
use uuid::Uuid;

pub async fn register_user_in_db(
    data: &web::Data<AppState>,
    username: &str,
) -> Result<(String, String), AppError> {
    with_db_conn(data, |conn| {
        let tx = conn.transaction().map_err(AppError::Database)?;

        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM users WHERE username = ?1",
            params![username],
            |row| row.get(0),
        ).map_err(AppError::Database)?;

        if count > 0 {
            return Err(AppError::Validation("Username already taken".to_string()));
        }

        let user_id = Uuid::new_v4().to_string();

        // generate secret token (user_token) for authentication
        let user_token: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // hash the secret token with bcrypt
        let user_token_hash = hash(&user_token, DEFAULT_COST)
            .map_err(|e| AppError::Internal(format!("Hashing error: {}", e)))?;

        // insert into DB
        tx.execute(
            "INSERT INTO users (user_id, username, user_token_hash, username_last_changed, role) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&user_id, username, &user_token_hash, Utc::now().to_rfc3339(), "user"],
        ).map_err(AppError::Database)?;

        tx.commit().map_err(AppError::Database)?;

        // return both user_id and user_token (token is shown to user)
        Ok((user_id, user_token))
    }).await
}

// ban a user (admin only)
#[derive(serde::Deserialize)]
pub struct BanForm {
    username: String,
    csrf_token: String,
}

pub async fn ban_user(
    data: web::Data<AppState>,
    form: web::Form<BanForm>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = &form.csrf_token;

    with_csrf_validation(&session, form_csrf_token, || async {
        // check if the requester is an admin
        let user_id = get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
        
        let conn = get_db_conn(&data)?;
        if !is_user_admin(&conn, &user_id).await? {
            return Err(AppError::Unauthorized("Admin access required".to_string()));
        }

        let username = form.username.trim();
        if username.is_empty() {
            return Err(AppError::Validation("Username cannot be empty".to_string()));
        }

        // update the user's banned status
        let rows_affected = with_db_conn(&data, |conn| {
            conn.execute(
                "UPDATE users SET banned = TRUE WHERE username = ?1",
                params![username],
            )
            .map_err(AppError::Database)
        })
        .await?;

        if rows_affected == 0 {
            return Err(AppError::Validation("User not found".to_string()));
        }

        set_flash_message(&session, &format!("User {} banned successfully", username), "success")?;
        Ok(HttpResponse::Found()
            .append_header(("Location", "/admin/users"))
            .finish())
    })
    .await
}

// unban a user (admin only)
#[derive(serde::Deserialize)]
pub struct UnbanForm {
    username: String,
    csrf_token: String,
}

pub async fn unban_user(
    data: web::Data<AppState>,
    form: web::Form<UnbanForm>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = &form.csrf_token;

    with_csrf_validation(&session, form_csrf_token, || async {
        // check if the requester is an admin
        let user_id = get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
        
        let conn = get_db_conn(&data)?;
        if !is_user_admin(&conn, &user_id).await? {
            return Err(AppError::Unauthorized("Admin access required".to_string()));
        }

        let username = form.username.trim();
        if username.is_empty() {
            return Err(AppError::Validation("Username cannot be empty".to_string()));
        }

        // update the user's banned status
        let rows_affected = with_db_conn(&data, |conn| {
            conn.execute(
                "UPDATE users SET banned = FALSE WHERE username = ?1",
                params![username],
            )
            .map_err(AppError::Database)
        })
        .await?;

        if rows_affected == 0 {
            return Err(AppError::Validation("User not found".to_string()));
        }

        set_flash_message(&session, &format!("User {} unbanned successfully", username), "success")?;
        Ok(HttpResponse::Found()
            .append_header(("Location", "/admin/users"))
            .finish())
    })
    .await
}

// admin user management page
pub async fn admin_users(
    data: web::Data<AppState>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = get_user_id_from_jwt(&req, &jwt_secret)?
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    
    let conn = get_db_conn(&data)?;
    if !is_user_admin(&conn, &user_id).await? {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }

    let users = with_db_conn(&data, |conn| {
        let mut stmt = conn.prepare(
            "SELECT username, banned, role FROM users ORDER BY username"
        ).map_err(AppError::Database)?;

        let user_iter = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, String>(2)?,
            ))
        }).map_err(AppError::Database)?;

        user_iter.collect::<Result<Vec<_>, _>>().map_err(AppError::Database)
    }).await?;

    let mut context = Context::new();
    context.insert("site_name", "admin_users");
    context.insert("csrf_token", &set_csrf_token(&session)?);
    setup_user_context(&mut context, &data, &session)?;
    context.insert("users", &users);

    let rendered = render_template(&data.tera, "admin/users.html", &context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

fn render_register_form(
    data: &web::Data<AppState>,
    session: &Session,
    username: &str,
    errors: &HashMap<String, Vec<String>>,
) -> Result<HttpResponse, AppError> {
    let mut context = Context::new();
    context.insert("site_name", "pastry");
    context.insert("register_url", "/register");
    context.insert("csrf_token", &set_csrf_token(session)?);
    setup_user_context(&mut context, data, session)?;

    context.insert("username", username);
    context.insert("errors", errors);

    let rendered = render_template(&data.tera, "user/register.html", &context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

pub async fn register_form(
    data: web::Data<AppState>,
    session: Session,
) -> Result<HttpResponse, AppError> {
    let mut context = Context::new();
    context.insert("site_name", "pastry");
    context.insert("register_url", "/register");
    context.insert("csrf_token", &set_csrf_token(&session)?);
    setup_user_context(&mut context, &data, &session)?;
    context.insert("username", "");
    context.insert("errors", &HashMap::<String, Vec<String>>::new());

    let rendered = render_template(&data.tera, "user/register.html", &context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

pub async fn register(
    data: web::Data<AppState>,
    form: web::Form<RegisterForm>,
    session: Session,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");

    with_csrf_validation(&session, form_csrf_token, || async {
        let username = form.username.trim().to_string();

        if !ALLOWED_REGISTER_USERS.iter().any(|allowed| allowed.eq_ignore_ascii_case(&username)) {
            let mut errors: HashMap<String, Vec<String>> = HashMap::new();
            errors.entry("username".to_string()).or_default()
            .push("Registration is limited to approved testers.".to_string());
        return render_register_form(&data, &session, &username, &errors);
    }

        let errors = validate_username(&username);
        if !errors.is_empty() {
            return render_register_form(&data, &session, &username, &errors);
        }

        match register_user_in_db(&data, &username).await {
            Ok((user_id, user_token)) => {
                // use user_id as stable identifier for JWT
                let token = generate_jwt(&user_id, &jwt_secret)?;

                let cookie = Cookie::build("jwt_token", token)
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .max_age(ActixDuration::days(30))
                    .finish();

                set_flash_message(
                    &session,
                    "Registration successful. Please save your user token safely!",
                    "success",
                )?;

                session.insert("user_token", &user_token)?; // secret token to show once
                session.insert("user_id", &user_id)?;
                session.insert("username", &username)?;
                session.insert("show_welcome", true)?;

                Ok(HttpResponse::Found()
                    .append_header(("Location", "/welcome"))
                    .cookie(cookie)
                    .finish())
            }
            Err(AppError::Validation(msg)) => {
                let mut errors: HashMap<String, Vec<String>> = HashMap::new();
                errors.entry("username".to_string()).or_default().push(msg);
                render_register_form(&data, &session, &username, &errors)
            }
            Err(e) => Err(e),
        }
    })
    .await
}

pub async fn register_success(
    data: web::Data<AppState>,
    session: Session,
) -> Result<HttpResponse, AppError> {
    let user_token: Option<String> = session.get("user_token")?; // match key used in registration
    if user_token.is_none() {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/register"))
            .finish());
    }

    let user_token = user_token.unwrap();
    session.remove("user_token");

    let show_welcome: Option<bool> = session.get("show_welcome")?;

    if show_welcome.unwrap_or(false) {
        session.remove("show_welcome");

        let mut context = Context::new();
        context.insert("site_name", "pastry");
        context.insert("user_token", &user_token);
        setup_user_context(&mut context, &data, &session)?;

        let rendered = render_template(&data.tera, "user/register_success.html", &context)?;
        Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
    } else {
        Ok(HttpResponse::Found()
            .append_header(("Location", "/"))
            .finish())
    }
}

pub async fn login_form(
    data: web::Data<AppState>,
    session: Session,
) -> Result<HttpResponse, AppError> {
    let mut context = Context::new();
    context.insert("site_name", "pastry");
    context.insert("csrf_token", &set_csrf_token(&session)?);
    setup_user_context(&mut context, &data, &session)?;
    let rendered = render_template(&data.tera, "user/login.html", &context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

pub async fn login(
    data: web::Data<AppState>,
    form: web::Form<LoginForm>,
    session: Session,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");

    with_csrf_validation(&session, form_csrf_token, || async {
        let username = form.username.trim();
        let user_token = form.user_token.trim(); // the secret token user provides

        let mut context = Context::new();
        context.insert("site_name", "pastry");
        context.insert("csrf_token", &set_csrf_token(&session)?);
        setup_user_context(&mut context, &data, &session)?;

        if username.is_empty() || user_token.is_empty() {
            set_flash_message(
                &session,
                "Username and user ID token cannot be empty",
                "error",
            )?;
            let rendered = render_template(&data.tera, "user/login.html", &context)?;
            return Ok(HttpResponse::Ok().content_type("text/html").body(rendered));
        }

        // fetch the stored bcrypt hash for the username
        let result = with_db_conn(&data, |conn| {
            conn.query_row(
                "SELECT user_token_hash, user_id FROM users WHERE username = ?1",
                params![username],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    AppError::Validation("Invalid username or token".to_string())
                }
                _ => AppError::Database(e),
            })
        })
        .await;

        match result {
            Ok((user_token_hash, user_id)) => {
                if verify(user_token, &user_token_hash)
                    .map_err(|e| AppError::Internal(format!("Verification error: {}", e)))?
                {
                    // check if user is banned
                    let is_banned = with_db_conn(&data, |conn| {
                        is_user_banned(conn, &user_id)
                    }).await?;

                    if is_banned {
                        set_flash_message(&session, "Your account is banned.", "error")?;
                        let rendered = render_template(&data.tera, "user/login.html", &context)?;
                        return Ok(HttpResponse::Ok().content_type("text/html").body(rendered));
                    }

                    // proceed with login
                    let token = generate_jwt(&user_id, &jwt_secret)?;
                    let cookie = Cookie::build("jwt_token", token)
                        .path("/")
                        .secure(true)
                        .http_only(true)
                        .max_age(ActixDuration::days(30))
                        .finish();

                    set_flash_message(&session, "Login successful", "success")?;
                    session.insert("user_id", &user_id)?;
                    session.insert("username", username)?;

                    Ok(HttpResponse::Found()
                        .append_header(("Location", "/"))
                        .cookie(cookie)
                        .finish())
                } else {
                    set_flash_message(&session, "Invalid username or token", "error")?;
                    let rendered = render_template(&data.tera, "user/login.html", &context)?;
                    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
                }
            }
            Err(AppError::Validation(msg)) => {
                set_flash_message(&session, &msg, "error")?;
                let rendered = render_template(&data.tera, "user/login.html", &context)?;
                Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
            }
            Err(e) => Err(e),
        }
    })
    .await
}

pub async fn logout(session: Session) -> Result<HttpResponse, AppError> {
    session.purge();
    let cookie = Cookie::build("jwt_token", "")
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(ActixDuration::seconds(0))
        .finish();
    set_flash_message(&session, "Logged out successfully", "success")?;
    Ok(HttpResponse::Found()
        .append_header(("Location", "/"))
        .cookie(cookie)
        .finish())
}
