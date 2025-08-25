use crate::common::constants::EDIT_PASTE_URL_PREFIX;
use crate::common::prelude::*;
use crate::jws::validate_jwt;
use crate::models::Friend;
use crate::models::{Paste, TemplateUser};
use crate::state::AppState;
use actix_web::{error::ErrorInternalServerError, HttpResponse};
use ammonia::Builder;
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rand::{distributions::Alphanumeric, Rng};
use tera::Tera;

pub fn get_sanitizer() -> Builder<'static> {
    let mut builder = Builder::default();
    builder
        .add_tags(&[
            "div", "p", "span", "a", "ul", "ol", "li", "strong", "em", "br", "img", "table",
            "thead", "tbody", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6",
        ])
        .add_generic_attributes(&[
            "class", "id", "style", "href", "src", "alt", "title", "target",
        ])
        .add_url_schemes(&["http", "https", "mailto"]);
    builder
}

pub fn parse_timestamp(timestamp_str: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(timestamp_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

// database connection pool
pub fn get_db_conn(
    data: &web::Data<AppState>,
) -> Result<PooledConnection<SqliteConnectionManager>, actix_web::Error> {
    data.db_pool.get().map_err(|e| {
        log::error!("DB pool error: {:?}", e);
        ErrorInternalServerError("Database connection error")
    })
}

pub async fn with_db_conn<T, F>(data: &web::Data<AppState>, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut PooledConnection<SqliteConnectionManager>) -> Result<T, AppError>,
{
    let mut conn = get_db_conn(data)?;
    f(&mut conn)
}

pub async fn with_db_conn_async<T, Fut, F>(data: &web::Data<AppState>, f: F) -> Result<T, AppError>
where
    F: FnOnce(PooledConnection<SqliteConnectionManager>) -> Fut,
    Fut: std::future::Future<Output = Result<T, AppError>>,
{
    let conn = get_db_conn(data)?;
    f(conn).await
}

#[macro_export]
macro_rules! log_and_error {
    ($err:expr, $fmt:expr $(, $args:expr)* $(,)?) => {{
        log::error!(concat!($fmt, ": {:?}"), $($args,)* $err);
        actix_web::error::ErrorInternalServerError(format!(concat!($fmt, ": {:?}"), $($args,)* $err))
    }};
}

// csrf token
pub fn generate_csrf_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub fn set_csrf_token(session: &Session) -> Result<String, actix_web::Error> {
    let token = generate_csrf_token();
    session.insert("csrf_token", &token)?;
    session.insert("csrf_timestamp", Utc::now().timestamp())?;
    Ok(token)
}

pub fn validate_csrf_token(session: &Session, token: &str) -> Result<bool, actix_web::Error> {
    let stored_token: Option<String> = session.get("csrf_token")?;
    let timestamp: Option<i64> = session.get("csrf_timestamp")?;
    match (stored_token, timestamp) {
        (Some(stored), Some(ts)) => {
            let age = Utc::now().timestamp() - ts;
            if age > 1800 {
                log::warn!("CSRF token expired for session");
                session.remove("csrf_token");
                session.remove("csrf_timestamp");
                return Ok(false);
            }
            if stored != token {
                log::warn!(
                    "CSRF token mismatch: provided={}, expected={}",
                    token,
                    stored
                );
                return Ok(false);
            }
            Ok(true)
        }
        _ => {
            log::warn!("No CSRF token or timestamp found in session");
            Ok(false)
        }
    }
}

pub async fn with_csrf_validation<T, F, Fut>(
    session: &Session,
    form_csrf_token: &str,
    handler: F,
) -> Result<T, AppError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, AppError>>,
{
    if !validate_csrf_token(session, form_csrf_token)? {
        return Err(AppError::BadRequest("Invalid CSRF token".to_string()));
    }
    handler().await
}

// rendering
pub fn render_template(
    tera: &Tera,
    template_name: &str,
    context: &tera::Context,
) -> Result<String, AppError> {
    tera.render(template_name, context).map_err(|e| {
        log::error!("Template rendering error for {}: {:?}", template_name, e);
        AppError::Template(e)
    })
}

pub fn render_404(data: &web::Data<AppState>, session: &Session) -> Result<HttpResponse, AppError> {
    let mut context = tera::Context::new();
    context.insert("paste_form_url", "/");
    context.insert("info_url", "/info");
    context.insert("dashboard_url", "/dashboard");
    context.insert("login_url", "/login");
    context.insert("logout_url", "/logout");
    context.insert("register_url", "/register");

    if let Some(user) = get_template_user(data, session) {
        context.insert("current_user", &user);
        context.insert("user_profile_url", &format!("/profile/{}", user.username));
        context.insert("is_logged_in", &true);
    } else {
        context.insert("is_logged_in", &false);
    }

    context.insert("error", "Page or paste not found");
    let rendered = render_template(&data.tera, "404.html", &context)?;
    Ok(HttpResponse::NotFound()
        .content_type("text/html")
        .body(rendered))
}

// context setup
pub fn setup_view_paste_context(
    context: &mut tera::Context,
    data: &web::Data<AppState>,
    session: &Session,
    paste: Option<&Paste>,
) -> Result<(), AppError> {
    context.insert("paste_form_url", "/");
    context.insert("info_url", "/info");
    context.insert("dashboard_url", "/dashboard");
    context.insert("login_url", "/login");
    context.insert("logout_url", "/logout");
    context.insert("register_url", "/register");

    if let Some(user) = get_template_user(data, session) {
        context.insert("current_user", &user);
        context.insert("user_profile_url", &format!("/profile/{}", user.username));
        context.insert("is_logged_in", &true);
    } else {
        context.insert("is_logged_in", &false);
    }

    if let Some(paste) = paste {
        context.insert("paste", paste);
        context.insert(
            "timestamp",
            &paste.timestamp.format("%d %b %Y %H:%M UTC").to_string(),
        );
        context.insert(
            "edit_timestamp",
            &paste
                .edit_timestamp
                .format("%d %b %Y %H:%M UTC")
                .to_string(),
        );
        context.insert(
            "edit_paste_url",
            &format!("{}{}", EDIT_PASTE_URL_PREFIX, paste.token),
        );
    }
    Ok(())
}

pub fn setup_edit_paste_context(
    context: &mut tera::Context,
    data: &web::Data<AppState>,
    session: &Session,
    paste: &Paste,
) -> Result<(), AppError> {
    context.insert("paste_form_url", "/");
    context.insert("info_url", "/info");
    context.insert("dashboard_url", "/dashboard");
    context.insert("login_url", "/login");
    context.insert("logout_url", "/logout");
    context.insert("register_url", "/register");

    if let Some(user) = get_template_user(data, session) {
        context.insert("current_user", &user);
        context.insert("user_profile_url", &format!("/profile/{}", user.username));
        context.insert("is_logged_in", &true);
    } else {
        context.insert("is_logged_in", &false);
    }

    context.insert("paste", paste);
    context.insert("css", &paste.css);
    context.insert("can_edit", &true);
    context.insert(
        "edit_paste_url",
        &format!("{}{}", EDIT_PASTE_URL_PREFIX, paste.token),
    );
    context.insert("csrf_token", &set_csrf_token(session)?);
    Ok(())
}

pub fn setup_user_context(
    context: &mut Context,
    data: &web::Data<AppState>,
    session: &Session,
) -> Result<(), AppError> {
    context.insert("paste_form_url", "/");
    context.insert("info_url", "/info");
    context.insert("dashboard_url", "/dashboard");
    context.insert("login_url", "/login");
    context.insert("logout_url", "/logout");
    context.insert("register_url", "/register");

    if let Some(user) = get_template_user(data, session) {
        context.insert("current_user", &user);
        context.insert("user_profile_url", &format!("/profile/{}", user.username));
        context.insert("is_logged_in", &true);
    } else {
        context.insert("is_logged_in", &false);
    }

    let flash_messages = get_flash_messages(session);
    if !flash_messages.is_empty() {
        context.insert("flash_messages", &flash_messages);
    }

    Ok(())
}

// user getters

pub fn user_exists(conn: &rusqlite::Connection, username: &str) -> Result<bool, AppError> {
    conn.query_row(
        "SELECT 1 FROM users WHERE username = ?1",
        params![username],
        |_row| Ok(true),
    )
    .optional()
    .map_err(AppError::Database)
    .map(|opt| opt.is_some())
}

pub fn get_user_id(
    conn: &rusqlite::Connection,
    username: &str,
) -> Result<Option<String>, AppError> {
    conn.query_row(
        "SELECT user_id FROM users WHERE username = ?1",
        params![username],
        |row| row.get(0),
    )
    .optional()
    .map_err(AppError::Database)
}

pub fn get_user_id_from_jwt(
    req: &HttpRequest,
    jwt_secret: &str,
) -> Result<Option<String>, AppError> {
    if let Some(cookie) = req.cookie("jwt_token") {
        let token = cookie.value();
        let claims = validate_jwt(token, jwt_secret)?;
        Ok(Some(claims.sub))
    } else {
        Ok(None)
    }
}

pub fn get_user_ids_from_usernames(
    conn: &rusqlite::Connection,
    usernames: &[&str],
) -> Result<Vec<String>, AppError> {
    let mut user_ids = Vec::with_capacity(usernames.len());

    for &username in usernames {
        let user_id = get_user_id(conn, username)?.ok_or_else(|| {
            AppError::Validation(format!("Username '{}' does not exist", username))
        })?;
        user_ids.push(user_id);
    }

    Ok(user_ids)
}

pub fn get_template_user(data: &AppState, session: &Session) -> Option<TemplateUser> {
    if let Ok(Some(user_id)) = session.get::<String>("user_id") {
        let conn = data.db_pool.get().unwrap();
        let user = conn
            .query_row(
                "SELECT username, profile_picture_url FROM users WHERE user_id = ?1",
                &[&user_id],
                |row| {
                    Ok(TemplateUser {
                        username: row.get(0)?,
                        profile_picture_url: row.get(1)?,
                    })
                },
            )
            .ok();
        return user;
    }
    None
}

pub fn get_user_profile(
    conn: &rusqlite::Connection,
    username: &str,
) -> Result<Option<(String, String, Option<String>, Option<String>)>, AppError> {
    conn.query_row(
        "SELECT user_id, username, bio, profile_picture_url FROM users WHERE username = ?1",
        params![username],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .optional()
    .map_err(AppError::Database)
}

pub async fn get_user_role(
    conn: &rusqlite::Connection,
    user_id: &str,
) -> Result<String, AppError> {
    let role: String = conn.query_row(
        "SELECT role FROM users WHERE user_id = ?1",
        params![user_id],
        |row| row.get(0),
    ).map_err(AppError::Database)?;
    Ok(role)
}

pub async fn is_user_admin(
    conn: &rusqlite::Connection,
    user_id: &str,
) -> Result<bool, AppError> {
    Ok(get_user_role(conn, user_id).await?.to_lowercase() == "admin")
}

pub fn is_user_banned(
    conn: &rusqlite::Connection,
    user_id: &str,
    ) -> Result<bool, AppError> {
    conn.query_row(
        "SELECT banned FROM users WHERE user_id = ?1",
        params![user_id],
        |row| row.get(0),
    )
    .map_err(AppError::Database)
}

pub fn get_friends(
    conn: &rusqlite::Connection,
    user_id: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Friend>, AppError> {
    let mut stmt = conn
        .prepare(
            "SELECT u.username, u.profile_picture_url
         FROM users u
         JOIN friendships f ON (u.user_id = f.user_id1 OR u.user_id = f.user_id2)
         WHERE (f.user_id1 = ?1 OR f.user_id2 = ?1) AND u.user_id != ?1
         LIMIT ?2 OFFSET ?3",
        )
        .map_err(AppError::Database)?;

    let friend_iter = stmt
        .query_map(params![user_id, limit, offset], |row| {
            Ok(Friend {
                username: row.get(0)?,
                profile_picture_url: row.get(1)?,
            })
        })
        .map_err(AppError::Database)?;

    friend_iter
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::Database)
}

pub fn validate_username(username: &str) -> HashMap<String, Vec<String>> {
    let mut errors: HashMap<String, Vec<String>> = HashMap::new();

    if username.is_empty() {
        errors
            .entry("username".to_string())
            .or_default()
            .push("Username cannot be empty".to_string());
    } else if username.len() < 3 || username.len() > 20 {
        errors
            .entry("username".to_string())
            .or_default()
            .push("Username must be between 3 and 20 characters".to_string());
    } else if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        errors
            .entry("username".to_string())
            .or_default()
            .push("Username can only contain letters, numbers, or underscores".to_string());
    }

    errors
}

//friendship

pub fn are_friends(
    conn: &rusqlite::Connection,
    user_id1: &str,
    user_id2: &str,
) -> Result<bool, AppError> {
    conn.query_row(
        "SELECT 1 FROM friendships WHERE (user_id1 = ?1 AND user_id2 = ?2) OR (user_id1 = ?2 AND user_id2 = ?1)",
        params![user_id1, user_id2],
        |_row| Ok(true),
    )
    .optional()
    .map_err(AppError::Database)
    .map(|opt| opt.is_some())
}

pub fn add_friendship(
    conn: &rusqlite::Connection,
    user_id1: &str,
    user_id2: &str,
) -> Result<(), AppError> {
    let (uid1, uid2) = if user_id1 < user_id2 {
        (user_id1, user_id2)
    } else {
        (user_id2, user_id1)
    };

    conn.execute(
        "INSERT INTO friendships (user_id1, user_id2) VALUES (?1, ?2)",
        params![uid1, uid2],
    )
    .map_err(AppError::Database)
    .map(|_| ())
}

pub fn remove_friendship(
    conn: &rusqlite::Connection,
    user_id1: &str,
    user_id2: &str,
) -> Result<bool, AppError> {
    let (uid1, uid2) = if user_id1 < user_id2 {
        (user_id1, user_id2)
    } else {
        (user_id2, user_id1)
    };

    let deleted = conn
        .execute(
            "DELETE FROM friendships WHERE user_id1 = ?1 AND user_id2 = ?2",
            params![uid1, uid2],
        )
        .map_err(AppError::Database)?;

    Ok(deleted > 0)
}

// flash messages
pub fn set_flash_message(
    session: &Session,
    message: &str,
    category: &str,
) -> Result<(), actix_web::Error> {
    session.insert(format!("flash_{}", category), message)?;
    Ok(())
}

pub fn get_flash_messages(session: &Session) -> HashMap<String, String> {
    let mut messages = HashMap::new();
    if let Ok(Some(msg)) = session.get::<String>("flash_error") {
        messages.insert("error".to_string(), msg);
        session.remove("flash_error");
    }
    if let Ok(Some(msg)) = session.get::<String>("flash_success") {
        messages.insert("success".to_string(), msg);
        session.remove("flash_success");
    }
    messages
}

// paste specific
pub fn get_paste_by_token(
    conn: &PooledConnection<SqliteConnectionManager>,
    token: &str,
) -> Result<Option<Paste>, AppError> {
    conn.query_row(
        "SELECT token, content, css, timestamp, edit_timestamp, user_id FROM pastes WHERE token = ?1",
        &[token],
        |row| {
            Ok(Paste {
                token: row.get(0)?,
                content: row.get(1)?,
                css: row.get(2)?,
                timestamp: parse_timestamp(&row.get::<_, String>(3)?),
                edit_timestamp: parse_timestamp(&row.get::<_, String>(4)?),
                user_id: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(AppError::Database)
}

pub fn validate_paste_content(content: &str, css: Option<&str>) -> Result<(), AppError> {
    if content.trim().is_empty() {
        return Err(AppError::Validation(
            "Paste content cannot be empty".to_string(),
        ));
    }
    if content.len() > crate::common::constants::MAX_PASTE_CONTENT_SIZE {
        return Err(AppError::Validation(
            "Paste content too large (max 1MB)".to_string(),
        ));
    }
    if let Some(css) = css {
        if css.len() > crate::common::constants::MAX_CSS_SIZE {
            return Err(AppError::Validation(
                "CSS content too large (max 100KB)".to_string(),
            ));
        }
    }
    Ok(())
}

// dashboard

#[derive(Debug, serde::Serialize)]
pub struct Pagination {
    pub total_pages: usize,
    pub has_next: bool,
    pub has_prev: bool,
}

pub fn calculate_pagination(total_count: usize, page: usize, per_page: usize) -> Pagination {
    if per_page == 0 {
        return Pagination {
            total_pages: 1,
            has_next: false,
            has_prev: false,
        };
    }

    let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as usize;
    let total_pages = total_pages.max(1);
    let page = page.max(1).min(total_pages);
    let has_next = page < total_pages;
    let has_prev = page > 1;

    Pagination {
        total_pages,
        has_next,
        has_prev,
    }
}
