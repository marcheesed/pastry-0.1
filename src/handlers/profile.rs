use crate::common::constants::FRIENDS_PER_PAGE;
use crate::common::prelude::*;
use crate::common::utils::{
    add_friendship, are_friends, get_friends, get_user_id, get_user_id_from_jwt, get_user_profile,
    remove_friendship, render_template, set_csrf_token, set_flash_message, setup_user_context,
    user_exists, validate_username, with_csrf_validation, with_db_conn,
};
use crate::models::{Friend, ProfileForm};
use chrono::Duration;

struct ProfileFriendsData {
    user_id: String,
    username: String,
    bio: Option<String>,
    profile_picture_url: Option<String>,
    total_friends: u32,
    total_pages: u32,
    current_page: u32,
    friends: Vec<Friend>,
}

fn parse_profile_query_params(query: &str) -> Result<(bool, u32), AppError> {
    let query_params: web::Query<HashMap<String, String>> = web::Query::from_query(query)
        .map_err(|e| AppError::BadRequest(format!("Invalid query parameters: {}", e)))?;
    let edit_mode = query_params
        .get("edit")
        .map(|v| v == "true")
        .unwrap_or(false);
    let page: u32 = query_params
        .get("page")
        .and_then(|p| p.parse().ok())
        .unwrap_or(1);
    Ok((edit_mode, page))
}

fn get_profile_friends_data(
    conn: &rusqlite::Connection,
    username: &str,
    page: u32,
    friends_per_page: u32,
) -> Result<ProfileFriendsData, AppError> {
    let user_profile = get_user_profile(conn, username)?
        .ok_or_else(|| AppError::NotFound(format!("User '{}' not found", username)))?;

    let (user_id, username, bio, profile_picture_url) = user_profile;

    let total_friends: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM users u
         JOIN friendships f ON (u.user_id = f.user_id1 OR u.user_id = f.user_id2)
         WHERE (f.user_id1 = ?1 OR f.user_id2 = ?1) AND u.user_id != ?1",
            params![&user_id],
            |row| row.get(0),
        )
        .map_err(AppError::Database)?;

    let total_pages = (total_friends as f64 / friends_per_page as f64).ceil() as u32;
    let current_page = page.max(1).min(total_pages.max(1));
    let offset = (current_page - 1) * friends_per_page;

    let friends = get_friends(conn, &user_id, friends_per_page, offset)?;

    Ok(ProfileFriendsData {
        user_id,
        username,
        bio,
        profile_picture_url,
        total_friends,
        total_pages,
        current_page,
        friends,
    })
}

pub async fn view_profile(
    data: web::Data<AppState>,
    path: web::Path<String>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let username = path.into_inner();
    let (edit_mode, page) = parse_profile_query_params(req.query_string())?;
    let current_user_id_opt = get_user_id_from_jwt(&req, &jwt_secret)?;

    let result = with_db_conn(&data, |conn| {
        let profile_data = get_profile_friends_data(conn, &username, page, FRIENDS_PER_PAGE)?;

        let is_own_profile = current_user_id_opt
            .as_ref()
            .map(|id| id == &profile_data.user_id)
            .unwrap_or(false);

        let is_friend = if let Some(current_user_id) = &current_user_id_opt {
            if current_user_id != &profile_data.user_id {
                are_friends(conn, current_user_id, &profile_data.user_id)?
            } else {
                false
            }
        } else {
            false
        };

        let mut context = Context::new();
        context.insert("username", &profile_data.username);
        context.insert("bio", &profile_data.bio.as_ref().map(|s| s.as_str()));
        context.insert(
            "profile_picture_url",
            &profile_data
                .profile_picture_url
                .as_ref()
                .map(|s| s.as_str()),
        );
        context.insert("edit_mode", &edit_mode);
        context.insert("friends", &profile_data.friends);
        context.insert("is_own_profile", &is_own_profile);
        context.insert("is_friend", &is_friend);
        context.insert("csrf_token", &set_csrf_token(&session)?);
        context.insert("current_page", &profile_data.current_page);
        context.insert("total_pages", &profile_data.total_pages);
        context.insert("total_friends", &profile_data.total_friends);

        setup_user_context(&mut context, &data, &session)?;

        let template_name = if edit_mode {
            "user/edit_profile.html"
        } else {
            "user/profile.html"
        };
        let rendered = render_template(&data.tera, template_name, &context)?;
        Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
    })
    .await?;

    Ok(result)
}

pub async fn api_profile_friends(
    data: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, AppError> {
    let username = path.into_inner();
    let page: u32 = query.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);

    let result = with_db_conn(&data, |conn| {
        let profile_data = get_profile_friends_data(conn, &username, page, FRIENDS_PER_PAGE)?;

        Ok(serde_json::json!({
            "friends": profile_data.friends,
            "page": profile_data.current_page,
            "total_pages": profile_data.total_pages,
            "total_friends": profile_data.total_friends,
            "has_next": profile_data.current_page < profile_data.total_pages,
            "has_prev": profile_data.current_page > 1,
        }))
    })
    .await?;

    Ok(HttpResponse::Ok().json(result))
}

pub async fn update_profile(
    data: web::Data<AppState>,
    form: web::Form<ProfileForm>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");
    with_csrf_validation(&session, form_csrf_token, || async {
        let user_id = get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

        let new_username = form.username.trim().to_string();
        let mut errors = validate_username(&new_username);

        let result = with_db_conn(&data, |conn| {
            let tx = conn.transaction().map_err(AppError::Database)?;

            let (db_username, last_changed): (String, String) = tx.query_row(
                "SELECT username, username_last_changed FROM users WHERE user_id = ?1",
                params![user_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(AppError::Database)?;

            if new_username != db_username {
                if new_username == db_username {
                    errors.entry("username".to_string())
                        .or_default()
                        .push("Username must be different from current username".to_string());
                }

                let last_changed_time = chrono::DateTime::parse_from_rfc3339(&last_changed)
                    .map_err(|e| AppError::Internal(format!("Date parse error: {}", e)))?;
                let now = Utc::now();
                let two_weeks = Duration::weeks(2);

                if last_changed_time + two_weeks > now {
                    errors.entry("username".to_string())
                        .or_default()
                        .push("You can only change your username every two weeks".to_string());
                }

                if user_exists(&tx, &new_username)? {
                    errors.entry("username".to_string())
                        .or_default()
                        .push("Username already taken".to_string());
                }
            }

            if !errors.is_empty() {
                let mut context = Context::new();
                context.insert("site_name", "pastry");
                context.insert("csrf_token", &set_csrf_token(&session)?);
                setup_user_context(&mut context, &data, &session)?;
                context.insert("username", &new_username);
                context.insert("profile_picture_url", &form.profile_picture_url);
                context.insert("bio", &form.bio);
                context.insert("errors", &errors);

                let rendered = render_template(&data.tera, "user/edit_profile.html", &context)?;
                return Ok(HttpResponse::Ok().content_type("text/html").body(rendered));
            }

            let now_rfc3339 = Utc::now().to_rfc3339();
            if new_username != db_username {
                tx.execute(
                    "UPDATE users SET username = ?1, username_last_changed = ?2, profile_picture_url = ?3, bio = ?4 WHERE user_id = ?5",
                    params![new_username, now_rfc3339, form.profile_picture_url, form.bio, user_id],
                ).map_err(AppError::Database)?;
            } else {
                tx.execute(
                    "UPDATE users SET profile_picture_url = ?1, bio = ?2 WHERE user_id = ?3",
                    params![form.profile_picture_url, form.bio, user_id],
                ).map_err(AppError::Database)?;
            }
            tx.commit().map_err(AppError::Database)?;
            session.remove("csrf_token");
            session.remove("csrf_timestamp");

            set_flash_message(&session, "Profile updated successfully", "success")?;

            let redirect_url = format!("/profile/{}", new_username);

            Ok(HttpResponse::Found()
                .append_header(("Location", redirect_url))
                .finish())
        }).await;

        result
    }).await
}

pub async fn add_friend(
    data: web::Data<AppState>,
    form: web::Form<ProfileForm>,
    path: web::Path<String>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");
    with_csrf_validation(&session, form_csrf_token, || async {
        let friend_username = path.into_inner();

        let current_user_id = get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

        with_db_conn(&data, |conn| {
            let tx = conn.transaction().map_err(AppError::Database)?;

            let friend_user_id = get_user_id(&tx, &friend_username)?
                .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

            if current_user_id == friend_user_id {
                return Err(AppError::BadRequest(
                    "You cannot friend yourself".to_string(),
                ));
            }

            if are_friends(&tx, &current_user_id, &friend_user_id)? {
                return Err(AppError::BadRequest("Already friends".to_string()));
            }

            add_friendship(&tx, &current_user_id, &friend_user_id)?;
            tx.commit().map_err(AppError::Database)?;

            set_flash_message(&session, "Friend added successfully", "success")?;
            Ok(HttpResponse::Found()
                .append_header(("Location", format!("/profile/{}", friend_username)))
                .finish())
        })
        .await
    })
    .await
}

pub async fn remove_friend(
    data: web::Data<AppState>,
    form: web::Form<ProfileForm>,
    path: web::Path<String>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");
    with_csrf_validation(&session, form_csrf_token, || async {
        let friend_username = path.into_inner();

        let current_user_id = get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

        with_db_conn(&data, |conn| {
            let tx = conn.transaction().map_err(AppError::Database)?;

            let friend_user_id = get_user_id(&tx, &friend_username)?
                .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

            let deleted = remove_friendship(&tx, &current_user_id, &friend_user_id)?;

            if !deleted {
                return Err(AppError::BadRequest("Not friends".to_string()));
            }

            tx.commit().map_err(AppError::Database)?;
            set_flash_message(&session, "Friend removed successfully", "success")?;
            Ok(HttpResponse::Found()
                .append_header(("Location", format!("/profile/{}", friend_username)))
                .finish())
        })
        .await
    })
    .await
}
