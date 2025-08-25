use crate::common::constants::{
    ALLOWED_CHARS, EDIT_PASTE_URL_PREFIX, MAX_TOKEN_ATTEMPTS, RESERVED_TOKENS, SAVE_PASTE_URL,
    TEMPLATE_EDIT_PASTE, TEMPLATE_PASTE_FORM, TEMPLATE_PASTE_VIEW, TOKEN_LENGTH,
};
use crate::common::prelude::*;
use crate::common::utils::{
    get_paste_by_token, get_sanitizer, get_user_id_from_jwt, get_user_ids_from_usernames,
    render_404, render_template, set_csrf_token, set_flash_message, setup_edit_paste_context,
    setup_view_paste_context, validate_csrf_token, validate_paste_content, with_csrf_validation,
    with_db_conn, with_db_conn_async, is_user_admin,
};
use crate::models::{EditForm, FormData, Paste, PasteAction};
use rand::{rngs::OsRng, Rng};
use rusqlite::Transaction;

// renders the paste creation form
pub async fn index(data: web::Data<AppState>, session: Session) -> Result<HttpResponse, AppError> {
    let mut context = tera::Context::new();
    context.insert("site_name", "pastry");
    context.insert("save_paste_url", SAVE_PASTE_URL);
    context.insert("csrf_token", &set_csrf_token(&session)?);
    setup_view_paste_context(&mut context, &data, &session, None)?;
    let rendered = render_template(&data.tera, TEMPLATE_PASTE_FORM, &context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

// generates a unique token, either custom or random, with collision checks
fn generate_unique_token(
    tx: &Transaction,
    custom_token: Option<&String>,
) -> Result<String, AppError> {
    if let Some(custom_token) = custom_token {
        let token = custom_token.to_lowercase();

        if token.is_empty() {
            return Err(AppError::BadRequest(
                "Custom token cannot be empty.".to_string(),
            ));
        }
        if token.len() < 2 || token.len() > 20 {
            return Err(AppError::BadRequest(
                "Custom token must be 2-20 characters.".to_string(),
            ));
        }
        if !token.chars().all(|c| ALLOWED_CHARS.contains(&(c as u8))) {
            return Err(AppError::BadRequest(
                "Custom token contains invalid characters. Allowed: a-z, 0-9".to_string(),
            ));
        }
        if RESERVED_TOKENS.contains(&token.as_str()) {
            return Err(AppError::BadRequest(
                "Custom token is reserved.".to_string(),
            ));
        }
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM pastes WHERE token = ?1",
                params![&token],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;
        if count > 0 {
            return Err(AppError::BadRequest(
                "Custom URL token already taken, please choose another.".to_string(),
            ));
        }
        Ok(token)
    } else {
        let mut attempts = MAX_TOKEN_ATTEMPTS;
        loop {
            let token: String = (0..TOKEN_LENGTH)
                .map(|_| {
                    let idx = OsRng.gen_range(0..ALLOWED_CHARS.len());
                    ALLOWED_CHARS[idx] as char
                })
                .collect();
            if RESERVED_TOKENS.contains(&token.as_str()) {
                attempts -= 1;
                if attempts == 0 {
                    return Err(AppError::BadRequest(
                        "Failed to generate unique token after retries.".to_string(),
                    ));
                }
                continue;
            }
            let count: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM pastes WHERE token = ?1",
                    params![&token],
                    |row| row.get(0),
                )
                .map_err(AppError::Database)?;
            if count == 0 {
                return Ok(token);
            }
            attempts -= 1;
            if attempts == 0 {
                return Err(AppError::BadRequest(
                    "Failed to generate unique token after retries.".to_string(),
                ));
            }
        }
    }
}

pub async fn is_main_owner(
    conn: &rusqlite::Connection,
    paste_token: &str,
    user_id: &str,
) -> Result<bool, AppError> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pastes WHERE token = ?1 AND user_id = ?2",
            params![paste_token, user_id],
            |row| row.get(0),
        )
        .map_err(AppError::Database)?;
    Ok(count > 0)
}

pub async fn is_collaborator(
    conn: &rusqlite::Connection,
    paste_token: &str,
    user_id: &str,
) -> Result<bool, AppError> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM paste_collaborators WHERE paste_token = ?1 AND user_id = ?2",
            params![paste_token, user_id],
            |row| row.get(0),
        )
        .map_err(AppError::Database)?;
    Ok(count > 0)
}

async fn validate_and_get_paste(
    data: &web::Data<AppState>,
    token: &str,
    req: &HttpRequest,
    jwt_secret: &web::Data<String>,
) -> Result<(Paste, String), AppError> {
    let user_id = get_user_id_from_jwt(req, jwt_secret)?
        .ok_or_else(|| AppError::Unauthorized("User not logged in".to_string()))?;

    let paste = with_db_conn_async(data, |conn| async move {
        get_paste_by_token(&conn, token)?
            .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))
    })
    .await?;

    Ok((paste, user_id))
}

fn update_paste_content(
    tx: &Transaction,
    token: &str,
    content: &str,
    css: &str,
) -> Result<(), AppError> {
    let now_str = Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE pastes SET content = ?1, css = ?2, edit_timestamp = ?3 WHERE token = ?4",
        params![content, css, &now_str, token],
    )?;
    tx.execute(
        "UPDATE pastes_fts SET content = ?1 WHERE token = ?2",
        params![content, token],
    )?;
    Ok(())
}

fn update_ownership(
    tx: &Transaction,
    token: &str,
    new_owner_username: Option<&String>,
) -> Result<(), AppError> {
    if let Some(username) = new_owner_username
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let new_owner_user_id: String = tx
            .query_row(
                "SELECT user_id FROM users WHERE username = ?1",
                params![username],
                |row| row.get(0),
            )
            .map_err(|_| AppError::Validation("New owner username does not exist".to_string()))?;
        tx.execute(
            "UPDATE pastes SET user_id = ?1 WHERE token = ?2",
            params![new_owner_user_id, token],
        )?;
    }
    Ok(())
}

fn update_collaborators(
    tx: &Transaction,
    token: &str,
    paste_user_id: &str,
    collaborators_str: Option<&String>,
) -> Result<(), AppError> {
    tx.execute(
        "DELETE FROM paste_collaborators WHERE paste_token = ?1",
        params![token],
    )?;

    if let Some(collaborators) = collaborators_str {
        let usernames: Vec<&str> = collaborators
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        let collaborator_ids = get_user_ids_from_usernames(tx, &usernames)?;

        let mut stmt =
            tx.prepare("INSERT INTO paste_collaborators (paste_token, user_id) VALUES (?1, ?2)")?;
        for id in collaborator_ids {
            if id != paste_user_id {
                stmt.execute(params![token, id])?;
            }
        }
    }
    Ok(())
}

async fn handle_save_action(
    data: &web::Data<AppState>,
    session: &Session,
    token: &str,
    paste: &Paste,
    form: EditForm,
    is_main_owner: bool,
    is_admin: bool,
) -> Result<HttpResponse, AppError> {
    if let Err(e) =
        validate_paste_content(form.content.as_deref().unwrap_or(""), form.css.as_deref())
    {
        let mut context = tera::Context::new();
        context.insert("token", token);
        context.insert("paste", &paste.content);
        context.insert("css", &paste.css);
        context.insert("can_edit", &true);
        context.insert(
            "edit_paste_url",
            &format!("{}{}", EDIT_PASTE_URL_PREFIX, token),
        );
        context.insert("csrf_token", &set_csrf_token(session)?);
        context.insert(
            "errors",
            &HashMap::from([("form".to_string(), vec![e.to_string()])]),
        );
        setup_edit_paste_context(&mut context, data, session, paste)?;
        let body = render_template(&data.tera, TEMPLATE_EDIT_PASTE, &context)?;
        return Ok(HttpResponse::Ok().content_type("text/html").body(body));
    }

    let content = get_sanitizer()
        .clean(form.content.as_deref().unwrap_or(""))
        .to_string();
    let css = form.css.as_deref().unwrap_or("").to_string();

    with_db_conn_async(data, |mut conn| async move {
        let tx = conn.transaction()?;
        update_paste_content(&tx, token, &content, &css)?;
        if is_main_owner || is_admin {
            update_ownership(&tx, token, form.new_owner_username.as_ref())?;
            update_collaborators(
                &tx,
                token,
                &paste.user_id,
                form.collaborators_usernames.as_ref(),
            )?;
        } else if form.new_owner_username.is_some() || form.collaborators_usernames.is_some() {
            return Err(AppError::Unauthorized(
                "Only the main owner or admin can change owner or collaborators".to_string(),
            ));
        }
        tx.commit()?;
        Ok(())
    })
    .await?;

    set_flash_message(session, "Paste updated successfully", "success")?;
    Ok(HttpResponse::Found()
        .append_header(("Location", format!("/{}", token)))
        .finish())
}

async fn handle_delete_action(
    data: &web::Data<AppState>,
    session: &Session,
    token: &str,
    user_id: &str,
) -> Result<HttpResponse, AppError> {
    with_db_conn_async(data, |mut conn| async move {
        let is_main_owner = is_main_owner(&conn, token, user_id).await?;
        let is_admin = is_user_admin(&conn, user_id).await?;
        if !is_main_owner && !is_admin {
            return Err(AppError::Unauthorized(
                "Only the main owner or admin can delete this paste".to_string(),
            ));
        }
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM pastes WHERE token = ?1", params![token])?;
        tx.execute("DELETE FROM pastes_fts WHERE token = ?1", params![token])?;
        tx.execute(
            "DELETE FROM paste_collaborators WHERE paste_token = ?1",
            params![token],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await?;

    set_flash_message(session, "Paste deleted successfully", "success")?;
    Ok(HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish())
}

// saves a new paste to the db
pub async fn save_paste(
    data: web::Data<AppState>,
    form: web::Form<FormData>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");
    with_csrf_validation(&session, form_csrf_token, || async {
        if let Err(e) = validate_paste_content(&form.content, form.css.as_deref()) {
            set_flash_message(&session, &e.to_string(), "error")?;
            let mut context = tera::Context::new();
            context.insert("site_name", "pastry");
            context.insert("save_paste_url", SAVE_PASTE_URL);
            context.insert("csrf_token", &set_csrf_token(&session)?);
            context.insert("content", &form.content);
            context.insert("css", form.css.as_deref().unwrap_or(""));
            context.insert("custom_token", form.custom_token.as_deref().unwrap_or(""));
            context.insert("errors", &HashMap::from([("form".to_string(), vec![e.to_string()])]));
            setup_view_paste_context(&mut context, &data, &session, None)?;
            let rendered = render_template(&data.tera, TEMPLATE_PASTE_FORM, &context)?;
            return Ok(HttpResponse::Ok().content_type("text/html").body(rendered));
        }
        let user_id = get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("User not logged in".to_string()))?;
        with_db_conn(&data, |conn| {
            let tx = conn.transaction().map_err(AppError::Database)?;

            let user_exists = tx.query_row("SELECT 1 FROM users WHERE user_id = ?1", params![&user_id], |_| Ok(())).is_ok();
            if !user_exists {
                return Err(AppError::Unauthorized("Invalid user session. Please log in again.".to_string()));
            }
            let content = get_sanitizer().clean(&form.content).to_string();
            let css = form.css.as_deref().unwrap_or("").to_string();
            let token = generate_unique_token(&tx, form.custom_token.as_ref())?;
            let now_str = Utc::now().to_rfc3339();
            tx.execute(
                "INSERT INTO pastes (token, content, css, timestamp, edit_timestamp, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![&token, &content, &css, &now_str, &now_str, &user_id],
            )?;
            tx.execute(
                "INSERT INTO pastes_fts (token, content) VALUES (?1, ?2)",
                params![&token, &content],
            )?;
            tx.commit().map_err(AppError::Database)?;
            set_flash_message(&session, "Paste saved successfully", "success")?;
            Ok(HttpResponse::Found().append_header(("Location", format!("/{}", token))).finish())
        }).await
    }).await
}

// retrieves and displays a paste
pub async fn view_paste(
    data: web::Data<AppState>,
    path: web::Path<String>,
    session: Session,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();
    with_db_conn(&data, |conn| {
        let paste = match get_paste_by_token(conn, &token)? {
            Some(paste) => paste,
            None => return render_404(&data, &session),
        };

        let username = conn
            .query_row(
                "SELECT username FROM users WHERE user_id = ?1",
                &[&paste.user_id],
                |row| row.get(0),
            )
            .map_err(AppError::Database)
            .unwrap_or_else(|_| "Unknown".to_string());

        let mut context = tera::Context::new();
        context.insert("owner_username", &username);
        context.insert("owner_profile_url", &format!("/profile/{}", username));
        setup_view_paste_context(
            &mut context,
            &data,
            &session,
            Some(&Paste {
                content: get_sanitizer().clean(&paste.content).to_string(),
                ..paste
            }),
        )?;
        let rendered = render_template(&data.tera, TEMPLATE_PASTE_VIEW, &context)?;
        Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
    })
    .await
}

// retrieves the raw CSS for a paste
pub async fn view_raw_css(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();
    with_db_conn(&data, |conn| {
        let css: String = conn
            .query_row(
                "SELECT css FROM pastes WHERE token = ?1",
                &[&token],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    AppError::NotFound("Paste not found".to_string())
                }
                _ => AppError::Database(e),
            })?;
        Ok(HttpResponse::Ok().content_type("text/css").body(css))
    })
    .await
}

pub async fn edit_paste_form(
    data: web::Data<AppState>,
    path: web::Path<String>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();

    with_db_conn_async(&data.clone(), |conn| async move {
        let paste = match get_paste_by_token(&conn, &token)? {
            Some(paste) => paste,
            None => return render_404(&data, &session),
        };

        let user_id = get_user_id_from_jwt(&req, &jwt_secret)?;
        let (current_user_is_main_owner, current_user_can_edit, is_admin) = if let Some(u_id) = &user_id {
            let is_main_owner = is_main_owner(&conn, &token, u_id).await?;
            let is_admin = is_user_admin(&conn, u_id).await?;
            let can_edit = is_admin || is_main_owner || is_collaborator(&conn, &token, u_id).await?;
            (is_main_owner, can_edit, is_admin)
        } else {
            (false, false, false)
        };

        if !current_user_can_edit {
            return Err(AppError::Unauthorized(
                "You do not have permission to edit this paste".to_string(),
            ));
        }

        let mut collaborators_stmt = conn.prepare(
            "SELECT T2.username FROM paste_collaborators T1 JOIN users T2 ON T1.user_id = T2.user_id WHERE T1.paste_token = ?1"
        )?;
        let collaborators_usernames_vec: Vec<String> = collaborators_stmt
            .query_map(params![&token], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        let collaborators_usernames_str = collaborators_usernames_vec.join(", ");

        let mut context = tera::Context::new();
        setup_edit_paste_context(&mut context, &data, &session, &paste)?;
        context.insert("can_edit", &current_user_can_edit);
        context.insert("is_main_owner", &current_user_is_main_owner);
        context.insert("is_admin", &is_admin);
        context.insert("collaborators_usernames", &collaborators_usernames_str);

        let body = render_template(&data.tera, TEMPLATE_EDIT_PASTE, &context)?;
        Ok(HttpResponse::Ok().content_type("text/html").body(body))
    }).await
}

pub async fn edit_paste(
    data: web::Data<AppState>,
    path: web::Path<String>,
    form: web::Form<EditForm>,
    session: Session,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();

    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");
    if !validate_csrf_token(&session, form_csrf_token)? {
        return Err(AppError::BadRequest("Invalid CSRF token".to_string()));
    }

    let (paste, user_id) = validate_and_get_paste(&data, &token, &req, &jwt_secret).await?;

    let token_clone = token.clone();
    let user_id_clone = user_id.clone();

    let (is_main_owner, is_collaborator, is_admin) = with_db_conn_async(&data, |conn| async move {
        let is_admin = is_user_admin(&conn, &user_id_clone).await?;
        let is_main_owner = is_main_owner(&conn, &token_clone, &user_id_clone).await?;
        let is_collaborator = is_collaborator(&conn, &token_clone, &user_id_clone).await?;
        Ok((is_main_owner, is_collaborator, is_admin))
    })
    .await?;

    if !is_main_owner && !is_collaborator && !is_admin {
        return Err(AppError::Unauthorized(
            "You do not have permission to edit this paste".to_string(),
        ));
    }

    let response = match form.action {
        Some(PasteAction::Save) => {
            handle_save_action(
                &data,
                &session,
                &token,
                &paste,
                form.into_inner(),
                is_main_owner,
                is_admin,
            )
            .await?
        }
        Some(PasteAction::Delete) => {
            handle_delete_action(&data, &session, &token, &user_id).await?
        }
        None => HttpResponse::Found()
            .append_header(("Location", format!("{}{}", EDIT_PASTE_URL_PREFIX, token)))
            .finish(),
    };

    session.remove("csrf_token");
    Ok(response)
}