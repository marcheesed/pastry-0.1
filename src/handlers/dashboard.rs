use crate::common::constants::{
    BASE_COUNT_SQL, BASE_PASTES_SQL, PASTES_PER_PAGE, SEARCH_COUNT_SQL, SEARCH_PASTES_SQL,
};
use crate::common::prelude::*;
use crate::common::utils::{
    calculate_pagination, get_db_conn, get_user_id_from_jwt, render_template, setup_user_context,
    Pagination,
};
use crate::models::{DashboardQuery, Paste};

#[derive(Debug)]
struct PasteResult {
    pastes: Vec<Paste>,
    page: usize,
    total_count: usize,
    pagination: Pagination,
}

#[derive(Debug)]
enum SortOption {
    TokenAsc,
    TimestampDesc,
    EditTimestampDesc,
}

impl SortOption {
    fn to_sql(&self) -> &'static str {
        match self {
            SortOption::TokenAsc => "token ASC",
            SortOption::TimestampDesc => "timestamp DESC",
            SortOption::EditTimestampDesc => "edit_timestamp DESC",
        }
    }
}

async fn fetch_user_pastes(
    conn: &rusqlite::Connection,
    user_id: &str,
    query: &DashboardQuery,
) -> Result<PasteResult, AppError> {
    let mut count_params: Vec<&dyn rusqlite::ToSql> = vec![&user_id];
    let mut search_pattern = None;

    let (count_sql, pastes_sql) = if let Some(ref search_term) = query.search {
        search_pattern = Some(format!("%{}%", search_term));
        (SEARCH_COUNT_SQL, SEARCH_PASTES_SQL)
    } else {
        (BASE_COUNT_SQL, BASE_PASTES_SQL)
    };

    if let Some(ref pattern) = search_pattern {
        count_params.push(pattern);
    }

    let total_count: i64 = conn
        .query_row(count_sql, count_params.as_slice(), |row| row.get(0))
        .map_err(AppError::Database)?;
    let total_count = total_count as usize;

    let page = query.page.unwrap_or(1);
    let pagination = calculate_pagination(total_count, page, PASTES_PER_PAGE);
    let page = page.max(1).min(pagination.total_pages); // Clamp page
    let offset = (page - 1) * PASTES_PER_PAGE;

    let mut sql = String::from(pastes_sql);
    let mut params: Vec<&dyn rusqlite::ToSql> = vec![&user_id];

    if let Some(ref pattern) = search_pattern {
        params.push(pattern);
    }

    let order_by = match query.sort.as_deref() {
        Some("a-z") => SortOption::TokenAsc,
        Some("created") => SortOption::TimestampDesc,
        Some("edited") => SortOption::EditTimestampDesc,
        _ => SortOption::TimestampDesc,
    }
    .to_sql();
    sql.push_str(&format!(" ORDER BY {} LIMIT ? OFFSET ?", order_by));

    let limit = PASTES_PER_PAGE as i64;
    let offset_i64 = offset as i64;
    params.push(&limit);
    params.push(&offset_i64);

    let mut stmt = conn.prepare(&sql).map_err(AppError::Database)?;
    let pastes = stmt
        .query_map(params.as_slice(), |row| {
            Ok(Paste {
                token: row.get(0)?,
                content: row.get(1)?,
                css: row.get(2)?,
                timestamp: crate::common::utils::parse_timestamp(&row.get::<_, String>(3)?),
                edit_timestamp: crate::common::utils::parse_timestamp(&row.get::<_, String>(4)?),
                user_id: row.get(5)?,
            })
        })
        .map_err(AppError::Database)?
        .collect::<Result<Vec<Paste>, _>>()
        .map_err(AppError::Database)?;

    Ok(PasteResult {
        pastes,
        page,
        total_count,
        pagination,
    })
}

pub async fn view_dashboard(
    data: web::Data<AppState>,
    session: Session,
    query: web::Query<DashboardQuery>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = get_user_id_from_jwt(&req, &jwt_secret)?
        .ok_or_else(|| AppError::Unauthorized("User not logged in".to_string()))?;

    let conn = get_db_conn(&data)?;
    let PasteResult {
        pastes,
        page,
        total_count,
        pagination,
    } = fetch_user_pastes(&conn, &user_id, &query).await?;

    let mut context = tera::Context::new();
    context.insert("pastes", &pastes);
    context.insert("user_id", &user_id);
    context.insert("site_name", "pastry");
    context.insert("page", &page);
    context.insert("total_pages", &pagination.total_pages);
    context.insert("total_count", &total_count);
    context.insert("has_next", &pagination.has_next);
    context.insert("has_prev", &pagination.has_prev);
    context.insert("search", &query.search);
    context.insert("sort", &query.sort);

    setup_user_context(&mut context, &data, &session)?;

    let rendered = render_template(&data.tera, "dashboard.html", &context)?;
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

pub async fn api_search_pastes(
    data: web::Data<AppState>,
    query: web::Query<DashboardQuery>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = get_user_id_from_jwt(&req, &jwt_secret)?
        .ok_or_else(|| AppError::Unauthorized("User not logged in".to_string()))?;

    let conn = get_db_conn(&data)?;
    let PasteResult {
        pastes,
        page,
        total_count,
        pagination,
    } = fetch_user_pastes(&conn, &user_id, &query).await?;

    let response = serde_json::json!({
        "pastes": pastes,
        "page": page,
        "total_pages": pagination.total_pages,
        "total_count": total_count,
        "has_next": pagination.has_next,
        "has_prev": pagination.has_prev,
    });

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(response))
}
