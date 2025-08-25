use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tera::Tera;

pub struct AppState {
    pub db_pool: Pool<SqliteConnectionManager>,
    pub tera: Tera,
}

pub fn create_app_state() -> Result<AppState, Box<dyn std::error::Error>> {
    let manager = SqliteConnectionManager::file("pastes.db");
    let pool = Pool::new(manager)?;

    {
        let conn = pool.get()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                user_token_hash TEXT NOT NULL,
                username_last_changed TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                role TEXT NOT NULL DEFAULT 'user',
                banned BOOLEAN NOT NULL DEFAULT FALSE,
                bio TEXT,
                profile_picture_url TEXT
            );
            CREATE TABLE IF NOT EXISTS pastes (
                token TEXT PRIMARY KEY NOT NULL CHECK(token != ''),
                content TEXT NOT NULL,
                css TEXT,
                timestamp TEXT NOT NULL,
                edit_timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS paste_collaborators (
                paste_token TEXT NOT NULL,
                user_id TEXT NOT NULL,
                PRIMARY KEY (paste_token, user_id),
                FOREIGN KEY (paste_token) REFERENCES pastes(token) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS friendships (
                user_id1 TEXT NOT NULL,
                user_id2 TEXT NOT NULL,
                PRIMARY KEY (user_id1, user_id2),
                FOREIGN KEY (user_id1) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (user_id2) REFERENCES users(user_id) ON DELETE CASCADE,
                CHECK (user_id1 < user_id2)
            );
            
            CREATE INDEX IF NOT EXISTS idx_pastes_token ON pastes(token);
            CREATE INDEX IF NOT EXISTS idx_pastes_user_id ON pastes(user_id);
            CREATE INDEX IF NOT EXISTS idx_pastes_timestamp ON pastes(timestamp);
            CREATE INDEX IF NOT EXISTS idx_pastes_edit_timestamp ON pastes(edit_timestamp);
            CREATE INDEX IF NOT EXISTS idx_paste_collaborators_paste_token ON paste_collaborators(paste_token);
            CREATE INDEX IF NOT EXISTS idx_users_banned ON users(banned);

            CREATE VIRTUAL TABLE IF NOT EXISTS pastes_fts USING fts5(token, content, tokenize='unicode61');
        ")?;
    }

    let tera = Tera::new("templates/**/*")?;

    Ok(AppState {
        db_pool: pool,
        tera,
    })
}
