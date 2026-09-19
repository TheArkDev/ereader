-- Users
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  display_name TEXT,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Books
CREATE TABLE IF NOT EXISTS books (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  author TEXT,
  description TEXT,
  format TEXT NOT NULL CHECK (format IN ('pdf', 'epub')),
  file_key TEXT NOT NULL,       -- key of the book file inside the R2 bucket
  cover_key TEXT,               -- key of the cover image inside the R2 bucket (nullable)
  file_size INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Per-user reading progress (nice to have, used by the app to resume reading)
CREATE TABLE IF NOT EXISTS reading_progress (
  user_id TEXT NOT NULL,
  book_id TEXT NOT NULL,
  position TEXT,                -- page number (pdf) or CFI string (epub), stored as text
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, book_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (book_id) REFERENCES books(id)
);

CREATE INDEX IF NOT EXISTS idx_books_title ON books(title);
