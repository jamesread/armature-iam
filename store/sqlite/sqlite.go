package sqlite

import (
	"context"
	"database/sql"
	"strings"

	_ "github.com/mattn/go-sqlite3"

	migratefs "github.com/jamesread/armature-iam/migrate/sqlite"
)

// SQLite implements store.Store on a shared *sql.DB.
type SQLite struct {
	db *sql.DB
}

// New wraps an existing SQLite connection. The caller applies migrations.
func New(db *sql.DB) *SQLite {
	return &SQLite{db: db}
}

// OpenMemory opens a single-connection in-memory database and applies the IAM schema.
func OpenMemory() (*SQLite, error) {
	db, err := sql.Open("sqlite3", "file::memory:?_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := ApplySchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return New(db), nil
}

func (s *SQLite) DB() *sql.DB {
	return s.db
}

func (s *SQLite) Close() error {
	return s.db.Close()
}

func (s *SQLite) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// ApplySchema executes the Up section of the embedded IAM migration.
func ApplySchema(db *sql.DB) error {
	raw, err := migratefs.FS.ReadFile("3.iam.sql")
	if err != nil {
		return err
	}
	up := upSection(string(raw))
	_, err = db.Exec(up)
	return err
}

func upSection(sqlText string) string {
	const marker = "-- +migrate Down"
	if i := strings.Index(sqlText, marker); i >= 0 {
		return sqlText[:i]
	}
	return sqlText
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
