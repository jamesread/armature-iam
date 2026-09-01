package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jamesread/armature-iam/store"
)

func (s *SQLite) ListAPIKeysForUser(ctx context.Context, userID int) ([]store.APIKeyRow, error) {
	rows, err := s.db.QueryContext(ctx, apiKeySelectSQL()+` WHERE user_account_id = ? ORDER BY name, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list api keys for user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]store.APIKeyRow, 0)
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (s *SQLite) CreateAPIKey(ctx context.Context, userID int, name, keyValue string, readOnly bool) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (user_account_id, name, key_value, read_only) VALUES (?, ?, ?, ?)`,
		userID, name, keyValue, boolToInt(readOnly),
	)
	if err != nil {
		return 0, fmt.Errorf("create api key: %w", err)
	}
	return lastID(res, "create api key")
}

func (s *SQLite) DeleteAPIKey(ctx context.Context, id, userID int) error {
	return s.execOp(ctx, "delete api key", `DELETE FROM api_keys WHERE id = ? AND user_account_id = ?`, id, userID)
}

func (s *SQLite) GetUserByAPIKey(ctx context.Context, keyValue string) (*store.UserAccountRow, bool, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.password_hash, u.created_by, u.created_at, u.updated_at, k.read_only
		 FROM api_keys k
		 INNER JOIN user_accounts u ON u.id = k.user_account_id
		 WHERE k.key_value = ?`, keyValue,
	)
	var u store.UserAccountRow
	var readOnly int
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedBy, &u.CreatedAt, &u.UpdatedAt, &readOnly); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get user by api key: %w", err)
	}
	return &u, readOnly != 0, nil
}

func (s *SQLite) TouchAPIKeyUsed(ctx context.Context, keyValue string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	return s.execOp(ctx, "touch api key used",
		`UPDATE api_keys SET last_used_at = ?, updated_at = datetime('now') WHERE key_value = ?`,
		now, keyValue)
}
