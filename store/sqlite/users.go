package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jamesread/armature-iam/store"
)

func (s *SQLite) CountUserAccounts(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_accounts`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count user accounts: %w", err)
	}
	return n, nil
}

func (s *SQLite) GetUserByUsername(ctx context.Context, username string) (*store.UserAccountRow, error) {
	return s.getUser(ctx, userAccountSelectSQL()+` WHERE username = ?`, username)
}

func (s *SQLite) GetUserByID(ctx context.Context, id int) (*store.UserAccountRow, error) {
	return s.getUser(ctx, userAccountSelectSQL()+` WHERE id = ?`, id)
}

func (s *SQLite) getUser(ctx context.Context, q string, arg any) (*store.UserAccountRow, error) {
	u, err := scanUserAccount(s.db.QueryRowContext(ctx, q, arg))
	if err != nil {
		return nil, ignoreNoRows(fmt.Errorf("get user: %w", err))
	}
	return u, nil
}

func (s *SQLite) ListUserAccounts(ctx context.Context) ([]store.UserAccountRow, error) {
	rows, err := s.db.QueryContext(ctx, userAccountSelectSQL()+` ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list user accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]store.UserAccountRow, 0)
	for rows.Next() {
		u, err := scanUserAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user account: %w", err)
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *SQLite) CreateUserAccount(ctx context.Context, username, passwordHash, createdBy string) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO user_accounts (username, password_hash, created_by) VALUES (?, ?, ?)`,
		username, passwordHash, createdBy,
	)
	if err != nil {
		return 0, fmt.Errorf("create user account: %w", err)
	}
	return lastID(res, "create user account")
}

func (s *SQLite) DeleteUserAccount(ctx context.Context, id int) error {
	return s.execOp(ctx, "delete user account", `DELETE FROM user_accounts WHERE id = ?`, id)
}

func (s *SQLite) UpdateUserPassword(ctx context.Context, id int, passwordHash string) error {
	return s.execOp(ctx, "update user password",
		`UPDATE user_accounts SET password_hash = ?, updated_at = datetime('now') WHERE id = ?`,
		passwordHash, id)
}

func lastID(res sql.Result, op string) (int, error) {
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s id: %w", op, err)
	}
	return int(id), nil
}

func execAffected(res sql.Result, err error, op string) error {
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s rows affected: %w", op, err)
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLite) execOp(ctx context.Context, op, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	return execAffected(res, err, op)
}

func execTxOp(ctx context.Context, tx *sql.Tx, op, q string, args ...any) error {
	res, err := tx.ExecContext(ctx, q, args...)
	return execAffected(res, err, op)
}
