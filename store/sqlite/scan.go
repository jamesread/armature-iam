package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jamesread/armature-iam/store"
)

func userAccountSelectSQL() string {
	return `SELECT id, username, password_hash, created_by, created_at, updated_at FROM user_accounts`
}

func scanUserAccount(row interface{ Scan(dest ...any) error }) (*store.UserAccountRow, error) {
	var u store.UserAccountRow
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedBy, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func sessionSelectSQL() string {
	return `SELECT id, sid, user_account_id, impersonator_user_id, created_at, updated_at FROM sessions`
}

func scanSession(row interface{ Scan(dest ...any) error }) (*store.SessionRow, error) {
	var s store.SessionRow
	var impersonator sql.NullInt64
	if err := row.Scan(&s.ID, &s.SID, &s.UserAccountID, &impersonator, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	if impersonator.Valid {
		v := int(impersonator.Int64)
		s.ImpersonatorUserID = &v
	}
	return &s, nil
}

func apiKeySelectSQL() string {
	return `SELECT id, user_account_id, name, key_value, read_only, COALESCE(last_used_at, ''), created_at, updated_at FROM api_keys`
}

func scanAPIKey(row interface{ Scan(dest ...any) error }) (*store.APIKeyRow, error) {
	var k store.APIKeyRow
	var readOnly int
	if err := row.Scan(&k.ID, &k.UserAccountID, &k.Name, &k.KeyValue, &readOnly, &k.LastUsedAt, &k.CreatedAt, &k.UpdatedAt); err != nil {
		return nil, err
	}
	k.ReadOnly = readOnly != 0
	return &k, nil
}

func userGroupSelectSQL() string {
	return `SELECT g.id, g.name,
		(SELECT COUNT(*) FROM user_group_memberships m WHERE m.user_group_id = g.id) AS member_count,
		g.created_at, g.updated_at
		FROM user_groups g`
}

func scanUserGroup(row interface{ Scan(dest ...any) error }) (*store.UserGroupRow, error) {
	var g store.UserGroupRow
	if err := row.Scan(&g.ID, &g.Name, &g.MemberCount, &g.CreatedAt, &g.UpdatedAt); err != nil {
		return nil, err
	}
	return &g, nil
}

func ignoreNoRows(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

func (s *SQLite) queryStrings(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]string, 0)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLite) queryInts(ctx context.Context, q string, args ...any) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]int, 0)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
