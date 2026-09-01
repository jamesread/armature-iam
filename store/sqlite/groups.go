package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jamesread/armature-iam/rbac"
	"github.com/jamesread/armature-iam/store"
)

func (s *SQLite) ListUserGroups(ctx context.Context) ([]store.UserGroupRow, error) {
	return s.queryUserGroups(ctx, userGroupSelectSQL()+` ORDER BY g.name`)
}

func (s *SQLite) GetUserGroupByName(ctx context.Context, name string) (*store.UserGroupRow, error) {
	return s.getUserGroup(ctx, userGroupSelectSQL()+` WHERE g.name = ?`, name)
}

func (s *SQLite) GetUserGroupByID(ctx context.Context, id int) (*store.UserGroupRow, error) {
	return s.getUserGroup(ctx, userGroupSelectSQL()+` WHERE g.id = ?`, id)
}

func (s *SQLite) getUserGroup(ctx context.Context, q string, arg any) (*store.UserGroupRow, error) {
	g, err := scanUserGroup(s.db.QueryRowContext(ctx, q, arg))
	if err != nil {
		return nil, ignoreNoRows(fmt.Errorf("get user group: %w", err))
	}
	return g, nil
}

func (s *SQLite) queryUserGroups(ctx context.Context, q string, args ...any) ([]store.UserGroupRow, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list user groups: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]store.UserGroupRow, 0)
	for rows.Next() {
		g, err := scanUserGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user group: %w", err)
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (s *SQLite) CreateUserGroup(ctx context.Context, name string) (int, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO user_groups (name) VALUES (?)`, name)
	if err != nil {
		return 0, fmt.Errorf("create user group: %w", err)
	}
	return lastID(res, "create user group")
}

func (s *SQLite) userGroupNameByID(ctx context.Context, id int) (string, error) {
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM user_groups WHERE id = ?`, id).Scan(&name); err != nil {
		return "", err
	}
	return name, nil
}

func (s *SQLite) DeleteUserGroup(ctx context.Context, id int) error {
	name, err := s.userGroupNameByID(ctx, id)
	if err != nil {
		return err
	}
	if rbac.IsSystemGroup(name) {
		return fmt.Errorf("%w %q", store.ErrSystemGroup, name)
	}
	return s.execOp(ctx, "delete user group", `DELETE FROM user_groups WHERE id = ?`, id)
}

func (s *SQLite) ListUserGroupMemberIDs(ctx context.Context, groupID int) ([]int, error) {
	ids, err := s.queryInts(ctx, `SELECT user_account_id FROM user_group_memberships WHERE user_group_id = ? ORDER BY user_account_id`, groupID)
	if err != nil {
		return nil, fmt.Errorf("list user group member ids: %w", err)
	}
	return ids, nil
}

func (s *SQLite) ListUserGroupIDsForUser(ctx context.Context, userID int) ([]int, error) {
	ids, err := s.queryInts(ctx, `SELECT user_group_id FROM user_group_memberships WHERE user_account_id = ? ORDER BY user_group_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user group ids for user: %w", err)
	}
	return ids, nil
}

func (s *SQLite) SetUserGroupMembers(ctx context.Context, groupID int, userIDs []int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set user group members begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := replaceGroupMembers(ctx, tx, groupID, userIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("set user group members commit: %w", err)
	}
	return s.ensureSuperuserCoverage(ctx)
}

func replaceGroupMembers(ctx context.Context, tx *sql.Tx, groupID int, userIDs []int) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_group_memberships WHERE user_group_id = ?`, groupID); err != nil {
		return fmt.Errorf("clear user group members: %w", err)
	}
	for _, userID := range userIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_group_memberships (user_account_id, user_group_id) VALUES (?, ?)`,
			userID, groupID,
		); err != nil {
			return fmt.Errorf("insert user group member: %w", err)
		}
	}
	return nil
}
