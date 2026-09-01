package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jamesread/armature-iam/rbac"
	"github.com/jamesread/armature-iam/store"
)

func (s *SQLite) EnsureRBACBootstrap(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("ensure rbac bootstrap begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := runBootstrap(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ensure rbac bootstrap commit: %w", err)
	}
	return nil
}

func runBootstrap(ctx context.Context, tx *sql.Tx) error {
	if err := bootstrapGroups(ctx, tx); err != nil {
		return err
	}
	if err := bootstrapGroupRoles(ctx, tx); err != nil {
		return err
	}
	if err := bootstrapFirstSuperuser(ctx, tx); err != nil {
		return err
	}
	return bootstrapEveryoneMemberships(ctx, tx)
}

func bootstrapGroups(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_groups (name) VALUES (?), (?)`,
		rbac.GroupEveryone, rbac.GroupAdministrators,
	)
	if err != nil {
		return fmt.Errorf("ensure rbac bootstrap groups: %w", err)
	}
	return nil
}

func bootstrapGroupRoles(ctx context.Context, tx *sql.Tx) error {
	if err := insertGroupRole(ctx, tx, rbac.GroupEveryone, rbac.RoleMember); err != nil {
		return err
	}
	return insertGroupRole(ctx, tx, rbac.GroupAdministrators, rbac.RoleSuperuser)
}

func insertGroupRole(ctx context.Context, tx *sql.Tx, groupName, roleName string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO rbac_group_roles (user_group_id, role_id)
		 SELECT g.id, r.id FROM user_groups g CROSS JOIN rbac_roles r
		 WHERE g.name = ? AND r.name = ?`,
		groupName, roleName,
	)
	if err != nil {
		return fmt.Errorf("ensure rbac bootstrap group role: %w", err)
	}
	return nil
}

func bootstrapFirstSuperuser(ctx context.Context, tx *sql.Tx) error {
	var superCount int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ugm.user_account_id)
		 FROM user_group_memberships ugm
		 INNER JOIN rbac_group_roles gr ON gr.user_group_id = ugm.user_group_id
		 INNER JOIN rbac_roles r ON r.id = gr.role_id
		 WHERE r.name = ?`, rbac.RoleSuperuser,
	).Scan(&superCount); err != nil {
		return fmt.Errorf("ensure rbac bootstrap superuser count: %w", err)
	}
	if superCount > 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_group_memberships (user_account_id, user_group_id)
		 SELECT u.id, g.id FROM user_accounts u
		 CROSS JOIN user_groups g
		 WHERE g.name = ?
		 AND u.id = (SELECT MIN(id) FROM user_accounts)`,
		rbac.GroupAdministrators,
	)
	if err != nil {
		return fmt.Errorf("ensure rbac bootstrap first superuser: %w", err)
	}
	return nil
}

func bootstrapEveryoneMemberships(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_group_memberships (user_account_id, user_group_id)
		 SELECT u.id, g.id FROM user_accounts u
		 CROSS JOIN user_groups g
		 WHERE g.name = ?
		 AND NOT EXISTS (
		   SELECT 1 FROM user_group_memberships ugm WHERE ugm.user_account_id = u.id
		 )`, rbac.GroupEveryone,
	)
	if err != nil {
		return fmt.Errorf("ensure rbac bootstrap everyone memberships: %w", err)
	}
	return nil
}

func (s *SQLite) EnsureUserInEveryoneGroup(ctx context.Context, userID int) error {
	return s.EnsureUserInGroup(ctx, userID, rbac.GroupEveryone)
}

func (s *SQLite) EnsureUserInGroup(ctx context.Context, userID int, groupName string) error {
	groupName = strings.TrimSpace(groupName)
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_group_memberships (user_account_id, user_group_id)
		 SELECT ?, g.id FROM user_groups g WHERE g.name = ?`,
		userID, groupName)
	if err != nil {
		return fmt.Errorf("ensure user in group: %w", err)
	}
	return nil
}

func (s *SQLite) CountUsersWithSuperuserViaGroups(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ugm.user_account_id)
		 FROM user_group_memberships ugm
		 INNER JOIN rbac_group_roles gr ON gr.user_group_id = ugm.user_group_id
		 INNER JOIN rbac_roles r ON r.id = gr.role_id
		 WHERE r.name = ?`, rbac.RoleSuperuser,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users with superuser via groups: %w", err)
	}
	return n, nil
}

func (s *SQLite) ensureSuperuserCoverage(ctx context.Context) error {
	n, err := s.CountUsersWithSuperuserViaGroups(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNoSuperuser
	}
	return nil
}
