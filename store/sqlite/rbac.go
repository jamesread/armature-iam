package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jamesread/armature-iam/rbac"
	"github.com/jamesread/armature-iam/store"
)

func (s *SQLite) LoadEffectiveRBAC(ctx context.Context, userID int) (*rbac.EffectiveRBAC, error) {
	isSuper, err := s.userIsSuperuser(ctx, userID)
	if err != nil {
		return nil, err
	}
	perms, err := s.loadPermissionSet(ctx, userID, isSuper)
	if err != nil {
		return nil, err
	}
	roles, err := s.GetUserRbacRoleNames(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &rbac.EffectiveRBAC{IsSuperuser: isSuper, Permissions: perms, RoleNames: roles}, nil
}

func (s *SQLite) userIsSuperuser(ctx context.Context, userID int) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_group_memberships ugm
		 INNER JOIN rbac_group_roles gr ON gr.user_group_id = ugm.user_group_id
		 INNER JOIN rbac_roles r ON r.id = gr.role_id
		 WHERE ugm.user_account_id = ? AND r.name = ?`,
		userID, rbac.RoleSuperuser,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("load effective rbac superuser count: %w", err)
	}
	return n > 0, nil
}

func (s *SQLite) loadPermissionSet(ctx context.Context, userID int, isSuper bool) (map[string]bool, error) {
	q := `SELECT DISTINCT p.name FROM rbac_permissions p
			 INNER JOIN rbac_role_permissions rp ON rp.permission_id = p.id
			 INNER JOIN rbac_group_roles gr ON gr.role_id = rp.role_id
			 INNER JOIN user_group_memberships ugm ON ugm.user_group_id = gr.user_group_id
			 WHERE ugm.user_account_id = ?
			 ORDER BY p.name`
	args := []any{userID}
	if isSuper {
		q = `SELECT name FROM rbac_permissions ORDER BY name`
		args = nil
	}
	names, err := s.queryStrings(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("load effective rbac permissions: %w", err)
	}
	return stringSet(names), nil
}

func stringSet(names []string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out
}

func (s *SQLite) ListRBACPermissions(ctx context.Context) ([]store.RBACPermissionRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description FROM rbac_permissions ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list rbac permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]store.RBACPermissionRow, 0)
	for rows.Next() {
		var p store.RBACPermissionRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Description); err != nil {
			return nil, fmt.Errorf("scan rbac permission: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLite) GetRBACRole(ctx context.Context, id int) (*store.RBACRoleRow, error) {
	return s.loadRBACRole(ctx, id)
}

func (s *SQLite) loadRBACRole(ctx context.Context, id int) (*store.RBACRoleRow, error) {
	role, err := s.scanRBACRole(ctx, id)
	if err != nil || role == nil {
		return role, err
	}
	if err := s.fillRBACRole(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

func (s *SQLite) scanRBACRole(ctx context.Context, id int) (*store.RBACRoleRow, error) {
	var role store.RBACRoleRow
	err := s.db.QueryRowContext(ctx, `SELECT id, name, description FROM rbac_roles WHERE id = ?`, id).
		Scan(&role.ID, &role.Name, &role.Description)
	if err != nil {
		return nil, ignoreNoRows(fmt.Errorf("load rbac role: %w", err))
	}
	return &role, nil
}

func (s *SQLite) fillRBACRole(ctx context.Context, role *store.RBACRoleRow) error {
	permIDs, err := s.ListRolePermissionIDs(ctx, role.ID)
	if err != nil {
		return err
	}
	role.PermissionIDs = permIDs
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM rbac_group_roles WHERE role_id = ?`, role.ID).Scan(&role.GroupCount); err != nil {
		return fmt.Errorf("load rbac role group count: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ugm.user_account_id)
		 FROM user_group_memberships ugm
		 INNER JOIN rbac_group_roles gr ON gr.user_group_id = ugm.user_group_id
		 WHERE gr.role_id = ?`, role.ID,
	).Scan(&role.UserCount); err != nil {
		return fmt.Errorf("load rbac role user count: %w", err)
	}
	return nil
}

func (s *SQLite) ListRBACRoles(ctx context.Context) ([]store.RBACRoleRow, error) {
	ids, err := s.queryInts(ctx, `SELECT id FROM rbac_roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list rbac roles: %w", err)
	}
	out := make([]store.RBACRoleRow, 0, len(ids))
	for _, id := range ids {
		role, err := s.loadRBACRole(ctx, id)
		if err != nil {
			return nil, err
		}
		if role != nil {
			out = append(out, *role)
		}
	}
	return out, nil
}

func (s *SQLite) rbacRoleNameByID(ctx context.Context, id int) (string, error) {
	var name string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM rbac_roles WHERE id = ?`, id).Scan(&name)
	if err != nil {
		return "", err
	}
	return name, nil
}

func (s *SQLite) setRBACRolePermissionsTx(ctx context.Context, tx *sql.Tx, roleID int, permissionIDs []int) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM rbac_role_permissions WHERE role_id = ?`, roleID); err != nil {
		return fmt.Errorf("clear rbac role permissions: %w", err)
	}
	for _, pid := range permissionIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO rbac_role_permissions (role_id, permission_id) VALUES (?, ?)`,
			roleID, pid,
		); err != nil {
			return fmt.Errorf("insert rbac role permission: %w", err)
		}
	}
	return nil
}

func (s *SQLite) CreateRBACRole(ctx context.Context, name, description string, permissionIDs []int) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("create rbac role begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	id, err := s.insertRoleWithPerms(ctx, tx, name, description, permissionIDs)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("create rbac role commit: %w", err)
	}
	return id, nil
}

func (s *SQLite) insertRoleWithPerms(ctx context.Context, tx *sql.Tx, name, description string, permissionIDs []int) (int, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO rbac_roles (name, description) VALUES (?, ?)`, name, description)
	if err != nil {
		return 0, fmt.Errorf("create rbac role: %w", err)
	}
	id, err := lastID(res, "create rbac role")
	if err != nil {
		return 0, err
	}
	if err := s.setRBACRolePermissionsTx(ctx, tx, id, permissionIDs); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *SQLite) UpdateRBACRole(ctx context.Context, id int, name, description string, permissionIDs []int) error {
	curName, err := s.rbacRoleNameByID(ctx, id)
	if err != nil {
		return err
	}
	if rbac.IsSystemRole(curName) && name != curName {
		return fmt.Errorf("%w %q", store.ErrRenameSystemRole, curName)
	}
	return s.updateRBACRoleTx(ctx, id, name, description, permissionIDs, curName)
}

func (s *SQLite) updateRBACRoleTx(ctx context.Context, id int, name, description string, permissionIDs []int, curName string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("update rbac role begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := execTxOp(ctx, tx, "update rbac role",
		`UPDATE rbac_roles SET name = ?, description = ?, updated_at = datetime('now') WHERE id = ?`,
		name, description, id); err != nil {
		return err
	}
	if err := maybeSetRolePerms(ctx, s, tx, id, permissionIDs, curName); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("update rbac role commit: %w", err)
	}
	return nil
}

func maybeSetRolePerms(ctx context.Context, s *SQLite, tx *sql.Tx, id int, permissionIDs []int, curName string) error {
	if curName == rbac.RoleSuperuser {
		return nil
	}
	return s.setRBACRolePermissionsTx(ctx, tx, id, permissionIDs)
}

func (s *SQLite) DeleteRBACRole(ctx context.Context, id int) error {
	name, err := s.rbacRoleNameByID(ctx, id)
	if err != nil {
		return err
	}
	if rbac.IsSystemRole(name) {
		return fmt.Errorf("%w %q", store.ErrSystemRole, name)
	}
	return s.execOp(ctx, "delete rbac role", `DELETE FROM rbac_roles WHERE id = ?`, id)
}

func (s *SQLite) SetRBACRolePermissions(ctx context.Context, roleID int, permissionIDs []int) error {
	name, err := s.rbacRoleNameByID(ctx, roleID)
	if err != nil {
		return err
	}
	if name == rbac.RoleSuperuser {
		return fmt.Errorf("%w %q", store.ErrSystemRole, name)
	}
	return s.replaceRolePermissions(ctx, roleID, permissionIDs)
}

func (s *SQLite) replaceRolePermissions(ctx context.Context, roleID int, permissionIDs []int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set rbac role permissions begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.setRBACRolePermissionsTx(ctx, tx, roleID, permissionIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("set rbac role permissions commit: %w", err)
	}
	return nil
}

func (s *SQLite) ListRolePermissionIDs(ctx context.Context, roleID int) ([]int, error) {
	ids, err := s.queryInts(ctx, `SELECT permission_id FROM rbac_role_permissions WHERE role_id = ? ORDER BY permission_id`, roleID)
	if err != nil {
		return nil, fmt.Errorf("list role permission ids: %w", err)
	}
	return ids, nil
}

func (s *SQLite) ListPermissionRoleNames(ctx context.Context, permissionID int) ([]string, error) {
	names, err := s.queryStrings(ctx,
		`SELECT r.name FROM rbac_roles r
		 INNER JOIN rbac_role_permissions rp ON rp.role_id = r.id
		 WHERE rp.permission_id = ?
		 ORDER BY r.name`, permissionID)
	if err != nil {
		return nil, fmt.Errorf("list permission role names: %w", err)
	}
	return names, nil
}

func (s *SQLite) GetUserRbacRoleNames(ctx context.Context, userID int) ([]string, error) {
	names, err := s.queryStrings(ctx,
		`SELECT DISTINCT r.name FROM rbac_roles r
		 INNER JOIN rbac_group_roles gr ON gr.role_id = r.id
		 INNER JOIN user_group_memberships ugm ON ugm.user_group_id = gr.user_group_id
		 WHERE ugm.user_account_id = ?
		 ORDER BY r.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("get user rbac role names: %w", err)
	}
	return names, nil
}

func (s *SQLite) GetUserGroupRbacRoleIDs(ctx context.Context, groupID int) ([]int, error) {
	ids, err := s.queryInts(ctx, `SELECT role_id FROM rbac_group_roles WHERE user_group_id = ? ORDER BY role_id`, groupID)
	if err != nil {
		return nil, fmt.Errorf("get user group rbac role ids: %w", err)
	}
	return ids, nil
}

func (s *SQLite) SetUserGroupRbacRoles(ctx context.Context, groupID int, roleIDs []int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set user group rbac roles begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := replaceGroupRoles(ctx, tx, groupID, roleIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("set user group rbac roles commit: %w", err)
	}
	return s.ensureSuperuserCoverage(ctx)
}

func replaceGroupRoles(ctx context.Context, tx *sql.Tx, groupID int, roleIDs []int) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM rbac_group_roles WHERE user_group_id = ?`, groupID); err != nil {
		return fmt.Errorf("clear user group rbac roles: %w", err)
	}
	for _, roleID := range roleIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO rbac_group_roles (user_group_id, role_id) VALUES (?, ?)`,
			groupID, roleID,
		); err != nil {
			return fmt.Errorf("insert user group rbac role: %w", err)
		}
	}
	return nil
}

func (s *SQLite) ListRbacRoleGroupNames(ctx context.Context, roleID int) ([]string, error) {
	names, err := s.queryStrings(ctx,
		`SELECT g.name FROM user_groups g
		 INNER JOIN rbac_group_roles gr ON gr.user_group_id = g.id
		 WHERE gr.role_id = ?
		 ORDER BY g.name`, roleID)
	if err != nil {
		return nil, fmt.Errorf("list rbac role group names: %w", err)
	}
	return names, nil
}

func (s *SQLite) ListRbacRoleUsernames(ctx context.Context, roleID int) ([]string, error) {
	names, err := s.queryStrings(ctx,
		`SELECT DISTINCT u.username FROM user_accounts u
		 INNER JOIN user_group_memberships ugm ON ugm.user_account_id = u.id
		 INNER JOIN rbac_group_roles gr ON gr.user_group_id = ugm.user_group_id
		 WHERE gr.role_id = ?
		 ORDER BY u.username COLLATE NOCASE`, roleID)
	if err != nil {
		return nil, fmt.Errorf("list rbac role usernames: %w", err)
	}
	return names, nil
}
