package sqlite

import (
	"context"
	"fmt"

	"github.com/jamesread/armature-iam/rbac"
	"github.com/jamesread/armature-iam/store"
)

func (s *SQLite) GetMyPermissionsAudit(ctx context.Context, userID int) ([]string, []string, bool, []store.MyPermissionAuditRow, error) {
	groupNames, err := s.queryStrings(ctx,
		`SELECT g.name FROM user_groups g
		 INNER JOIN user_group_memberships ugm ON ugm.user_group_id = g.id
		 WHERE ugm.user_account_id = ?
		 ORDER BY g.name`, userID)
	if err != nil {
		return nil, nil, false, nil, fmt.Errorf("get my permissions audit groups: %w", err)
	}
	return s.finishPermissionsAudit(ctx, userID, groupNames)
}

func (s *SQLite) finishPermissionsAudit(ctx context.Context, userID int, groupNames []string) ([]string, []string, bool, []store.MyPermissionAuditRow, error) {
	roleNames, err := s.GetUserRbacRoleNames(ctx, userID)
	if err != nil {
		return nil, nil, false, nil, err
	}
	effective, err := s.LoadEffectiveRBAC(ctx, userID)
	if err != nil {
		return nil, nil, false, nil, err
	}
	rows, err := s.buildAuditRows(ctx, userID, effective)
	if err != nil {
		return nil, nil, false, nil, err
	}
	return groupNames, roleNames, effective.IsSuperuser, rows, nil
}

func (s *SQLite) buildAuditRows(ctx context.Context, userID int, effective *rbac.EffectiveRBAC) ([]store.MyPermissionAuditRow, error) {
	catalog, err := s.ListRBACPermissions(ctx)
	if err != nil {
		return nil, err
	}
	grants, err := s.grantingGroupsByPerm(ctx, userID)
	if err != nil {
		return nil, err
	}
	return auditFromCatalog(catalog, effective, grants), nil
}

func (s *SQLite) grantingGroupsByPerm(ctx context.Context, userID int) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT p.name, g.name FROM rbac_permissions p
		 INNER JOIN rbac_role_permissions rp ON rp.permission_id = p.id
		 INNER JOIN rbac_group_roles gr ON gr.role_id = rp.role_id
		 INNER JOIN user_group_memberships ugm ON ugm.user_group_id = gr.user_group_id
		 INNER JOIN user_groups g ON g.id = ugm.user_group_id
		 WHERE ugm.user_account_id = ?
		 ORDER BY p.name, g.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("get my permissions audit grants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanGrantPairs(rows)
}

func scanGrantPairs(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) (map[string][]string, error) {
	out := map[string][]string{}
	for rows.Next() {
		var permName, groupName string
		if err := rows.Scan(&permName, &groupName); err != nil {
			return nil, fmt.Errorf("scan permission grant: %w", err)
		}
		out[permName] = append(out[permName], groupName)
	}
	return out, rows.Err()
}

func auditFromCatalog(catalog []store.RBACPermissionRow, effective *rbac.EffectiveRBAC, grants map[string][]string) []store.MyPermissionAuditRow {
	rows := make([]store.MyPermissionAuditRow, 0, len(catalog))
	for _, p := range catalog {
		rows = append(rows, auditRow(p.Name, effective, grants[p.Name]))
	}
	return rows
}

func auditRow(name string, effective *rbac.EffectiveRBAC, groups []string) store.MyPermissionAuditRow {
	row := store.MyPermissionAuditRow{Permission: name, Granted: effective.Has(name)}
	if effective.IsSuperuser {
		return row
	}
	if groups == nil {
		groups = []string{}
	}
	row.GrantingGroups = groups
	return row
}
