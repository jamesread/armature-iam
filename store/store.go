package store

import (
	"context"

	"github.com/jamesread/armature-iam/rbac"
)

// Store persists users, sessions, API keys, groups, and RBAC.
type Store interface {
	CountUserAccounts(ctx context.Context) (int, error)
	GetUserByUsername(ctx context.Context, username string) (*UserAccountRow, error)
	GetUserByID(ctx context.Context, id int) (*UserAccountRow, error)
	ListUserAccounts(ctx context.Context) ([]UserAccountRow, error)
	CreateUserAccount(ctx context.Context, username, passwordHash, createdBy string) (int, error)
	DeleteUserAccount(ctx context.Context, id int) error
	UpdateUserPassword(ctx context.Context, id int, passwordHash string) error

	CreateSession(ctx context.Context, sid string, userID int, impersonatorID *int) error
	GetSessionBySID(ctx context.Context, sid string) (*SessionRow, error)
	DeleteSession(ctx context.Context, sid string) error
	DeleteSessionsForUser(ctx context.Context, userID int) error

	ListAPIKeysForUser(ctx context.Context, userID int) ([]APIKeyRow, error)
	CreateAPIKey(ctx context.Context, userID int, name, keyValue string, readOnly bool) (int, error)
	DeleteAPIKey(ctx context.Context, id, userID int) error
	GetUserByAPIKey(ctx context.Context, keyValue string) (*UserAccountRow, bool, error)
	TouchAPIKeyUsed(ctx context.Context, keyValue string) error

	LoadEffectiveRBAC(ctx context.Context, userID int) (*rbac.EffectiveRBAC, error)
	EnsureRBACBootstrap(ctx context.Context) error
	EnsureUserInEveryoneGroup(ctx context.Context, userID int) error
	EnsureUserInGroup(ctx context.Context, userID int, groupName string) error
	CountUsersWithSuperuserViaGroups(ctx context.Context) (int, error)

	ListRBACPermissions(ctx context.Context) ([]RBACPermissionRow, error)
	ListRBACRoles(ctx context.Context) ([]RBACRoleRow, error)
	GetRBACRole(ctx context.Context, id int) (*RBACRoleRow, error)
	CreateRBACRole(ctx context.Context, name, description string, permissionIDs []int) (int, error)
	UpdateRBACRole(ctx context.Context, id int, name, description string, permissionIDs []int) error
	DeleteRBACRole(ctx context.Context, id int) error
	SetRBACRolePermissions(ctx context.Context, roleID int, permissionIDs []int) error
	ListRolePermissionIDs(ctx context.Context, roleID int) ([]int, error)
	ListPermissionRoleNames(ctx context.Context, permissionID int) ([]string, error)
	GetUserRbacRoleNames(ctx context.Context, userID int) ([]string, error)
	GetUserGroupRbacRoleIDs(ctx context.Context, groupID int) ([]int, error)
	SetUserGroupRbacRoles(ctx context.Context, groupID int, roleIDs []int) error
	ListRbacRoleGroupNames(ctx context.Context, roleID int) ([]string, error)
	ListRbacRoleUsernames(ctx context.Context, roleID int) ([]string, error)
	GetMyPermissionsAudit(ctx context.Context, userID int) ([]string, []string, bool, []MyPermissionAuditRow, error)

	ListUserGroups(ctx context.Context) ([]UserGroupRow, error)
	GetUserGroupByName(ctx context.Context, name string) (*UserGroupRow, error)
	GetUserGroupByID(ctx context.Context, id int) (*UserGroupRow, error)
	CreateUserGroup(ctx context.Context, name string) (int, error)
	DeleteUserGroup(ctx context.Context, id int) error
	ListUserGroupMemberIDs(ctx context.Context, groupID int) ([]int, error)
	ListUserGroupIDsForUser(ctx context.Context, userID int) ([]int, error)
	SetUserGroupMembers(ctx context.Context, groupID int, userIDs []int) error
}
