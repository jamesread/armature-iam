package rbac

const (
	PermissionAppAccess          = "app.access"
	PermissionUsersView          = "users.view"
	PermissionUsersCreate        = "users.create"
	PermissionUsersDelete        = "users.delete"
	PermissionUsersResetPassword = "users.reset-password"
	PermissionUserGroupsView     = "usergroups.view"
	PermissionUserGroupsManage   = "usergroups.manage"
	PermissionRbacView           = "rbac.view"
	PermissionRbacManage         = "rbac.manage"
	PermissionSystemSettings     = "system.settings"
	PermissionSystemLogs         = "system.logs"
	PermissionSystemImpersonate  = "system.impersonate"

	RoleSuperuser = "superuser"
	RoleMember    = "member"

	GroupEveryone        = "Everyone"
	GroupAdministrators  = "Administrators"
)

type EffectiveRBAC struct {
	Permissions map[string]bool
	RoleNames   []string
	IsSuperuser bool
}

func (e *EffectiveRBAC) Has(p string) bool {
	if e == nil {
		return false
	}
	if e.IsSuperuser {
		return true
	}
	return e.Permissions[p]
}

func IsSystemRole(name string) bool {
	return name == RoleSuperuser || name == RoleMember
}

func IsSystemGroup(name string) bool {
	return name == GroupEveryone || name == GroupAdministrators
}
