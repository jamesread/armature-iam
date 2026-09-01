package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEffectiveHas(t *testing.T) {
	assert.False(t, (*EffectiveRBAC)(nil).Has("x"))
	super := &EffectiveRBAC{IsSuperuser: true, Permissions: map[string]bool{}}
	assert.True(t, super.Has("anything"))
	member := &EffectiveRBAC{Permissions: map[string]bool{PermissionAppAccess: true}}
	assert.True(t, member.Has(PermissionAppAccess))
	assert.False(t, member.Has(PermissionUsersView))
}

func TestSystemNames(t *testing.T) {
	assert.True(t, IsSystemRole(RoleSuperuser))
	assert.True(t, IsSystemGroup(GroupEveryone))
	assert.False(t, IsSystemRole("parent"))
}
