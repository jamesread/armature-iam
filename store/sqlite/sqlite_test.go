package sqlite

import (
	"context"
	"testing"

	"github.com/jamesread/armature-iam/password"
	"github.com/jamesread/armature-iam/rbac"
	"github.com/jamesread/armature-iam/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTest(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBootstrapAndFirstUser(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	require.NoError(t, s.EnsureRBACBootstrap(ctx))

	hash, err := password.Hash("admin")
	require.NoError(t, err)
	id, err := s.CreateUserAccount(ctx, "admin", hash, store.UserCreatedByAdmin)
	require.NoError(t, err)
	require.NoError(t, s.EnsureUserInEveryoneGroup(ctx, id))
	require.NoError(t, s.EnsureRBACBootstrap(ctx))

	n, err := s.CountUsersWithSuperuserViaGroups(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	eff, err := s.LoadEffectiveRBAC(ctx, id)
	require.NoError(t, err)
	assert.True(t, eff.IsSuperuser)
	assert.True(t, eff.Has(rbac.PermissionUsersView))
}

func TestAPIKeyRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, err := s.CreateUserAccount(ctx, "alice", "", store.UserCreatedByAdmin)
	require.NoError(t, err)

	keyID, err := s.CreateAPIKey(ctx, id, "cli", "sa_testkey", true)
	require.NoError(t, err)
	assert.Positive(t, keyID)

	user, readOnly, err := s.GetUserByAPIKey(ctx, "sa_testkey")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "alice", user.Username)
	assert.True(t, readOnly)

	require.NoError(t, s.TouchAPIKeyUsed(ctx, "sa_testkey"))
}

func TestRefuseZeroSuperusers(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	require.NoError(t, s.EnsureRBACBootstrap(ctx))
	id, err := s.CreateUserAccount(ctx, "admin", "", store.UserCreatedByAdmin)
	require.NoError(t, err)
	require.NoError(t, s.EnsureRBACBootstrap(ctx))

	admins, err := s.GetUserGroupByName(ctx, rbac.GroupAdministrators)
	require.NoError(t, err)
	err = s.SetUserGroupMembers(ctx, admins.ID, nil)
	assert.ErrorIs(t, err, store.ErrNoSuperuser)

	_ = id
}

func TestCannotDeleteSystemGroup(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	g, err := s.GetUserGroupByName(ctx, rbac.GroupEveryone)
	require.NoError(t, err)
	err = s.DeleteUserGroup(ctx, g.ID)
	assert.ErrorIs(t, err, store.ErrSystemGroup)
}
