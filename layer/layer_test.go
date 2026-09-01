package layer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jamesread/armature-iam/rbac"
	iamsqlite "github.com/jamesread/armature-iam/store/sqlite"
)

func TestUserHelpers(t *testing.T) {
	assert.False(t, (*AuthenticatedUser)(nil).CanAccessControlPanel())
	set := map[string]bool{rbac.PermissionUsersView: true}
	au := &AuthenticatedUser{RBAC: &rbac.EffectiveRBAC{Permissions: set}}
	assert.True(t, au.CanAccessIam())
	assert.False(t, au.CanAccessSettings())
	assert.True(t, au.CanAccessControlPanel())
}

func TestDevDisableAuth(t *testing.T) {
	st, err := iamsqlite.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	l, err := New(st, Config{
		DevDisableAuth:     true,
		AllowUnauthenticated: []string{"/login"},
		RequiredPermission: func(string) string { return rbac.PermissionAppAccess },
	})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/app.v1.Svc/Foo", nil)
	info, err := l.Handle(req.Context(), req)
	require.NoError(t, err)
	au := info.(*AuthenticatedUser)
	assert.True(t, au.HasPermission(rbac.PermissionAppAccess))
}

func TestAPIKeyAuth(t *testing.T) {
	st, err := iamsqlite.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	id, err := st.CreateUserAccount(ctx, "alice", "", "admin-created")
	require.NoError(t, err)
	require.NoError(t, st.EnsureUserInEveryoneGroup(ctx, id))
	require.NoError(t, st.EnsureRBACBootstrap(ctx))
	_, err = st.CreateAPIKey(ctx, id, "cli", "sa_secret", false)
	require.NoError(t, err)

	l, err := New(st, Config{
		AllowUnauthenticated: []string{},
		RequiredPermission:   func(string) string { return rbac.PermissionAppAccess },
		SecureCookies:        true,
	})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(ctx, "POST", "/app.v1.Svc/Foo", nil)
	req.Header.Set("Authorization", "Bearer sa_secret")
	info, err := l.Handle(ctx, req)
	require.NoError(t, err)
	au := info.(*AuthenticatedUser)
	assert.Equal(t, "alice", au.User.Username)
	assert.False(t, au.ReadOnly)
}

func TestGuestDenied(t *testing.T) {
	st, err := iamsqlite.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	l, err := New(st, Config{
		RequiredPermission: func(string) string { return rbac.PermissionAppAccess },
	})
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/app.v1.Svc/Foo", nil)
	_, err = l.Handle(req.Context(), req)
	assert.Error(t, err)
}

func TestSessionCookieHelpers(t *testing.T) {
	st, err := iamsqlite.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	l, err := New(st, Config{CookieName: "app-sid", DevDisableAuth: true, SecureCookies: true})
	require.NoError(t, err)
	c := l.NewSessionCookie("abc")
	assert.Equal(t, "app-sid", c.Name)
	assert.Equal(t, "abc", c.Value)
	assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
	assert.True(t, c.Secure)
	clear := l.ClearSessionCookie()
	assert.Equal(t, -1, clear.MaxAge)
}
