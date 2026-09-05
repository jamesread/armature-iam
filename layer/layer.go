package layer

import (
	"context"
	"encoding/json"
	"net/http"

	"connectrpc.com/authn"
	japauth "github.com/jamesread/httpauthshim"
	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/sirupsen/logrus"

	"github.com/jamesread/armature-iam/rbac"
	"github.com/jamesread/armature-iam/store"
)

const providerJWT = "jwt"
const providerCallbackBearer = "callback-bearer"

type Config struct {
	Logger               *logrus.Logger
	AuthYAML             map[string]any
	RequiredPermission   func(procedure string) string
	CookieName           string
	APIKeyPrefix         string
	AllowUnauthenticated []string
	DevDisableAuth       bool
	SecureCookies        bool
}

type Layer struct {
	Store store.Store
	shim  *japauth.AuthShimContext
	log   *logrus.Logger
	allow map[string]bool
	cfg   Config
}

func New(st store.Store, cfg Config) (*Layer, error) {
	cfg = normalizeConfig(cfg)
	l := &Layer{
		Store: st,
		cfg:   cfg,
		allow: allowSet(cfg.AllowUnauthenticated),
		log:   cfg.Logger,
	}
	if cfg.DevDisableAuth {
		l.log.Warn("armature-iam: DevDisableAuth is set: requests run as anonymous superuser")
		return l, nil
	}
	shim, err := l.newAuthShim()
	if err != nil {
		return nil, err
	}
	l.shim = shim
	return l, nil
}

func normalizeConfig(cfg Config) Config {
	if cfg.Logger == nil {
		cfg.Logger = logrus.New()
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "sid"
	}
	if cfg.RequiredPermission == nil {
		cfg.RequiredPermission = func(string) string { return rbac.PermissionAppAccess }
	}
	return cfg
}

func allowSet(names []string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out
}

func (l *Layer) WrapHandler(in http.Handler) http.Handler {
	return authn.NewMiddleware(l.Handle).Wrap(in)
}

func (l *Layer) Handle(ctx context.Context, req *http.Request) (any, error) {
	procedure, _ := authn.InferProcedure(req.URL)
	if l.cfg.DevDisableAuth {
		return l.handleDev(procedure)
	}
	return l.handleAuth(ctx, req, procedure)
}

func (l *Layer) handleDev(procedure string) (any, error) {
	au := &AuthenticatedUser{
		User: &store.UserAccountRow{ID: 0, Username: "anonymous"},
		RBAC: &rbac.EffectiveRBAC{IsSuperuser: true, Permissions: map[string]bool{}},
	}
	if l.allow[procedure] {
		return au, nil
	}
	return l.enforcePermission(au, procedure)
}

func (l *Layer) handleAuth(ctx context.Context, req *http.Request, procedure string) (any, error) {
	if out, err, ok := l.tryAPIKey(ctx, req, procedure); ok {
		return out, err
	}
	return l.handleShim(ctx, req, procedure)
}

func (l *Layer) tryAPIKey(ctx context.Context, req *http.Request, procedure string) (any, error, bool) {
	token, ok := authn.BearerToken(req)
	if !ok {
		return nil, nil, false
	}
	user, readOnly, err := l.Store.GetUserByAPIKey(ctx, token)
	if user == nil {
		if err != nil {
			l.log.WithError(err).Debug("GetUserByAPIKey")
		}
		return nil, nil, false
	}
	out, ferr := l.finishWithRBAC(ctx, &AuthenticatedUser{User: user, ReadOnly: readOnly}, procedure)
	return out, ferr, true
}

func (l *Layer) handleShim(ctx context.Context, req *http.Request, procedure string) (any, error) {
	shimUser, err := l.shim.AuthFromHttpReqWithError(req)
	if err != nil {
		return nil, authn.Errorf("Authentication Required")
	}
	if shimUser.IsGuest() {
		return l.guestResult(procedure)
	}
	dbUser, err := l.resolveDBUser(ctx, shimUser)
	if err != nil || dbUser == nil {
		l.log.WithField("username", shimUser.Username).Warn("session user not in database")
		return nil, authn.Errorf("Authentication Required")
	}
	au := &AuthenticatedUser{User: dbUser, ReadOnly: shimUser.Provider == providerCallbackBearer}
	return l.finishWithRBAC(ctx, au, procedure)
}

func (l *Layer) guestResult(procedure string) (any, error) {
	if l.allow[procedure] {
		return nil, nil
	}
	return nil, authn.Errorf("Authentication Required")
}

func (l *Layer) finishWithRBAC(ctx context.Context, au *AuthenticatedUser, procedureName string) (any, error) {
	rb, err := l.Store.LoadEffectiveRBAC(ctx, au.User.ID)
	if err != nil {
		l.log.WithError(err).Error("LoadEffectiveRBAC")
		return nil, authn.Errorf("Authentication Required")
	}
	au.RBAC = rb
	if l.allow[procedureName] {
		return au, nil
	}
	return l.enforcePermission(au, procedureName)
}

func (l *Layer) enforcePermission(au *AuthenticatedUser, procedureName string) (any, error) {
	req := l.cfg.RequiredPermission(procedureName)
	if req != "" && !au.HasPermission(req) {
		l.log.WithFields(logrus.Fields{
			"user":      au.User.Username,
			"procedure": procedureName,
			"perm":      req,
		}).Warn("RBAC denied")
		return nil, authn.Errorf("Forbidden")
	}
	return au, nil
}

func (l *Layer) resolveDBUser(ctx context.Context, shimUser *authpublic.AuthenticatedUser) (*store.UserAccountRow, error) {
	if shimUser == nil || shimUser.Username == "" {
		return nil, nil
	}
	user, err := l.Store.GetUserByUsername(ctx, shimUser.Username)
	if err != nil || user != nil {
		return user, err
	}
	return l.maybeProvisionSSO(ctx, shimUser)
}

func (l *Layer) maybeProvisionSSO(ctx context.Context, shimUser *authpublic.AuthenticatedUser) (*store.UserAccountRow, error) {
	if shimUser.Provider != providerJWT {
		return nil, nil
	}
	return l.provisionSSOUser(ctx, shimUser.Username)
}

func (l *Layer) provisionSSOUser(ctx context.Context, username string) (*store.UserAccountRow, error) {
	id, err := l.Store.CreateUserAccount(ctx, username, "", store.UserCreatedBySSO)
	if err != nil {
		if existing, _ := l.Store.GetUserByUsername(ctx, username); existing != nil {
			return existing, nil
		}
		return nil, err
	}
	if err := l.Store.EnsureUserInEveryoneGroup(ctx, id); err != nil {
		l.log.WithError(err).Warn("EnsureUserInEveryoneGroup for SSO user")
	}
	return l.Store.GetUserByID(ctx, id)
}

func (l *Layer) WrapMCPHandler(in http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, status, err := l.authenticateMCP(r)
		if err != nil {
			writeMCPAuthError(w, status, err.Error())
			return
		}
		in.ServeHTTP(w, r.WithContext(authn.SetInfo(r.Context(), au)))
	})
}

func writeMCPAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (l *Layer) authenticateMCP(r *http.Request) (*AuthenticatedUser, int, error) {
	if l.cfg.DevDisableAuth {
		return l.devUser(), http.StatusOK, nil
	}
	return l.authenticateMCPBearer(r)
}

func (l *Layer) authenticateMCPBearer(r *http.Request) (*AuthenticatedUser, int, error) {
	if _, ok := authn.BearerToken(r); !ok {
		return nil, http.StatusUnauthorized, errMCPAuth
	}
	shimUser, err := l.shim.AuthFromHttpReqWithError(r)
	if err != nil || shimUser.IsGuest() || shimUser.Provider != providerCallbackBearer {
		return nil, http.StatusUnauthorized, errMCPAuth
	}
	return l.mcpFinish(r.Context(), r)
}

func (l *Layer) mcpFinish(ctx context.Context, r *http.Request) (*AuthenticatedUser, int, error) {
	token, _ := authn.BearerToken(r)
	user, readOnly, err := l.Store.GetUserByAPIKey(ctx, token)
	if err != nil || user == nil {
		return nil, http.StatusUnauthorized, errMCPAuth
	}
	info, rbacErr := l.finishWithRBAC(ctx, &AuthenticatedUser{User: user, ReadOnly: readOnly}, "")
	if rbacErr != nil {
		return nil, http.StatusForbidden, errMCPForbidden
	}
	return info.(*AuthenticatedUser), http.StatusOK, nil
}

func (l *Layer) devUser() *AuthenticatedUser {
	return &AuthenticatedUser{
		User: &store.UserAccountRow{Username: "anonymous"},
		RBAC: &rbac.EffectiveRBAC{IsSuperuser: true, Permissions: map[string]bool{}},
	}
}

type mcpAuthErr struct{ msg string }

func (e *mcpAuthErr) Error() string { return e.msg }

var (
	errMCPAuth      = &mcpAuthErr{msg: "Authorization required: Bearer API key"}
	errMCPForbidden = &mcpAuthErr{msg: "Forbidden"}
)

func UserFromContext(ctx context.Context) *AuthenticatedUser {
	info := authn.GetInfo(ctx)
	if info == nil {
		return nil
	}
	au, _ := info.(*AuthenticatedUser)
	return au
}
