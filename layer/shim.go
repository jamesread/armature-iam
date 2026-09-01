package layer

import (
	"context"
	"os"
	"path/filepath"

	japauth "github.com/jamesread/httpauthshim"
	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/jamesread/httpauthshim/providers/hascallback"
	"github.com/jamesread/httpauthshim/providers/hasjwt"
	"github.com/jamesread/httpauthshim/providers/hasmtls"
	"github.com/jamesread/httpauthshim/providers/hastrustedheaders"
	"github.com/jamesread/httpauthshim/sessions"
	"github.com/sirupsen/logrus"
)

func (l *Layer) newAuthShim() (*japauth.AuthShimContext, error) {
	cfg, err := authpublic.ConfigFromMap(l.cfg.AuthYAML)
	if err != nil {
		return nil, err
	}
	if cfg.BaseDir == "" {
		cfg.BaseDir = filepath.Join(os.TempDir(), "armature-iam-httpauthshim-unused")
	}
	storage := sessions.NewSessionStorage(sessions.NewNopPersistence())
	shim, err := japauth.NewAuthShimContext(cfg, storage)
	if err != nil {
		return nil, err
	}
	shim.AddProvider(hascallback.BearerToken(l.lookupAPIKey))
	registerConfiguredProviders(shim, cfg, l.log)
	shim.AddProvider(hascallback.CookieSID(l.cfg.CookieName, l.lookupSession))
	return shim, nil
}

func registerConfiguredProviders(ctx *japauth.AuthShimContext, cfg *authpublic.Config, log *logrus.Logger) {
	registerJWT(ctx, cfg, log)
	if cfg.HttpHeader.Username != "" {
		ctx.AddProvider(hastrustedheaders.CheckUserFromHeaders)
		log.Infof("httpauthshim: trusted header authentication enabled (%s)", cfg.HttpHeader.Username)
	}
	if cfg.Mtls.Enabled {
		ctx.AddProvider(hasmtls.CheckUserFromMtls)
		log.Info("httpauthshim: mTLS authentication enabled")
	}
}

func registerJWT(ctx *japauth.AuthShimContext, cfg *authpublic.Config, log *logrus.Logger) {
	if !jwtConfigured(cfg) {
		return
	}
	if cfg.Jwt.Header != "" {
		ctx.AddProvider(hasjwt.CheckUserFromJwtHeader)
		log.Info("httpauthshim: JWT header authentication enabled")
	}
	if cfg.Jwt.CookieName != "" {
		ctx.AddProvider(hasjwt.CheckUserFromJwtCookie)
		log.Info("httpauthshim: JWT cookie authentication enabled")
	}
}

func jwtConfigured(cfg *authpublic.Config) bool {
	return cfg.Jwt.CertsURL != "" || cfg.Jwt.PubKeyPath != "" || cfg.Jwt.HmacSecret != ""
}

func (l *Layer) lookupAPIKey(ctx context.Context, token string) (string, bool) {
	user, _, err := l.Store.GetUserByAPIKey(ctx, token)
	if err != nil || user == nil {
		return "", false
	}
	return user.Username, true
}

func (l *Layer) lookupSession(ctx context.Context, sid string) (string, bool) {
	sess, err := l.Store.GetSessionBySID(ctx, sid)
	if err != nil || sess == nil {
		return "", false
	}
	user, err := l.Store.GetUserByID(ctx, sess.UserAccountID)
	if err != nil || user == nil {
		return "", false
	}
	return user.Username, true
}
