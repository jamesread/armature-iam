package layer

import "net/http"

func (l *Layer) NewSessionCookie(sid string) http.Cookie {
	return http.Cookie{
		Name:     l.cfg.CookieName,
		Value:    sid,
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		Secure:   l.cfg.SecureCookies,
	}
}

func (l *Layer) ClearSessionCookie() http.Cookie {
	c := l.NewSessionCookie("")
	c.MaxAge = -1
	return c
}

func (l *Layer) CookieName() string {
	return l.cfg.CookieName
}

func (l *Layer) SecureCookiesEnabled() bool {
	return l.cfg.SecureCookies
}
