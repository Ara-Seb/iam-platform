package session

import (
	"net/http"
	"os"

	"github.com/gorilla/securecookie"
)

type SessionStore struct {
	sc *securecookie.SecureCookie
}

type AuthorizationSession struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Scope       string `json:"scope"`
	State       string `json:"state"`
}

const sessionCookieName = "auth_session"

func NewSessionStore(hashKey, blockKey []byte) *SessionStore {
	return &SessionStore{
		sc: securecookie.New(hashKey, blockKey),
	}
}

func (s *SessionStore) Set(w http.ResponseWriter, session *AuthorizationSession) error {
	encoded, err := s.sc.Encode(sessionCookieName, session)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    encoded,
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
		Path:     "/",
	})
	return nil
}

func (s *SessionStore) Get(r *http.Request) (*AuthorizationSession, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	session := &AuthorizationSession{}
	err = s.sc.Decode(sessionCookieName, cookie.Value, session)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (s *SessionStore) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "auth_session",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})
}
