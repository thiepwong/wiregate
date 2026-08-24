// File: src/internal/web/auth/manager.go
// Project: WireGate
// Author: Thiep Wong
// Email: thiep.wong@gmail.com
// Date: 2026-08-24
// Description: WireGate source code.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/wiregate-project/wiregate/internal/web/repository"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)

const CookieName = "__Host-wiregate_session"

var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrForbidden       = errors.New("permission denied")
	ErrInvalidLogin    = errors.New("invalid credentials")
	dummyPasswordHash  = func() string {
		hash, _ := HashPassword("wiregate constant-time dummy password")
		return hash
	}()
)

type Principal struct {
	UserID      string
	Username    string
	DisplayName string
	Role        string
	SessionHash []byte
	CSRFHash    []byte
	ReauthUntil time.Time
}

type Tokens struct {
	Session string
	CSRF    string
}

type Manager struct {
	repository *repository.Repository
	now        func() time.Time
}

func NewManager(repository *repository.Repository) (*Manager, error) {
	if repository == nil {
		return nil, errors.New("auth repository is required")
	}
	return &Manager{
		repository: repository,
		now:        func() time.Time { return time.Now().UTC() },
	}, nil
}

func (m *Manager) BootstrapRequired(ctx context.Context) (bool, error) {
	return m.repository.BootstrapRequired(ctx)
}

func (m *Manager) Bootstrap(
	ctx context.Context,
	token, username, displayName, password, requestID string,
) (repository.User, error) {
	if strings.TrimSpace(token) == "" || requestID == "" {
		return repository.User{}, ErrForbidden
	}
	username = strings.TrimSpace(username)
	displayName = strings.TrimSpace(displayName)
	if !usernamePattern.MatchString(username) || displayName == "" || len(displayName) > 128 {
		return repository.User{}, errors.New("invalid username or display name")
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return repository.User{}, err
	}
	return m.repository.BootstrapAdmin(
		ctx, tokenHash(token), username,
		displayName, passwordHash, requestID, m.now(),
	)
}

func (m *Manager) Login(
	ctx context.Context,
	username, password, requestID, sourceIP string,
) (repository.User, Tokens, error) {
	user, err := m.repository.FindUserByUsername(ctx, strings.TrimSpace(username))
	if len(username) > 128 {
		err = errors.New("username too long")
	}
	hash := dummyPasswordHash
	if err == nil {
		hash = user.PasswordHash
	}
	passwordValid := VerifyPassword(hash, password)
	valid := err == nil && passwordValid && user.Status == "active" &&
		(user.LockedUntil.IsZero() || !user.LockedUntil.After(m.now()))
	if !valid {
		_ = m.repository.RecordLoginFailure(ctx, strings.TrimSpace(username), requestID, sourceIP, m.now())
		return repository.User{}, Tokens{}, ErrInvalidLogin
	}
	rawSession, sessionHash, err := randomToken()
	if err != nil {
		return repository.User{}, Tokens{}, err
	}
	rawCSRF, csrfHash, err := randomToken()
	if err != nil {
		return repository.User{}, Tokens{}, err
	}
	now := m.now()
	if err := m.repository.CreateSession(
		ctx, user.ID, sessionHash, csrfHash,
		now.Add(12*time.Hour), now.Add(30*time.Minute), now,
	); err != nil {
		return repository.User{}, Tokens{}, err
	}
	_ = m.repository.RecordLoginSuccess(ctx, user.ID, user.Username, requestID, sourceIP, now)
	return user, Tokens{Session: rawSession, CSRF: rawCSRF}, nil
}

func (m *Manager) Authenticate(ctx context.Context, request *http.Request) (Principal, error) {
	cookie, err := request.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		return Principal{}, ErrUnauthenticated
	}
	hash := tokenHash(cookie.Value)
	session, err := m.repository.GetSession(ctx, hash, m.now())
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{
		UserID: session.User.ID, Username: session.User.Username,
		DisplayName: session.User.DisplayName, Role: session.User.Role,
		SessionHash: hash, CSRFHash: session.CSRFHash,
		ReauthUntil: session.ReauthUntil,
	}, nil
}

func (m *Manager) Reauthenticate(ctx context.Context, principal Principal, password string) (time.Time, error) {
	session, err := m.repository.GetSession(ctx, principal.SessionHash, m.now())
	if err != nil || !VerifyPassword(session.User.PasswordHash, password) {
		return time.Time{}, ErrInvalidLogin
	}
	until := m.now().Add(5 * time.Minute)
	if err := m.repository.MarkReauthenticated(ctx, principal.SessionHash, until); err != nil {
		return time.Time{}, err
	}
	return until, nil
}

func (m *Manager) RequireRecentReauth(principal Principal) error {
	if principal.ReauthUntil.IsZero() || !principal.ReauthUntil.After(m.now()) {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) ChangePassword(
	ctx context.Context,
	principal Principal,
	currentPassword, newPassword string,
) error {
	session, err := m.repository.GetSession(ctx, principal.SessionHash, m.now())
	if err != nil || !VerifyPassword(session.User.PasswordHash, currentPassword) {
		return ErrInvalidLogin
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	return m.repository.ChangePassword(ctx, principal.UserID, principal.SessionHash, hash, m.now())
}

func (m *Manager) Require(
	ctx context.Context,
	request *http.Request,
	permission string,
	mutation bool,
) (Principal, error) {
	principal, err := m.Authenticate(ctx, request)
	if err != nil {
		return Principal{}, err
	}
	if !Allowed(principal.Role, permission) {
		return Principal{}, ErrForbidden
	}
	if mutation {
		csrf := request.Header.Get("X-CSRF-Token")
		if csrf == "" || subtle.ConstantTimeCompare(tokenHash(csrf), principal.CSRFHash) != 1 {
			return Principal{}, ErrForbidden
		}
		if !sameOrigin(request) {
			return Principal{}, ErrForbidden
		}
	}
	return principal, nil
}

func (m *Manager) Logout(ctx context.Context, principal Principal) error {
	return m.repository.RevokeSession(ctx, principal.SessionHash, m.now())
}

func SetSessionCookie(w http.ResponseWriter, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: value, Path: "/", Expires: expires,
		MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true,
		Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func Allowed(role, permission string) bool {
	permissions := map[string]map[string]bool{
		"admin": {
			"interface:view": true, "interface:adopt": true,
			"interface:create": true, "interface:manage": true,
			"client:view": true, "client:manage": true, "client:export-secret": true,
			"diagnostic:view": true, "operation:view": true, "audit:view": true,
		},
		"operator": {
			"interface:view": true, "client:view": true, "client:manage": true,
			"client:export-secret": true,
			"diagnostic:view":      true, "operation:view": true, "audit:view": true,
		},
		"viewer": {
			"interface:view": true, "client:view": true, "diagnostic:view": true,
		},
		"auditor": {
			"interface:view": true, "client:view": true,
			"diagnostic:view": true, "operation:view": true, "audit:view": true,
		},
	}
	return permissions[role][permission]
}

func randomToken() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return encoded, tokenHash(encoded), nil
}

func NewBootstrapToken() (string, []byte, error) {
	return randomToken()
}

func ValidOrigin(request *http.Request) bool {
	return sameOrigin(request)
}

func tokenHash(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func sameOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		return false
	}
	expectedScheme := "https"
	if request.TLS == nil {
		// A reverse proxy may terminate TLS, but forwarded headers are not
		// trusted by default. Operators should preserve the original Host and
		// use HTTPS between proxy and web for mutations.
		expectedScheme = "http"
	}
	return origin == expectedScheme+"://"+request.Host
}
