package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

const (
	loginFailureWindow = 10 * time.Minute
	loginBlockDuration = 5 * time.Minute
	loginFailureLimit  = 5
)

type Session struct {
	Username  string
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

func (s *Store) Authenticate(username, password, remoteKey string) error {
	if s == nil {
		return ErrInvalidCredentials
	}
	remoteKey = strings.TrimSpace(remoteKey)
	if remoteKey == "" {
		remoteKey = "unknown"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	failure := s.state.Failures[remoteKey]
	if failure.BlockedUntil.After(now) {
		return ErrRateLimited
	}
	if failure.WindowStarted.IsZero() || now.Sub(failure.WindowStarted) >= loginFailureWindow {
		failure = failureRecord{WindowStarted: now}
	}

	valid := false
	if s.state.Admin != nil {
		usernameOK := subtle.ConstantTimeCompare([]byte(username), []byte(s.state.Admin.Username)) == 1
		passwordOK := VerifyPassword(s.state.Admin.PasswordHash, password)
		valid = usernameOK && passwordOK
	}
	if !valid {
		failure.Count++
		if failure.Count >= loginFailureLimit {
			failure.BlockedUntil = now.Add(loginBlockDuration)
			s.state.Failures[remoteKey] = failure
			if err := s.persistLocked(); err != nil {
				return err
			}
			return ErrRateLimited
		}
		s.state.Failures[remoteKey] = failure
		if err := s.persistLocked(); err != nil {
			return err
		}
		return ErrInvalidCredentials
	}

	if _, exists := s.state.Failures[remoteKey]; exists {
		delete(s.state.Failures, remoteKey)
		if err := s.persistLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) NewSession(username string, ttl time.Duration) (Session, error) {
	if s == nil {
		return Session{}, fmt.Errorf("auth store is nil")
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return Session{}, fmt.Errorf("invalid session lifetime")
	}
	token, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Admin == nil || username != s.state.Admin.Username {
		return Session{}, ErrInvalidCredentials
	}
	expiresAt := s.now().Add(ttl)
	s.state.Sessions[digestString(token)] = sessionRecord{
		Username:   username,
		CSRFDigest: digestString(csrf),
		ExpiresAt:  expiresAt,
	}
	if err := s.persistLocked(); err != nil {
		return Session{}, err
	}
	return Session{Username: username, Token: token, CSRFToken: csrf, ExpiresAt: expiresAt}, nil
}

func (s *Store) Session(token string) (Session, bool) {
	if s == nil || strings.TrimSpace(token) == "" {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := digestString(token)
	record, ok := s.state.Sessions[key]
	if !ok {
		return Session{}, false
	}
	if !s.now().Before(record.ExpiresAt) {
		delete(s.state.Sessions, key)
		_ = s.persistLocked()
		return Session{}, false
	}
	return Session{Username: record.Username, Token: token, ExpiresAt: record.ExpiresAt}, true
}

func (s *Store) ValidateCSRF(token, csrf string) bool {
	if s == nil || token == "" || csrf == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := digestString(token)
	record, ok := s.state.Sessions[key]
	if !ok || !s.now().Before(record.ExpiresAt) {
		if ok {
			delete(s.state.Sessions, key)
			_ = s.persistLocked()
		}
		return false
	}
	actual := digestString(csrf)
	return subtle.ConstantTimeCompare([]byte(actual), []byte(record.CSRFDigest)) == 1
}

func (s *Store) DeleteSession(token string) error {
	if s == nil || token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := digestString(token)
	if _, ok := s.state.Sessions[key]; !ok {
		return nil
	}
	delete(s.state.Sessions, key)
	return s.persistLocked()
}

func randomToken(size int) (string, error) {
	if size < 16 {
		return "", fmt.Errorf("token size is too small")
	}
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
