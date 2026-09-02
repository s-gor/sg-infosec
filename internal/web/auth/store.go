package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	ErrSetupUnavailable   = errors.New("setup is unavailable")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrRateLimited        = errors.New("authentication rate limited")
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,64}$`)

type adminRecord struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type setupRecord struct {
	Digest    string    `json:"digest"`
	ExpiresAt time.Time `json:"expires_at"`
}

type sessionRecord struct {
	Username   string    `json:"username"`
	CSRFDigest string    `json:"csrf_digest"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type failureRecord struct {
	Count         int       `json:"count"`
	WindowStarted time.Time `json:"window_started"`
	BlockedUntil  time.Time `json:"blocked_until,omitempty"`
}

type persistedState struct {
	Admin    *adminRecord             `json:"admin,omitempty"`
	Setup    *setupRecord             `json:"setup,omitempty"`
	Sessions map[string]sessionRecord `json:"sessions,omitempty"`
	Failures map[string]failureRecord `json:"failures,omitempty"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	now   func() time.Time
	state persistedState
}

func Open(path string, now func() time.Time) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("auth state path must be absolute")
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create auth state directory: %w", err)
	}
	store := &Store{path: path, now: now}
	store.state.Sessions = make(map[string]sessionRecord)
	store.state.Failures = make(map[string]failureRecord)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
		return nil, fmt.Errorf("read auth state: %w", err)
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("decode auth state: %w", err)
	}
	if store.state.Sessions == nil {
		store.state.Sessions = make(map[string]sessionRecord)
	}
	if store.state.Failures == nil {
		store.state.Failures = make(map[string]failureRecord)
	}
	return store, nil
}

func (s *Store) AdminConfigured() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Admin != nil
}

func (s *Store) AdminUsername() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Admin == nil {
		return ""
	}
	return s.state.Admin.Username
}

func (s *Store) SetupPending() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Admin == nil && s.state.Setup != nil && s.now().Before(s.state.Setup.ExpiresAt)
}

func (s *Store) IssueSetupCode(ttl time.Duration) (string, error) {
	if s == nil {
		return "", fmt.Errorf("auth store is nil")
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return "", fmt.Errorf("invalid setup code lifetime")
	}
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate setup code: %w", err)
	}
	hexCode := strings.ToUpper(hex.EncodeToString(raw))
	code := hexCode[0:4] + "-" + hexCode[4:8] + "-" + hexCode[8:12]

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Admin != nil {
		return "", ErrSetupUnavailable
	}
	s.state.Setup = &setupRecord{Digest: digestString(code), ExpiresAt: s.now().Add(ttl)}
	if err := s.persistLocked(); err != nil {
		return "", err
	}
	return code, nil
}

func (s *Store) ConsumeSetup(code, username, password string) error {
	if s == nil {
		return ErrSetupUnavailable
	}
	if err := validateUsername(username); err != nil {
		return err
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.state.Admin != nil || s.state.Setup == nil || !now.Before(s.state.Setup.ExpiresAt) {
		return ErrSetupUnavailable
	}
	actual := digestString(strings.TrimSpace(code))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(s.state.Setup.Digest)) != 1 {
		return ErrSetupUnavailable
	}
	s.state.Admin = &adminRecord{Username: username, PasswordHash: passwordHash}
	s.state.Setup = nil
	s.state.Sessions = make(map[string]sessionRecord)
	s.state.Failures = make(map[string]failureRecord)
	return s.persistLocked()
}

func (s *Store) ResetAdmin(username, password string) error {
	if s == nil {
		return fmt.Errorf("auth store is nil")
	}
	if err := validateUsername(username); err != nil {
		return err
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Admin = &adminRecord{Username: username, PasswordHash: passwordHash}
	s.state.Setup = nil
	s.state.Sessions = make(map[string]sessionRecord)
	s.state.Failures = make(map[string]failureRecord)
	return s.persistLocked()
}

func validateUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return fmt.Errorf("administrator username must be 3-64 characters using letters, digits, dot, dash, or underscore")
	}
	return nil
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (s *Store) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode auth state: %w", err)
	}
	data = append(data, '\n')
	parent := filepath.Dir(s.path)
	file, err := os.CreateTemp(parent, ".auth-state-*")
	if err != nil {
		return fmt.Errorf("create auth state temp file: %w", err)
	}
	tempPath := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(tempPath)
	}
	if err := file.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod auth state: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write auth state: %w", err)
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync auth state: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close auth state: %w", err)
	}
	if info, statErr := os.Stat(parent); statErr == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if err := os.Chown(tempPath, int(stat.Uid), int(stat.Gid)); err != nil && os.Geteuid() == 0 {
				_ = os.Remove(tempPath)
				return fmt.Errorf("set auth state ownership: %w", err)
			}
		}
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("replace auth state: %w", err)
	}
	if directory, err := os.Open(parent); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}
