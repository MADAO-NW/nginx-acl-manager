package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

type session struct {
	csrfToken     string
	createdAt     time.Time
	lastSeen      time.Time
	authenticated bool
}

// SessionStore 保存单进程内存 Session，并同时执行空闲和绝对过期。
type SessionStore struct {
	mu              sync.Mutex
	sessions        map[string]session
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	now             func() time.Time
	random          io.Reader
}

// NewSessionStore 创建进程内 Session 仓储。
func NewSessionStore(idleTimeout, absoluteTimeout time.Duration) (*SessionStore, error) {
	if idleTimeout <= 0 || absoluteTimeout <= 0 {
		return nil, errors.New("Session 过期时间必须大于 0")
	}
	if idleTimeout > absoluteTimeout {
		return nil, errors.New("Session 空闲过期不能长于绝对过期")
	}
	return &SessionStore{
		sessions:        make(map[string]session),
		idleTimeout:     idleTimeout,
		absoluteTimeout: absoluteTimeout,
		now:             time.Now,
		random:          rand.Reader,
	}, nil
}

// Create 在登录成功后生成新的 Session ID 和 CSRF token。
func (s *SessionStore) Create() (string, string, error) {
	return s.create(true)
}

// CreatePending 创建只允许继续完成 TOTP 的临时登录 Session。
func (s *SessionStore) CreatePending() (string, string, error) {
	return s.create(false)
}

func (s *SessionStore) create(authenticated bool) (string, string, error) {
	csrfToken, err := randomToken(s.random)
	if err != nil {
		return "", "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		sessionID, err := randomToken(s.random)
		if err != nil {
			return "", "", err
		}
		if _, exists := s.sessions[sessionID]; exists {
			continue
		}
		now := s.now()
		s.sessions[sessionID] = session{
			csrfToken:     csrfToken,
			createdAt:     now,
			lastSeen:      now,
			authenticated: authenticated,
		}
		return sessionID, csrfToken, nil
	}
}

// Get 校验 Session 并刷新最后访问时间。
func (s *SessionStore) Get(sessionID string) (string, bool) {
	return s.get(sessionID, true)
}

// GetPending 校验并刷新临时登录 Session。
func (s *SessionStore) GetPending(sessionID string) (string, bool) {
	return s.get(sessionID, false)
}

func (s *SessionStore) get(sessionID string, authenticated bool) (string, bool) {
	if sessionID == "" {
		return "", false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.sessions[sessionID]
	if !exists || current.authenticated != authenticated {
		return "", false
	}

	now := s.now()
	if now.Sub(current.lastSeen) >= s.idleTimeout || now.Sub(current.createdAt) >= s.absoluteTimeout {
		delete(s.sessions, sessionID)
		return "", false
	}
	current.lastSeen = now
	s.sessions[sessionID] = current
	return current.csrfToken, true
}

// PromotePending 消费临时 Session，并轮换为新的正式 Session。
func (s *SessionStore) PromotePending(sessionID string) (string, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.sessions[sessionID]
	if !exists || current.authenticated {
		return "", "", false, nil
	}
	now := s.now()
	if now.Sub(current.lastSeen) >= s.idleTimeout || now.Sub(current.createdAt) >= s.absoluteTimeout {
		delete(s.sessions, sessionID)
		return "", "", false, nil
	}
	csrfToken, err := randomToken(s.random)
	if err != nil {
		return "", "", false, err
	}
	for {
		newSessionID, err := randomToken(s.random)
		if err != nil {
			return "", "", false, err
		}
		if _, exists := s.sessions[newSessionID]; exists {
			continue
		}
		delete(s.sessions, sessionID)
		s.sessions[newSessionID] = session{
			csrfToken:     csrfToken,
			createdAt:     now,
			lastSeen:      now,
			authenticated: true,
		}
		return newSessionID, csrfToken, true, nil
	}
}

// Delete 使指定 Session 立即失效。
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// DeleteAll 使单管理员的全部正式和临时 Session 立即失效。
func (s *SessionStore) DeleteAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]session)
}

func randomToken(source io.Reader) (string, error) {
	data := make([]byte, 32)
	if _, err := io.ReadFull(source, data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
