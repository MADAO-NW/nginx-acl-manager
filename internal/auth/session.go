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
	csrfToken string
	createdAt time.Time
	lastSeen  time.Time
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
			csrfToken: csrfToken,
			createdAt: now,
			lastSeen:  now,
		}
		return sessionID, csrfToken, nil
	}
}

// Get 校验 Session 并刷新最后访问时间。
func (s *SessionStore) Get(sessionID string) (string, bool) {
	if sessionID == "" {
		return "", false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.sessions[sessionID]
	if !exists {
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

// Delete 使指定 Session 立即失效。
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

func randomToken(source io.Reader) (string, error) {
	data := make([]byte, 32)
	if _, err := io.ReadFull(source, data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
