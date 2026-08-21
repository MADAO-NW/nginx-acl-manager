package auth

import "sync"

// Manager 为登录请求提供可原子重载的单管理员认证视图。
type Manager struct {
	mu       sync.RWMutex
	verifier *Verifier
}

// LoadManager 从正式认证文件创建管理器。
func LoadManager(path string) (*Manager, error) {
	verifier, err := LoadVerifier(path)
	if err != nil {
		return nil, err
	}
	return &Manager{verifier: verifier}, nil
}

// Reload 在认证文件由可信边界更新后原子替换内存校验器。
func (m *Manager) Reload(path string) error {
	verifier, err := LoadVerifier(path)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifier = verifier
	return nil
}

// Verify 校验当前用户名和密码。
func (m *Manager) Verify(username, password string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.verifier.Verify(username, password)
}

// Username 返回当前管理员用户名。
func (m *Manager) Username() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.verifier.Username()
}

// TOTPSecret 返回当前已启用的 TOTP 密钥。
func (m *Manager) TOTPSecret() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.verifier.TOTPSecret()
}

// Fingerprint 返回当前正式凭据摘要。
func (m *Manager) Fingerprint() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.verifier.Fingerprint()
}
