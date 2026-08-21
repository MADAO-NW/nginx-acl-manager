package auth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// CandidateChangePassword 表示只替换管理员密码哈希。
	CandidateChangePassword = "change_password"
	// CandidateEnableTOTP 表示为管理员启用已经校验过的 TOTP 密钥。
	CandidateEnableTOTP = "enable_totp"
	// CandidateDisableTOTP 表示移除管理员 TOTP 密钥。
	CandidateDisableTOTP = "disable_totp"
)

// Candidate 是 Web 写入、root 重新校验的认证变更候选。
type Candidate struct {
	Action              string `json:"action"`
	ExpectedFingerprint string `json:"expectedFingerprint"`
	PasswordHash        string `json:"passwordHash,omitempty"`
	TOTPSecret          string `json:"totpSecret,omitempty"`
	TOTPInitialStep     int64  `json:"totpInitialStep,omitempty"`
}

// SaveCandidate 严格校验并原子保存认证变更候选。
func SaveCandidate(path string, candidate Candidate) error {
	if err := ValidateCandidate(candidate); err != nil {
		return err
	}
	data, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化认证候选: %w", err)
	}
	data = append(data, '\n')
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("创建认证候选目录: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".auth-candidate-*.tmp")
	if err != nil {
		return fmt.Errorf("创建认证候选临时文件: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("设置认证候选权限: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("写入认证候选: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("同步认证候选: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("关闭认证候选: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("替换认证候选: %w", err)
	}
	committed = true
	return nil
}

// LoadCandidate 严格读取认证变更候选。
func LoadCandidate(path string) (Candidate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Candidate{}, fmt.Errorf("读取认证候选: %w", err)
	}
	var candidate Candidate
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&candidate); err != nil {
		return Candidate{}, fmt.Errorf("解析认证候选: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Candidate{}, errors.New("认证候选只能包含一个 JSON 对象")
		}
		return Candidate{}, fmt.Errorf("解析认证候选尾部内容: %w", err)
	}
	if err := ValidateCandidate(candidate); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

// ValidateCandidate 校验认证变更动作和字段组合。
func ValidateCandidate(candidate Candidate) error {
	fingerprint, err := hex.DecodeString(candidate.ExpectedFingerprint)
	if err != nil || len(fingerprint) != 32 {
		return errors.New("认证候选凭据摘要无效")
	}
	switch candidate.Action {
	case CandidateChangePassword:
		if candidate.TOTPSecret != "" || candidate.TOTPInitialStep != 0 {
			return errors.New("修改密码候选不能携带 TOTP 密钥")
		}
		if _, _, err := parsePasswordHash(candidate.PasswordHash); err != nil {
			return err
		}
	case CandidateEnableTOTP:
		if candidate.PasswordHash != "" {
			return errors.New("启用 TOTP 候选不能携带密码哈希")
		}
		if _, err := decodeTOTPSecret(candidate.TOTPSecret); err != nil {
			return err
		}
		if candidate.TOTPInitialStep <= 0 {
			return errors.New("启用 TOTP 候选缺少已确认时间步")
		}
	case CandidateDisableTOTP:
		if candidate.PasswordHash != "" || candidate.TOTPSecret != "" || candidate.TOTPInitialStep != 0 {
			return errors.New("停用 TOTP 候选不能携带认证字段")
		}
	default:
		return errors.New("认证候选动作无效")
	}
	return nil
}

// ApplyCandidate 以正式凭据摘要为并发边界，原子应用一个认证候选。
func ApplyCandidate(credentialsPath, candidatePath, totpStatePath string) (Credentials, error) {
	current, err := LoadCredentials(credentialsPath)
	if err != nil {
		return Credentials{}, err
	}
	candidate, err := LoadCandidate(candidatePath)
	if err != nil {
		return Credentials{}, err
	}
	fingerprint, err := CredentialsFingerprint(current)
	if err != nil {
		return Credentials{}, err
	}
	if fingerprint != candidate.ExpectedFingerprint {
		return Credentials{}, errors.New("正式管理员凭据已变化，请重新提交")
	}

	updated := current
	switch candidate.Action {
	case CandidateChangePassword:
		updated.PasswordHash = candidate.PasswordHash
	case CandidateEnableTOTP:
		if current.TOTP != nil {
			return Credentials{}, errors.New("TOTP 已经启用")
		}
		updated.TOTP = &TOTPConfig{Secret: candidate.TOTPSecret}
	case CandidateDisableTOTP:
		if current.TOTP == nil {
			return Credentials{}, errors.New("TOTP 尚未启用")
		}
		updated.TOTP = nil
	}
	if err := SaveCredentials(credentialsPath, updated); err != nil {
		return Credentials{}, err
	}
	if candidate.Action == CandidateEnableTOTP {
		if err := saveTOTPState(totpStatePath, totpState{LastAcceptedStep: candidate.TOTPInitialStep}); err != nil {
			_ = SaveCredentials(credentialsPath, current)
			return Credentials{}, fmt.Errorf("初始化 TOTP 防重放状态: %w", err)
		}
	} else if candidate.Action == CandidateDisableTOTP {
		if err := os.Remove(totpStatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = SaveCredentials(credentialsPath, current)
			return Credentials{}, fmt.Errorf("重置 TOTP 防重放状态: %w", err)
		}
	}
	// 正式凭据和防重放状态已经提交后，候选清理失败不能回滚到不一致状态；
	// 残留候选受正式凭据摘要保护，下一次提交会将其原子覆盖。
	_ = os.Remove(candidatePath)
	return current, nil
}
