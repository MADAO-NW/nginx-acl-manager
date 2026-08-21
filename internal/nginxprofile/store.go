package nginxprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ErrNotFound 表示候选或正式 Profile 尚未创建。
var ErrNotFound = errors.New("Nginx Profile 不存在")

// Store 分离保存 Web 可写候选 Profile 和 root 所有的正式 Profile。
type Store struct {
	CandidatePath string
	ActivePath    string
}

// LoadCandidate 读取候选 Profile。
func (s Store) LoadCandidate() (Profile, error) {
	return load(s.CandidatePath)
}

// LoadActive 只读正式 Profile。
func (s Store) LoadActive() (Profile, error) {
	return load(s.ActivePath)
}

// SaveCandidate 对候选 Profile 复验后执行同目录原子替换。
func (s Store) SaveCandidate(profile Profile) error {
	if err := ValidateCandidate(profile); err != nil {
		return err
	}
	if s.CandidatePath == "" {
		return errors.New("候选 Profile 路径未配置")
	}

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化候选 Profile: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.CandidatePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("创建候选 Profile 目录: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".nginx-profile-*.tmp")
	if err != nil {
		return fmt.Errorf("创建候选 Profile 临时文件: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("设置候选 Profile 权限: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("写入候选 Profile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("同步候选 Profile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭候选 Profile: %w", err)
	}
	if err := os.Rename(tmpPath, s.CandidatePath); err != nil {
		return fmt.Errorf("替换候选 Profile: %w", err)
	}
	committed = true

	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("打开候选 Profile 目录: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("同步候选 Profile 目录: %w", err)
	}
	return nil
}

// SaveActive 由 root apply 在全部校验和 reload 成功后原子替换正式 Profile。
func (s Store) SaveActive(profile Profile) error {
	if err := ValidateCandidate(profile); err != nil {
		return err
	}
	if s.ActivePath == "" {
		return errors.New("正式 Profile 路径未配置")
	}
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化正式 Profile: %w", err)
	}
	data = append(data, '\n')
	return writeAtomic(s.ActivePath, data, 0o640)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("创建 Profile 目录: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".nginx-profile-*.tmp")
	if err != nil {
		return fmt.Errorf("创建 Profile 临时文件: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if directoryInfo, statErr := os.Stat(dir); statErr == nil {
		if stat, ok := directoryInfo.Sys().(*syscall.Stat_t); ok {
			if err := tmp.Chown(-1, int(stat.Gid)); err != nil {
				return fmt.Errorf("设置正式 Profile 文件组: %w", err)
			}
		}
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func load(path string) (Profile, error) {
	if path == "" {
		return Profile{}, ErrNotFound
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, fmt.Errorf("读取 Nginx Profile: %w", err)
	}

	var profile Profile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("解析 Nginx Profile: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Profile{}, err
	}
	if err := ValidateCandidate(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("解析 Nginx Profile 尾部内容: %w", err)
	}
	return errors.New("Nginx Profile 只能包含一个 JSON 对象")
}
