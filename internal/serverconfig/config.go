package serverconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

const (
	// ListenAddress 是管理页面固定绑定的回环地址。
	ListenAddress = "127.0.0.1"
	// DefaultPort 是未覆盖安装端口时使用的固定值。
	DefaultPort = 7582
)

// Config 保存管理服务实际需要的本机监听配置。
type Config struct {
	ListenPort int `json:"listenPort"`
}

// Default 返回默认管理服务配置。
func Default() Config {
	return Config{ListenPort: DefaultPort}
}

// Load 严格读取监听配置。
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("读取服务配置: %w", err)
	}

	var config Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("解析服务配置: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("服务配置只能包含一个 JSON 对象")
		}
		return Config{}, fmt.Errorf("解析服务配置尾部内容: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Save 校验配置并在目标目录内原子替换配置文件。
func Save(path string, config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if path == "" {
		return errors.New("服务配置路径不能为空")
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化服务配置: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	mode := os.FileMode(0o640)
	ownerUID, ownerGID := -1, -1
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			ownerUID = int(stat.Uid)
			ownerGID = int(stat.Gid)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("检查现有服务配置: %w", statErr)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("创建服务配置临时文件: %w", err)
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
		return fmt.Errorf("设置服务配置权限: %w", err)
	}
	if ownerUID >= 0 && ownerGID >= 0 {
		if err := tmp.Chown(ownerUID, ownerGID); err != nil {
			return fmt.Errorf("保留服务配置所有者: %w", err)
		}
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("写入服务配置: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("同步服务配置: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭服务配置: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("替换服务配置: %w", err)
	}
	committed = true

	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("打开服务配置目录: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("同步服务配置目录: %w", err)
	}
	return nil
}

// Validate 校验 TCP 端口范围。
func (c Config) Validate() error {
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return errors.New("监听端口必须在 1 到 65535 之间")
	}
	return nil
}

// ListenAddressWithPort 返回 net/http 使用的固定回环监听地址。
func (c Config) ListenAddressWithPort() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return net.JoinHostPort(ListenAddress, strconv.Itoa(c.ListenPort)), nil
}
