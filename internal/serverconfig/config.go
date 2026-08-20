package serverconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
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
