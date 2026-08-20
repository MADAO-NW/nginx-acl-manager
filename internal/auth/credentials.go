package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory          uint32 = 19456
	argonIterations      uint32 = 2
	argonParallelism     uint8  = 1
	argonSaltLength             = 16
	argonKeyLength              = 32
	minimumPasswordRunes        = 15
)

// Credentials 是 root 所有认证文件中的单管理员数据。
type Credentials struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}

// Verifier 在服务启动时完成凭据格式校验，登录时只执行固定参数比较。
type Verifier struct {
	usernameDigest [sha256.Size]byte
	salt           []byte
	expected       []byte
}

// HashPassword 使用固定 Argon2id 参数生成包含算法元数据的 PHC 字符串。
func HashPassword(password string) (string, error) {
	if !utf8.ValidString(password) {
		return "", errors.New("密码必须是有效 UTF-8 文本")
	}
	if utf8.RuneCountInString(password) < minimumPasswordRunes {
		return "", fmt.Errorf("密码至少需要 %d 个字符", minimumPasswordRunes)
	}

	salt := make([]byte, argonSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("生成密码盐值: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// LoadCredentials 严格读取认证 JSON，不接受兼容字段或尾随对象。
func LoadCredentials(path string) (Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}, fmt.Errorf("读取管理员凭据: %w", err)
	}

	var credentials Credentials
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return Credentials{}, fmt.Errorf("解析管理员凭据: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Credentials{}, errors.New("管理员凭据只能包含一个 JSON 对象")
		}
		return Credentials{}, fmt.Errorf("解析管理员凭据尾部内容: %w", err)
	}
	if err := validateUsername(credentials.Username); err != nil {
		return Credentials{}, err
	}
	if _, _, err := parsePasswordHash(credentials.PasswordHash); err != nil {
		return Credentials{}, err
	}
	return credentials, nil
}

// LoadVerifier 从固定认证文件加载可直接注入 Web 服务的验证器。
func LoadVerifier(path string) (*Verifier, error) {
	credentials, err := LoadCredentials(path)
	if err != nil {
		return nil, err
	}
	return NewVerifier(credentials)
}

// NewVerifier 校验凭据后创建登录验证器。
func NewVerifier(credentials Credentials) (*Verifier, error) {
	if err := validateUsername(credentials.Username); err != nil {
		return nil, err
	}
	salt, expected, err := parsePasswordHash(credentials.PasswordHash)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		usernameDigest: sha256.Sum256([]byte(credentials.Username)),
		salt:           salt,
		expected:       expected,
	}, nil
}

// Verify 对用户名和密码执行统一校验，不区分失败原因。
func (v *Verifier) Verify(username, password string) bool {
	usernameDigest := sha256.Sum256([]byte(username))
	usernameMatches := subtle.ConstantTimeCompare(usernameDigest[:], v.usernameDigest[:])
	actual := argon2.IDKey([]byte(password), v.salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	passwordMatches := subtle.ConstantTimeCompare(actual, v.expected)
	return usernameMatches&passwordMatches == 1
}

func validateUsername(username string) error {
	if username == "" {
		return errors.New("管理员用户名不能为空")
	}
	if !utf8.ValidString(username) {
		return errors.New("管理员用户名必须是有效 UTF-8 文本")
	}
	if strings.ContainsAny(username, "\x00\r\n") {
		return errors.New("管理员用户名不能包含换行或空字符")
	}
	return nil
}

func parsePasswordHash(encoded string) ([]byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, errors.New("管理员密码哈希格式无效")
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return nil, nil, errors.New("管理员密码哈希版本不受支持")
	}

	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 ||
		parameters[0] != "m="+strconv.FormatUint(uint64(argonMemory), 10) ||
		parameters[1] != "t="+strconv.FormatUint(uint64(argonIterations), 10) ||
		parameters[2] != "p="+strconv.FormatUint(uint64(argonParallelism), 10) {
		return nil, nil, errors.New("管理员密码哈希参数不受支持")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltLength {
		return nil, nil, errors.New("管理员密码哈希盐值无效")
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(expected) != argonKeyLength {
		return nil, nil, errors.New("管理员密码哈希摘要无效")
	}
	return salt, expected, nil
}
