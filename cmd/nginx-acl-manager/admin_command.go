package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"nginx-acl-manager/internal/auth"
)

func runAdmin(args []string) error {
	if len(args) == 0 {
		return errors.New("admin 命令缺少子命令")
	}

	switch args[0] {
	case "init", "reset", "set-username", "set-password":
		return updateAdministrator(args[0], args[1:])
	case "disable-2fa":
		return disableAdministratorTOTP(args[1:])
	default:
		return fmt.Errorf("未知 admin 子命令 %q", args[0])
	}
}

func updateAdministrator(action string, args []string) error {
	flags := flag.NewFlagSet("admin "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outputPath := flags.String("output", defaultCredentialsPath, "管理员凭据文件")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("admin 命令包含多余参数")
	}
	if err := requireAbsolutePath(*outputPath, "管理员凭据文件"); err != nil {
		return err
	}

	var current auth.Credentials
	if action == "init" {
		if _, err := os.Stat(*outputPath); err == nil {
			return errors.New("管理员凭据已经存在，不能重复初始化")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("检查管理员凭据: %w", err)
		}
	} else {
		loaded, err := auth.LoadCredentials(*outputPath)
		if err != nil {
			return err
		}
		current = loaded
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("打开交互终端: %w", err)
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)

	username := current.Username
	if action == "init" || action == "reset" || action == "set-username" {
		username, err = readTTYLine(tty, reader, "管理员用户名: ")
		if err != nil {
			return err
		}
	}

	passwordHash := current.PasswordHash
	if action == "init" || action == "reset" || action == "set-password" {
		password, readErr := readTTYPassword(tty, reader, "管理员密码（至少 6 个字符）: ")
		if readErr != nil {
			return readErr
		}
		confirmation, readErr := readTTYPassword(tty, reader, "再次输入管理员密码: ")
		if readErr != nil {
			return readErr
		}
		if password != confirmation {
			return errors.New("两次输入的管理员密码不一致")
		}
		passwordHash, err = auth.HashPassword(password)
		if err != nil {
			return err
		}
	}

	if err := auth.SaveCredentials(*outputPath, auth.Credentials{
		Username:     username,
		PasswordHash: passwordHash,
		TOTP:         current.TOTP,
	}); err != nil {
		return err
	}

	if action != "init" {
		if err := restartManagerService(); err != nil {
			return fmt.Errorf("凭据已更新，但重启服务失败: %w", err)
		}
	}
	return nil
}

func disableAdministratorTOTP(args []string) error {
	flags := flag.NewFlagSet("admin disable-2fa", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outputPath := flags.String("output", defaultCredentialsPath, "管理员凭据文件")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("admin disable-2fa 命令包含多余参数")
	}
	if err := requireAbsolutePath(*outputPath, "管理员凭据文件"); err != nil {
		return err
	}
	credentials, err := auth.LoadCredentials(*outputPath)
	if err != nil {
		return err
	}
	if credentials.TOTP == nil {
		return nil
	}
	credentials.TOTP = nil
	if err := auth.SaveCredentials(*outputPath, credentials); err != nil {
		return err
	}
	if err := restartManagerService(); err != nil {
		return fmt.Errorf("双因素认证已停用，但重启服务失败: %w", err)
	}
	return nil
}

func readTTYLine(tty *os.File, reader *bufio.Reader, prompt string) (string, error) {
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", fmt.Errorf("输出交互提示: %w", err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("读取交互输入: %w", err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func readTTYPassword(tty *os.File, reader *bufio.Reader, prompt string) (string, error) {
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", fmt.Errorf("输出密码提示: %w", err)
	}
	if err := setTerminalEcho(tty, false); err != nil {
		return "", err
	}
	defer func() {
		_ = setTerminalEcho(tty, true)
	}()

	line, err := reader.ReadString('\n')
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return "", fmt.Errorf("读取管理员密码: %w", err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func setTerminalEcho(tty *os.File, enabled bool) error {
	argument := "-echo"
	if enabled {
		argument = "echo"
	}
	command := exec.Command("stty", argument)
	command.Stdin = tty
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("切换终端密码回显: %w", err)
	}
	return nil
}

func requireAbsolutePath(path, label string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s必须是规范化绝对路径", label)
	}
	return nil
}
