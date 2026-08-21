package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"

	"nginx-acl-manager/internal/auth"
)

func runAuth(args []string) error {
	if len(args) != 1 || args[0] != "apply-candidate" {
		return errors.New("auth 命令只支持 apply-candidate")
	}
	if os.Geteuid() != 0 {
		return errors.New("auth apply-candidate 必须由 root oneshot 执行")
	}
	previous, err := auth.ApplyCandidate(defaultCredentialsPath, defaultAuthCandidatePath, defaultTOTPStatePath)
	if err != nil {
		return err
	}
	if err := setTOTPStateOwner(); err != nil {
		_ = auth.SaveCredentials(defaultCredentialsPath, previous)
		return err
	}
	command := exec.Command(defaultSystemctlPath, "--no-block", "restart", serviceName)
	if err := command.Run(); err != nil {
		if rollbackErr := auth.SaveCredentials(defaultCredentialsPath, previous); rollbackErr != nil {
			return fmt.Errorf("调度管理服务重启失败且旧凭据恢复失败: %v; %w", rollbackErr, err)
		}
		return fmt.Errorf("调度管理服务重启失败，已恢复旧凭据: %w", err)
	}
	return nil
}

func setTOTPStateOwner() error {
	if _, err := os.Stat(defaultTOTPStatePath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("检查 TOTP 状态文件: %w", err)
	}
	account, err := user.Lookup("nginx-acl-manager")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(defaultTOTPStatePath, uid, gid); err != nil {
		return fmt.Errorf("设置 TOTP 状态所有者: %w", err)
	}
	return nil
}
