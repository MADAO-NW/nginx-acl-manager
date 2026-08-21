package main

import (
	"errors"
	"fmt"
	"os"
)

const (
	defaultConfigPath           = "/etc/nginx-acl-manager/config.json"
	defaultCredentialsPath      = "/etc/nginx-acl-manager/auth.json"
	defaultCandidateProfilePath = "/var/lib/nginx-acl-manager/staging/nginx-profile-candidate.json"
	defaultActiveProfilePath    = "/etc/nginx-acl-manager/nginx-profile.json"
	defaultDraftDirectory       = "/var/lib/nginx-acl-manager/drafts/projects"
	defaultPublishCandidatePath = "/var/lib/nginx-acl-manager/staging/candidate.json"
	defaultAccessControlRoot    = "/etc/nginx/access-control"
	defaultTransactionPath      = "/etc/nginx/access-control/.publish-transaction.json"
	defaultPublishResultPath    = "/var/lib/nginx-acl-manager/results/publish.json"
	defaultProfileResultPath    = "/var/lib/nginx-acl-manager/results/profile-apply.json"
	defaultPublishLockPath      = "/run/lock/nginx-acl-manager-publish.lock"
	defaultSystemctlPath        = "/usr/bin/systemctl"
	defaultSudoPath             = "/usr/bin/sudo"
	defaultBinaryPath           = "/usr/local/bin/nginx-acl-manager"
	defaultRecoverUnitPath      = "/etc/systemd/system/nginx-acl-manager-recover.service"
	defaultSystemdRoot          = "/etc/systemd/system"
	profileApplyUnitName        = "nginx-acl-manager-profile-apply.service"
	publishUnitName             = "nginx-acl-manager-publish.service"
	serviceName                 = "nginx-acl-manager.service"
)

// version 由 GitHub Actions 在构建 Release 时通过 ldflags 注入。
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(usageText())
	}

	switch args[0] {
	case "--version", "version":
		if len(args) != 1 {
			return errors.New("version 命令不接收参数")
		}
		fmt.Println(version)
		return nil
	case "serve":
		if len(args) != 1 {
			return errors.New("serve 命令不接收参数")
		}
		return runServe()
	case "admin":
		return runAdmin(args[1:])
	case "config":
		return runConfig(args[1:])
	case "profile":
		return runProfile(args[1:])
	case "publish":
		if len(args) != 1 {
			return errors.New("publish 命令不接收参数")
		}
		return runPublish()
	case "recover":
		if len(args) != 1 {
			return errors.New("recover 命令不接收参数")
		}
		return runRecover()
	case "help", "--help", "-h":
		fmt.Print(usageText())
		return nil
	default:
		return fmt.Errorf("未知命令 %q\n%s", args[0], usageText())
	}
}

func usageText() string {
	return `用法:
  nginx-acl-manager serve
  nginx-acl-manager admin init [--output PATH]
  nginx-acl-manager admin set-username [--output PATH]
  nginx-acl-manager admin set-password [--output PATH]
  nginx-acl-manager admin reset [--output PATH]
  nginx-acl-manager config init [--output PATH] [--port PORT]
  nginx-acl-manager config set-port --port PORT [--output PATH]
  nginx-acl-manager profile seed-candidate [参数]
  nginx-acl-manager profile apply-candidate
  nginx-acl-manager publish
  nginx-acl-manager recover
  nginx-acl-manager --version
`
}
