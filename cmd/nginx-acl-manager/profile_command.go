package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"

	"nginx-acl-manager/internal/nginxprofile"
	"nginx-acl-manager/internal/release"
)

func runProfile(args []string) error {
	if len(args) == 0 {
		return errors.New("profile 需要 seed-candidate 或 apply-candidate 子命令")
	}
	if args[0] == "apply-candidate" {
		if len(args) != 1 {
			return errors.New("profile apply-candidate 不接收参数")
		}
		return runProfileApply()
	}
	if args[0] != "seed-candidate" {
		return errors.New("profile 只支持 seed-candidate 或 apply-candidate 子命令")
	}

	flags := flag.NewFlagSet("profile seed-candidate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outputPath := flags.String("output", defaultCandidateProfilePath, "候选 Profile 文件")
	binaryPath := flags.String("nginx-bin", "", "Nginx 二进制绝对路径")
	configPath := flags.String("nginx-conf", "", "Nginx 主配置绝对路径")
	prefixPath := flags.String("nginx-prefix", "", "Nginx prefix 绝对路径")
	nginxService := flags.String("nginx-service", nginxprofile.DefaultServiceName, "Nginx systemd service")
	httpInclude := flags.String("nginx-http-include", nginxprofile.DefaultHTTPIncludeFile, "管理器 http include")
	realIPSnippet := flags.String("nginx-real-ip-snippet", nginxprofile.DefaultRealIPSnippetPath, "real IP snippet")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("profile seed-candidate 包含多余参数")
	}
	if err := requireAbsolutePath(*outputPath, "候选 Profile 文件"); err != nil {
		return err
	}

	profile := nginxprofile.Profile{
		BinaryPath:        *binaryPath,
		ConfigPath:        *configPath,
		PrefixPath:        *prefixPath,
		ServiceName:       *nginxService,
		HTTPIncludeFile:   *httpInclude,
		RealIPSnippetPath: *realIPSnippet,
	}
	store := nginxprofile.Store{CandidatePath: *outputPath}
	if err := store.SaveCandidate(profile); err != nil {
		return fmt.Errorf("保存安装期候选 Profile: %w", err)
	}
	return nil
}

func runProfileApply() error {
	if os.Geteuid() != 0 {
		return errors.New("profile apply-candidate 必须由 root oneshot 执行")
	}
	account, err := user.Lookup("nginx-acl-manager")
	if err != nil {
		return fmt.Errorf("查找应用用户: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	runner := commandRunner{}
	profileStore := nginxprofile.Store{CandidatePath: defaultCandidateProfilePath, ActivePath: defaultActiveProfilePath}
	releaseStore := release.Store{
		AccessControlRoot: defaultAccessControlRoot,
		CandidatePath:     defaultPublishCandidatePath,
		TransactionPath:   defaultTransactionPath,
		ResultPath:        defaultPublishResultPath,
	}
	return nginxprofile.ApplyCandidate(context.Background(), nginxprofile.ApplyOptions{
		Profiles:          profileStore,
		Releases:          releaseStore,
		AccessControlRoot: defaultAccessControlRoot,
		Validator: nginxprofile.RuntimeValidator{
			SystemctlPath: defaultSystemctlPath,
			Runner:        runner,
		},
		Runner:          runner,
		SystemctlPath:   defaultSystemctlPath,
		ApplicationUID:  uid,
		ApplicationGID:  gid,
		ResultPath:      defaultProfileResultPath,
		RecoverUnitPath: defaultRecoverUnitPath,
		SystemdRoot:     defaultSystemdRoot,
		BinaryPath:      defaultBinaryPath,
	})
}
