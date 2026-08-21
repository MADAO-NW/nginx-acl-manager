package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"nginx-acl-manager/internal/nginxprofile"
)

func runProfile(args []string) error {
	if len(args) == 0 || args[0] != "seed-candidate" {
		return errors.New("profile 目前只支持 seed-candidate 子命令")
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
