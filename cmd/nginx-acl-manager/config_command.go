package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"nginx-acl-manager/internal/serverconfig"
)

func runConfig(args []string) error {
	if len(args) == 0 {
		return errors.New("config 命令缺少子命令")
	}
	if args[0] != "init" && args[0] != "set-port" {
		return fmt.Errorf("未知 config 子命令 %q", args[0])
	}

	flags := flag.NewFlagSet("config "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outputPath := flags.String("output", defaultConfigPath, "服务配置文件")
	port := flags.Int("port", serverconfig.DefaultPort, "管理页面端口")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("config 命令包含多余参数")
	}
	portProvided := false
	flags.Visit(func(current *flag.Flag) {
		if current.Name == "port" {
			portProvided = true
		}
	})
	if args[0] == "set-port" && !portProvided {
		return errors.New("config set-port 必须提供 --port")
	}
	if err := requireAbsolutePath(*outputPath, "服务配置文件"); err != nil {
		return err
	}
	updated := serverconfig.Config{ListenPort: *port}

	if args[0] == "init" {
		if _, err := os.Stat(*outputPath); err == nil {
			return errors.New("服务配置已经存在，不能重复初始化")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("检查服务配置: %w", err)
		}
		if err := ensurePortAvailable(updated); err != nil {
			return err
		}
		return serverconfig.Save(*outputPath, updated)
	}

	previous, err := serverconfig.Load(*outputPath)
	if err != nil {
		return err
	}
	if previous.ListenPort == updated.ListenPort {
		return nil
	}
	if err := ensurePortAvailable(updated); err != nil {
		return err
	}
	if err := serverconfig.Save(*outputPath, updated); err != nil {
		return err
	}
	if err := restartManagerService(); err != nil {
		if rollbackErr := serverconfig.Save(*outputPath, previous); rollbackErr != nil {
			return fmt.Errorf("新端口启动失败且旧配置恢复失败: %v; %w", rollbackErr, err)
		}
		if rollbackRestartErr := restartManagerService(); rollbackRestartErr != nil {
			return fmt.Errorf("已恢复旧配置但旧端口重新启动失败，原始错误: %v; %w", err, rollbackRestartErr)
		}
		return fmt.Errorf("新端口启动失败，已恢复旧配置: %w", err)
	}
	return nil
}

func ensurePortAvailable(config serverconfig.Config) error {
	address, err := config.ListenAddressWithPort()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("管理端口不可用: %w", err)
	}
	if err := listener.Close(); err != nil {
		return fmt.Errorf("释放管理端口检查监听器: %w", err)
	}
	return nil
}

func restartManagerService() error {
	systemctlPath, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.New("找不到 systemctl")
	}
	command := exec.Command(systemctlPath, "restart", serviceName)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart: %w: %s", err, string(output))
	}
	return nil
}
