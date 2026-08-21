package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"

	"nginx-acl-manager/internal/nginxprofile"
	"nginx-acl-manager/internal/release"
)

type commandRunner struct{}

func (commandRunner) Run(ctx context.Context, name string, args ...string) (nginxprofile.CommandOutput, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return nginxprofile.CommandOutput{Stdout: stdout.String(), Stderr: stderr.String()}, err
}

func runPublish() error {
	if os.Geteuid() != 0 {
		return errors.New("publish 必须由 root oneshot 执行")
	}
	publisher, err := rootPublisher()
	if err != nil {
		return err
	}
	_, err = publisher.Publish(context.Background())
	return err
}

func runRecover() error {
	if os.Geteuid() != 0 {
		return errors.New("recover 必须由 root oneshot 执行")
	}
	publisher, err := rootPublisher()
	if err != nil {
		return err
	}
	return publisher.Recover()
}

func rootPublisher() (release.Publisher, error) {
	account, err := user.Lookup("nginx-acl-manager")
	if err != nil {
		return release.Publisher{}, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return release.Publisher{}, err
	}
	runner := commandRunner{}
	return release.Publisher{
		Store: release.Store{
			AccessControlRoot: defaultAccessControlRoot,
			CandidatePath:     defaultPublishCandidatePath,
			TransactionPath:   defaultTransactionPath,
			ResultPath:        defaultPublishResultPath,
		},
		Profiles:  nginxprofile.Store{ActivePath: defaultActiveProfilePath},
		Validator: nginxprofile.RuntimeValidator{SystemctlPath: defaultSystemctlPath, Runner: runner},
		Runner:    runner,
		Systemctl: defaultSystemctlPath,
		LockPath:  defaultPublishLockPath,
		ResultGID: gid,
	}, nil
}
