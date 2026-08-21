package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"nginx-acl-manager/internal/auth"
	"nginx-acl-manager/internal/draft"
	"nginx-acl-manager/internal/nginxprofile"
	"nginx-acl-manager/internal/release"
	"nginx-acl-manager/internal/serverconfig"
	webhandler "nginx-acl-manager/internal/web"
)

type fixedSystemdTrigger struct {
	unit string
}

type disabledSystemdTrigger struct{}

type directAuthTrigger struct {
	credentialsPath string
	candidatePath   string
	totpStatePath   string
	manager         *auth.Manager
}

type reloadingAuthTrigger struct {
	trigger         webhandler.ApplyTrigger
	credentialsPath string
	manager         *auth.Manager
}

type servePaths struct {
	configPath           string
	credentialsPath      string
	candidateProfilePath string
	activeProfilePath    string
	draftDirectory       string
	publishCandidatePath string
	accessControlRoot    string
	transactionPath      string
	publishResultPath    string
	profileResultPath    string
	authCandidatePath    string
	totpStatePath        string
}

func (t fixedSystemdTrigger) Trigger(ctx context.Context) error {
	command := exec.CommandContext(ctx, defaultSudoPath, "-n", defaultSystemctlPath, "start", t.unit)
	if err := command.Run(); err != nil {
		return fmt.Errorf("启动固定 systemd unit %s: %w", t.unit, err)
	}
	return nil
}

func (disabledSystemdTrigger) Trigger(context.Context) error {
	return errors.New("本地开发模式不执行 systemd 写操作")
}

func (t directAuthTrigger) Trigger(context.Context) error {
	previous, err := auth.ApplyCandidate(t.credentialsPath, t.candidatePath, t.totpStatePath)
	if err != nil {
		return err
	}
	if err := t.manager.Reload(t.credentialsPath); err != nil {
		if rollbackErr := auth.SaveCredentials(t.credentialsPath, previous); rollbackErr != nil {
			return fmt.Errorf("重载本地认证失败且旧凭据恢复失败: %v; %w", rollbackErr, err)
		}
		_ = t.manager.Reload(t.credentialsPath)
		return fmt.Errorf("重载本地认证失败，已恢复旧凭据: %w", err)
	}
	return nil
}

func (t reloadingAuthTrigger) Trigger(ctx context.Context) error {
	if err := t.trigger.Trigger(ctx); err != nil {
		return err
	}
	return t.manager.Reload(t.credentialsPath)
}

func runServe(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	localDirectory := flags.String("local-dir", "", "本地开发数据目录")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve 命令包含多余参数")
	}

	paths, err := resolveServePaths(*localDirectory)
	if err != nil {
		return err
	}
	config, err := serverconfig.Load(paths.configPath)
	if err != nil {
		return err
	}
	address, err := config.ListenAddressWithPort()
	if err != nil {
		return err
	}
	credentials, err := auth.LoadManager(paths.credentialsPath)
	if err != nil {
		return err
	}
	sessions, err := auth.NewSessionStore(30*time.Minute, 12*time.Hour)
	if err != nil {
		return err
	}

	detectedBinary := ""
	if path, lookupErr := exec.LookPath("nginx"); lookupErr == nil && filepath.IsAbs(path) {
		detectedBinary = filepath.Clean(path)
	}
	var applyTrigger webhandler.ApplyTrigger = fixedSystemdTrigger{unit: profileApplyUnitName}
	var publishTrigger webhandler.ApplyTrigger = fixedSystemdTrigger{unit: publishUnitName}
	var authChangeTrigger webhandler.ApplyTrigger = reloadingAuthTrigger{
		trigger:         fixedSystemdTrigger{unit: authApplyUnitName},
		credentialsPath: paths.credentialsPath,
		manager:         credentials,
	}
	if *localDirectory != "" {
		applyTrigger = disabledSystemdTrigger{}
		publishTrigger = disabledSystemdTrigger{}
		authChangeTrigger = directAuthTrigger{
			credentialsPath: paths.credentialsPath,
			candidatePath:   paths.authCandidatePath,
			totpStatePath:   paths.totpStatePath,
			manager:         credentials,
		}
	}
	handler, err := webhandler.NewHandler(webhandler.Options{
		Verifier: credentials,
		Sessions: sessions,
		Profiles: nginxprofile.Store{
			CandidatePath: paths.candidateProfilePath,
			ActivePath:    paths.activeProfilePath,
		},
		ApplyTrigger:   applyTrigger,
		PublishTrigger: publishTrigger,
		Drafts:         draft.Store{Directory: paths.draftDirectory},
		Releases: release.Store{
			AccessControlRoot: paths.accessControlRoot,
			CandidatePath:     paths.publishCandidatePath,
			TransactionPath:   paths.transactionPath,
			ResultPath:        paths.publishResultPath,
		},
		ProfileResultPath:   paths.profileResultPath,
		DefaultCandidate:    nginxprofile.DefaultCandidate(detectedBinary),
		Logger:              slog.Default(),
		SecurityCredentials: credentials,
		AuthChangeTrigger:   authChangeTrigger,
		AuthCandidatePath:   paths.authCandidatePath,
		TOTPState:           &auth.TOTPStateStore{Path: paths.totpStatePath},
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if shutdownErr := server.Shutdown(ctx); shutdownErr != nil {
			slog.Error("关闭管理服务失败", "error", shutdownErr)
		}
	}()

	slog.Info("管理服务已启动", "address", address, "version", version)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("启动管理服务: %w", err)
	}
	return nil
}

func resolveServePaths(localDirectory string) (servePaths, error) {
	if localDirectory == "" {
		return servePaths{
			configPath:           defaultConfigPath,
			credentialsPath:      defaultCredentialsPath,
			candidateProfilePath: defaultCandidateProfilePath,
			activeProfilePath:    defaultActiveProfilePath,
			draftDirectory:       defaultDraftDirectory,
			publishCandidatePath: defaultPublishCandidatePath,
			accessControlRoot:    defaultAccessControlRoot,
			transactionPath:      defaultTransactionPath,
			publishResultPath:    defaultPublishResultPath,
			profileResultPath:    defaultProfileResultPath,
			authCandidatePath:    defaultAuthCandidatePath,
			totpStatePath:        defaultTOTPStatePath,
		}, nil
	}
	if err := requireAbsolutePath(localDirectory, "本地开发数据目录"); err != nil {
		return servePaths{}, err
	}

	return servePaths{
		configPath:           filepath.Join(localDirectory, "config.json"),
		credentialsPath:      filepath.Join(localDirectory, "auth.json"),
		candidateProfilePath: filepath.Join(localDirectory, "staging", "nginx-profile-candidate.json"),
		activeProfilePath:    filepath.Join(localDirectory, "nginx-profile.json"),
		draftDirectory:       filepath.Join(localDirectory, "drafts", "projects"),
		publishCandidatePath: filepath.Join(localDirectory, "staging", "candidate.json"),
		accessControlRoot:    filepath.Join(localDirectory, "access-control"),
		transactionPath:      filepath.Join(localDirectory, "access-control", ".publish-transaction.json"),
		publishResultPath:    filepath.Join(localDirectory, "results", "publish.json"),
		profileResultPath:    filepath.Join(localDirectory, "results", "profile-apply.json"),
		authCandidatePath:    filepath.Join(localDirectory, "staging", "auth-candidate.json"),
		totpStatePath:        filepath.Join(localDirectory, "auth", "totp-state.json"),
	}, nil
}
