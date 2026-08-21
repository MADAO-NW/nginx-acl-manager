package main

import (
	"context"
	"errors"
	"fmt"
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

func (t fixedSystemdTrigger) Trigger(ctx context.Context) error {
	command := exec.CommandContext(ctx, defaultSudoPath, "-n", defaultSystemctlPath, "start", t.unit)
	if err := command.Run(); err != nil {
		return fmt.Errorf("启动固定 systemd unit %s: %w", t.unit, err)
	}
	return nil
}

func runServe() error {
	config, err := serverconfig.Load(defaultConfigPath)
	if err != nil {
		return err
	}
	address, err := config.ListenAddressWithPort()
	if err != nil {
		return err
	}
	verifier, err := auth.LoadVerifier(defaultCredentialsPath)
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
	handler, err := webhandler.NewHandler(webhandler.Options{
		Verifier: verifier,
		Sessions: sessions,
		Profiles: nginxprofile.Store{
			CandidatePath: defaultCandidateProfilePath,
			ActivePath:    defaultActiveProfilePath,
		},
		ApplyTrigger:   fixedSystemdTrigger{unit: profileApplyUnitName},
		PublishTrigger: fixedSystemdTrigger{unit: publishUnitName},
		Drafts:         draft.Store{Directory: defaultDraftDirectory},
		Releases: release.Store{
			AccessControlRoot: defaultAccessControlRoot,
			CandidatePath:     defaultPublishCandidatePath,
			TransactionPath:   defaultTransactionPath,
			ResultPath:        defaultPublishResultPath,
		},
		ProfileResultPath: defaultProfileResultPath,
		DefaultCandidate:  nginxprofile.DefaultCandidate(detectedBinary),
		Logger:            slog.Default(),
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
