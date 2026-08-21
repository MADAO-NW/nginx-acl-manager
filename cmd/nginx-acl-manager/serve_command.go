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
	"nginx-acl-manager/internal/nginxprofile"
	"nginx-acl-manager/internal/serverconfig"
	webhandler "nginx-acl-manager/internal/web"
)

type unavailableApplyTrigger struct{}

func (unavailableApplyTrigger) Trigger(context.Context) error {
	return errors.New("当前版本尚未实现 root Profile apply")
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
		ApplyTrigger:     unavailableApplyTrigger{},
		DefaultCandidate: nginxprofile.DefaultCandidate(detectedBinary),
		AllowedHost:      address,
		Logger:           slog.Default(),
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
