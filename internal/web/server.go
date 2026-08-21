package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"nginx-acl-manager/internal/auth"
	"nginx-acl-manager/internal/draft"
	"nginx-acl-manager/internal/model"
	"nginx-acl-manager/internal/nginxprofile"
	"nginx-acl-manager/internal/release"
)

const (
	sessionCookieName   = "nginx_acl_session"
	loginCSRFCookieName = "nginx_acl_login_csrf"
)

// templateFiles 保存编译进二进制的服务端页面模板。
//
//go:embed templates/*.html
var templateFiles embed.FS

// CredentialVerifier 校验单管理员用户名和密码。
type CredentialVerifier interface {
	Verify(username, password string) bool
}

// SecurityCredentialProvider 提供安全设置和 TOTP 登录所需的只读正式凭据视图。
type SecurityCredentialProvider interface {
	CredentialVerifier
	Username() string
	TOTPSecret() string
	Fingerprint() string
}

// ProfileRepository 提供 Web 所需的候选写入和正式 Profile 只读能力。
type ProfileRepository interface {
	LoadCandidate() (nginxprofile.Profile, error)
	LoadActive() (nginxprofile.Profile, error)
	SaveCandidate(profile nginxprofile.Profile) error
}

// ApplyTrigger 只能触发预先固定的 root Profile apply 入口。
type ApplyTrigger interface {
	Trigger(ctx context.Context) error
}

// Options 定义 Web 处理器的必要依赖。
type Options struct {
	Verifier            CredentialVerifier
	Sessions            *auth.SessionStore
	Profiles            ProfileRepository
	ApplyTrigger        ApplyTrigger
	PublishTrigger      ApplyTrigger
	Drafts              draft.Store
	Releases            release.Store
	ProfileResultPath   string
	DefaultCandidate    nginxprofile.Profile
	SecureCookies       bool
	Logger              *slog.Logger
	SecurityCredentials SecurityCredentialProvider
	AuthChangeTrigger   ApplyTrigger
	AuthCandidatePath   string
	TOTPState           *auth.TOTPStateStore
	LoginLimiter        *auth.LoginLimiter
	Sleep               func(time.Duration)
}

type server struct {
	verifier            CredentialVerifier
	sessions            *auth.SessionStore
	profiles            ProfileRepository
	applyTrigger        ApplyTrigger
	publishTrigger      ApplyTrigger
	drafts              draft.Store
	releases            release.Store
	profileResultPath   string
	defaultCandidate    nginxprofile.Profile
	secureCookies       bool
	logger              *slog.Logger
	templates           *template.Template
	mux                 *http.ServeMux
	publishMu           sync.Mutex
	securityCredentials SecurityCredentialProvider
	authChangeTrigger   ApplyTrigger
	authCandidatePath   string
	totpState           *auth.TOTPStateStore
	loginLimiter        *auth.LoginLimiter
	sleep               func(time.Duration)
	authChangeMu        sync.Mutex
	pendingTOTPMu       sync.Mutex
	pendingTOTP         map[string]string
}

type loginPageData struct {
	CSRFToken         string
	Error             string
	TwoFactorRequired bool
}

type homePageData struct {
	CSRFToken        string
	HasActiveProfile bool
	Projects         []model.Project
	CurrentRevision  string
	Message          string
}

type settingsPageData struct {
	CSRFToken   string
	Candidate   nginxprofile.Profile
	Active      nginxprofile.Profile
	HasActive   bool
	FieldErrors nginxprofile.FieldErrors
	Error       string
	Message     string
}

// NewHandler 构建带登录、Session、CSRF 和 Nginx 设置页的 HTTP 处理器。
func NewHandler(options Options) (http.Handler, error) {
	if options.Verifier == nil || options.Sessions == nil || options.Profiles == nil || options.ApplyTrigger == nil {
		return nil, errors.New("Web 处理器依赖不完整")
	}

	templates, err := template.New("").Funcs(template.FuncMap{
		"hasMethod": methodChecked,
		"totalInstances": func(projects []model.Project) int {
			n := 0
			for _, p := range projects {
				n += len(p.Instances)
			}
			return n
		},
		"totalRules": func(projects []model.Project) int {
			n := 0
			for _, p := range projects {
				for _, inst := range p.Instances {
					n += len(inst.Rules)
				}
			}
			return n
		},
		"totalAllowlist": func(projects []model.Project) int {
			n := 0
			for _, p := range projects {
				for _, inst := range p.Instances {
					n += len(inst.AllowedCIDRs)
				}
			}
			return n
		},
	}).ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		return nil, err
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &server{
		verifier:            options.Verifier,
		sessions:            options.Sessions,
		profiles:            options.Profiles,
		applyTrigger:        options.ApplyTrigger,
		publishTrigger:      options.PublishTrigger,
		drafts:              options.Drafts,
		releases:            options.Releases,
		profileResultPath:   options.ProfileResultPath,
		defaultCandidate:    options.DefaultCandidate,
		secureCookies:       options.SecureCookies,
		logger:              logger,
		templates:           templates,
		mux:                 http.NewServeMux(),
		securityCredentials: options.SecurityCredentials,
		authChangeTrigger:   options.AuthChangeTrigger,
		authCandidatePath:   options.AuthCandidatePath,
		totpState:           options.TOTPState,
		loginLimiter:        options.LoginLimiter,
		sleep:               options.Sleep,
		pendingTOTP:         make(map[string]string),
	}
	if s.securityCredentials == nil {
		if provider, ok := options.Verifier.(SecurityCredentialProvider); ok {
			s.securityCredentials = provider
		}
	}
	if s.loginLimiter == nil {
		s.loginLimiter = auth.NewLoginLimiter()
	}
	if s.sleep == nil {
		s.sleep = time.Sleep
	}

	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /login", s.handleLogin)
	s.mux.HandleFunc("GET /login/2fa", s.handleLoginTOTPPage)
	s.mux.HandleFunc("POST /login/2fa", s.handleLoginTOTP)
	s.mux.HandleFunc("POST /login/2fa/cancel", s.handleCancelLoginTOTP)
	s.mux.HandleFunc("POST /logout", s.requireSession(true, s.handleLogout))
	s.mux.HandleFunc("GET /api/security", s.requireSession(false, s.handleSecurityStatus))
	s.mux.HandleFunc("POST /api/security/password", s.requireSession(true, s.handleChangePassword))
	s.mux.HandleFunc("POST /api/security/2fa/setup", s.requireSession(true, s.handleSetupTOTP))
	s.mux.HandleFunc("POST /api/security/2fa/enable", s.requireSession(true, s.handleEnableTOTP))
	s.mux.HandleFunc("POST /api/security/2fa/disable", s.requireSession(true, s.handleDisableTOTP))
	s.mux.HandleFunc("GET /settings/security", s.requireSession(false, s.handleSecuritySettingsPage))
	s.mux.HandleFunc("GET /{$}", s.requireSession(false, s.handleHome))
	s.mux.HandleFunc("GET /settings/nginx", s.requireSession(false, s.handleNginxSettings))
	s.mux.HandleFunc("POST /settings/nginx", s.requireSession(true, s.handleSaveNginxSettings))
	s.mux.HandleFunc("POST /settings/nginx/apply", s.requireSession(true, s.handleApplyNginxSettings))
	if s.drafts.Directory != "" && s.releases.AccessControlRoot != "" {
		s.mux.HandleFunc("GET /projects/new", s.requireSession(false, s.handleNewProjectPage))
		s.mux.HandleFunc("POST /projects", s.requireSession(true, s.handleCreateProject))
		s.mux.HandleFunc("GET /projects/{slug}", s.requireSession(false, s.handleProject))
		s.mux.HandleFunc("POST /projects/{slug}", s.requireSession(true, s.handleUpdateProject))
		s.mux.HandleFunc("POST /projects/{slug}/instances", s.requireSession(true, s.handleCreateInstance))
		s.mux.HandleFunc("POST /projects/{slug}/instances/{key}", s.requireSession(true, s.handleUpdateInstance))
		s.mux.HandleFunc("POST /projects/{slug}/instances/{key}/allowlist", s.requireSession(true, s.handleCreateAllowlist))
		s.mux.HandleFunc("POST /projects/{slug}/instances/{key}/allowlist/{id}", s.requireSession(true, s.handleUpdateAllowlist))
		s.mux.HandleFunc("POST /projects/{slug}/instances/{key}/rules", s.requireSession(true, s.handleCreateRule))
		s.mux.HandleFunc("POST /projects/{slug}/instances/{key}/rules/{id}", s.requireSession(true, s.handleUpdateRule))
		s.mux.HandleFunc("POST /projects/{slug}/preview", s.requireSession(true, s.handlePreviewProject))
		s.mux.HandleFunc("POST /projects/{slug}/publish", s.requireSession(true, s.handlePublishProject))
		s.mux.HandleFunc("POST /projects/{slug}/restore/{revision}", s.requireSession(true, s.handleRestoreProject))
	}
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	return s, nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

func (s *server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if _, _, ok := s.pendingSession(r); ok {
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}
	token, err := newToken()
	if err != nil {
		s.logger.Error("生成登录 CSRF token 失败", "error", err)
		http.Error(w, "暂时无法打开登录页", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, loginCSRFCookieName, token, true)
	s.render(w, http.StatusOK, "login.html", loginPageData{CSRFToken: token})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(loginCSRFCookieName)
	if err != nil || !sameToken(cookie.Value, r.FormValue("csrf_token")) {
		http.Error(w, "登录请求已失效，请刷新页面重试", http.StatusBadRequest)
		return
	}

	rateKey := loginRateKey(r, r.FormValue("username"), "password")
	if !s.verifier.Verify(r.FormValue("username"), r.FormValue("password")) {
		s.sleep(s.loginLimiter.Failure(rateKey))
		s.render(w, http.StatusUnauthorized, "login.html", loginPageData{
			CSRFToken: cookie.Value,
			Error:     "用户名或密码错误",
		})
		return
	}
	s.loginLimiter.Success(rateKey)
	if s.securityCredentials != nil && s.securityCredentials.TOTPSecret() != "" {
		sessionID, _, err := s.sessions.CreatePending()
		if err != nil {
			s.logger.Error("创建 TOTP 临时 Session 失败", "error", err)
			http.Error(w, "暂时无法登录", http.StatusInternalServerError)
			return
		}
		s.setCookie(w, sessionCookieName, sessionID, true)
		s.deleteCookie(w, loginCSRFCookieName, true)
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}

	sessionID, _, err := s.sessions.Create()
	if err != nil {
		s.logger.Error("创建 Session 失败", "error", err)
		http.Error(w, "暂时无法登录", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, sessionCookieName, sessionID, true)
	s.deleteCookie(w, loginCSRFCookieName, true)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.sessions.Delete(cookie.Value)
	}
	s.deleteCookie(w, sessionCookieName, true)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	_, csrfToken, _ := s.currentSession(r)
	_, err := s.profiles.LoadActive()
	hasActive := err == nil
	if err != nil && !errors.Is(err, nginxprofile.ErrNotFound) {
		s.logger.Error("读取正式 Nginx Profile 失败", "error", err)
		http.Error(w, "暂时无法读取 Nginx 状态", http.StatusInternalServerError)
		return
	}
	projects := []model.Project{}
	if s.drafts.Directory != "" {
		projects, err = s.drafts.List()
		if err != nil {
			s.logger.Error("读取项目草稿失败", "error", err)
			http.Error(w, "暂时无法读取项目", http.StatusInternalServerError)
			return
		}
	}
	currentRevision := ""
	if s.releases.AccessControlRoot != "" {
		if revision, revisionErr := s.releases.CurrentRevision(); revisionErr == nil {
			currentRevision = revision
		}
	}
	message := ""
	if r.URL.Query().Get("created") == "1" {
		message = "项目草稿已创建"
	}
	s.render(w, http.StatusOK, "home.html", homePageData{
		CSRFToken:        csrfToken,
		HasActiveProfile: hasActive,
		Projects:         projects,
		CurrentRevision:  currentRevision,
		Message:          message,
	})
}

func (s *server) handleNginxSettings(w http.ResponseWriter, r *http.Request) {
	_, csrfToken, _ := s.currentSession(r)
	data, err := s.settingsData(csrfToken)
	if err != nil {
		s.logger.Error("读取 Nginx 设置失败", "error", err)
		http.Error(w, "暂时无法读取 Nginx 设置", http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		data.Message = "候选 Profile 已保存，尚未修改正式配置"
	}
	if r.URL.Query().Get("apply") == "1" {
		data.Message = "已触发 root 验证与应用，请刷新页面查看正式 Profile"
	}
	if result, resultErr := nginxprofile.LoadApplyResult(s.profileResultPath); resultErr == nil {
		data.Message = result.Message
	}
	s.render(w, http.StatusOK, "nginx_settings.html", data)
}

func (s *server) handleSaveNginxSettings(w http.ResponseWriter, r *http.Request) {
	_, csrfToken, _ := s.currentSession(r)
	profile := profileFromRequest(r)
	if err := nginxprofile.ValidateCandidate(profile); err != nil {
		data, loadErr := s.settingsData(csrfToken)
		if loadErr != nil {
			http.Error(w, "暂时无法读取 Nginx 设置", http.StatusInternalServerError)
			return
		}
		data.Candidate = profile
		data.Error = "请修正标记的字段"
		if fieldErrors, ok := err.(nginxprofile.FieldErrors); ok {
			data.FieldErrors = fieldErrors
		}
		s.render(w, http.StatusUnprocessableEntity, "nginx_settings.html", data)
		return
	}
	if err := s.profiles.SaveCandidate(profile); err != nil {
		s.logger.Error("保存候选 Nginx Profile 失败", "error", err)
		http.Error(w, "候选 Profile 保存失败", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings/nginx?saved=1", http.StatusSeeOther)
}

func (s *server) handleApplyNginxSettings(w http.ResponseWriter, r *http.Request) {
	if _, err := s.profiles.LoadCandidate(); err != nil {
		if errors.Is(err, nginxprofile.ErrNotFound) {
			http.Error(w, "请先保存候选 Profile", http.StatusConflict)
			return
		}
		s.logger.Error("读取待应用 Nginx Profile 失败", "error", err)
		http.Error(w, "暂时无法读取候选 Profile", http.StatusInternalServerError)
		return
	}
	if err := s.applyTrigger.Trigger(r.Context()); err != nil {
		s.logger.Error("触发 Nginx Profile root apply 失败", "error", err)
		http.Error(w, "无法启动 Nginx Profile 验证", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/settings/nginx?apply=1", http.StatusSeeOther)
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *server) requireSession(requireCSRF bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, csrfToken, ok := s.currentSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if requireCSRF && !sameToken(csrfToken, r.FormValue("csrf_token")) {
			http.Error(w, "请求已失效，请刷新页面重试", http.StatusBadRequest)
			return
		}
		next(w, r)
	}
}

func (s *server) currentSession(r *http.Request) (string, string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", "", false
	}
	csrfToken, ok := s.sessions.Get(cookie.Value)
	return cookie.Value, csrfToken, ok
}

func (s *server) pendingSession(r *http.Request) (string, string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", "", false
	}
	csrfToken, ok := s.sessions.GetPending(cookie.Value)
	return cookie.Value, csrfToken, ok
}

func (s *server) settingsData(csrfToken string) (settingsPageData, error) {
	data := settingsPageData{CSRFToken: csrfToken}
	active, err := s.profiles.LoadActive()
	if err == nil {
		data.Active = active
		data.HasActive = true
	} else if !errors.Is(err, nginxprofile.ErrNotFound) {
		return settingsPageData{}, err
	}

	candidate, err := s.profiles.LoadCandidate()
	if err == nil {
		data.Candidate = candidate
		return data, nil
	}
	if !errors.Is(err, nginxprofile.ErrNotFound) {
		return settingsPageData{}, err
	}
	if data.HasActive {
		data.Candidate = data.Active
	} else {
		data.Candidate = s.defaultCandidate
	}
	return data, nil
}

func (s *server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Error("渲染页面失败", "template", name, "error", err)
	}
}

func (s *server) setCookie(w http.ResponseWriter, name, value string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: httpOnly,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *server) deleteCookie(w http.ResponseWriter, name string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: httpOnly,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func profileFromRequest(r *http.Request) nginxprofile.Profile {
	return nginxprofile.Profile{
		BinaryPath:        r.FormValue("binaryPath"),
		ConfigPath:        r.FormValue("configPath"),
		PrefixPath:        r.FormValue("prefixPath"),
		ServiceName:       r.FormValue("serviceName"),
		HTTPIncludeFile:   r.FormValue("httpIncludeFile"),
		RealIPSnippetPath: r.FormValue("realIpSnippetPath"),
	}
}

func newToken() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func sameToken(expected, actual string) bool {
	if expected == "" || len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}
