package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"nginx-acl-manager/internal/auth"
	"nginx-acl-manager/internal/draft"
	"nginx-acl-manager/internal/nginxprofile"
	"nginx-acl-manager/internal/release"
)

// csrfPattern 提取服务端模板中的 CSRF hidden input。
var csrfPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

type fixedVerifier struct{}

func (fixedVerifier) Verify(username, password string) bool {
	return username == "admin" && password == "correct horse battery staple"
}

type countingTrigger struct {
	calls int
	err   error
}

type directCredentialTrigger struct {
	credentialsPath string
	candidatePath   string
	totpStatePath   string
	manager         *auth.Manager
}

func (t directCredentialTrigger) Trigger(context.Context) error {
	if _, err := auth.ApplyCandidate(t.credentialsPath, t.candidatePath, t.totpStatePath); err != nil {
		return err
	}
	return t.manager.Reload(t.credentialsPath)
}

func (t *countingTrigger) Trigger(context.Context) error {
	t.calls++
	return t.err
}

func TestNginxSettingsRequireLoginAndKeepCandidateSeparate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	profiles := nginxprofile.Store{
		CandidatePath: filepath.Join(dir, "staging", "nginx-profile-candidate.json"),
		ActivePath:    filepath.Join(dir, "nginx-profile.json"),
	}
	sessions, err := auth.NewSessionStore(30*time.Minute, 12*time.Hour)
	if err != nil {
		t.Fatalf("NewSessionStore() error = %v", err)
	}
	trigger := &countingTrigger{}
	handler, err := NewHandler(Options{
		Verifier:         fixedVerifier{},
		Sessions:         sessions,
		Profiles:         profiles,
		ApplyTrigger:     trigger,
		DefaultCandidate: nginxprofile.DefaultCandidate("/usr/sbin/nginx"),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	response := performRequest(handler, http.MethodGet, "/settings/nginx", nil)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated settings = %d, location %q", response.Code, response.Header().Get("Location"))
	}

	loginPage := performRequest(handler, http.MethodGet, "/login", nil)
	if loginPage.Code != http.StatusOK {
		t.Fatalf("GET /login = %d", loginPage.Code)
	}
	loginCSRF := extractCSRF(t, loginPage.Body.String())
	loginCookie := findCookie(t, loginPage.Result().Cookies(), loginCSRFCookieName)

	loginForm := url.Values{
		"csrf_token": {loginCSRF},
		"username":   {"admin"},
		"password":   {"correct horse battery staple"},
	}
	loginResponse := performRequest(handler, http.MethodPost, "/login", loginForm, loginCookie)
	if loginResponse.Code != http.StatusSeeOther {
		t.Fatalf("POST /login = %d, body %s", loginResponse.Code, loginResponse.Body.String())
	}
	sessionCookie := findCookie(t, loginResponse.Result().Cookies(), sessionCookieName)

	settingsPage := performRequest(handler, http.MethodGet, "/settings/nginx", nil, sessionCookie)
	if settingsPage.Code != http.StatusOK {
		t.Fatalf("GET settings = %d", settingsPage.Code)
	}
	if !strings.Contains(settingsPage.Body.String(), "尚未应用正式 Profile") {
		t.Fatalf("settings page does not show missing active profile: %s", settingsPage.Body.String())
	}
	settingsCSRF := extractCSRF(t, settingsPage.Body.String())

	invalidForm := validProfileForm(settingsCSRF)
	invalidForm.Set("serviceName", "nginx.service;reboot")
	invalidResponse := performRequest(handler, http.MethodPost, "/settings/nginx", invalidForm, sessionCookie)
	if invalidResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid profile = %d", invalidResponse.Code)
	}
	if _, err := profiles.LoadCandidate(); err == nil {
		t.Fatal("invalid form wrote candidate profile")
	}

	validForm := validProfileForm(settingsCSRF)
	saveResponse := performRequest(handler, http.MethodPost, "/settings/nginx", validForm, sessionCookie)
	if saveResponse.Code != http.StatusSeeOther {
		t.Fatalf("save profile = %d, body %s", saveResponse.Code, saveResponse.Body.String())
	}
	if _, err := profiles.LoadCandidate(); err != nil {
		t.Fatalf("LoadCandidate() error = %v", err)
	}
	if _, err := profiles.LoadActive(); err == nil {
		t.Fatal("saving candidate unexpectedly created active profile")
	}

	badApply := url.Values{"csrf_token": {"wrong"}}
	badApplyResponse := performRequest(handler, http.MethodPost, "/settings/nginx/apply", badApply, sessionCookie)
	if badApplyResponse.Code != http.StatusBadRequest || trigger.calls != 0 {
		t.Fatalf("bad apply = %d, calls = %d", badApplyResponse.Code, trigger.calls)
	}

	applyForm := url.Values{"csrf_token": {settingsCSRF}}
	applyResponse := performRequest(handler, http.MethodPost, "/settings/nginx/apply", applyForm, sessionCookie)
	if applyResponse.Code != http.StatusSeeOther || trigger.calls != 1 {
		t.Fatalf("apply = %d, calls = %d", applyResponse.Code, trigger.calls)
	}
}

func TestLoginUsesUniformCredentialError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sessions, err := auth.NewSessionStore(30*time.Minute, 12*time.Hour)
	if err != nil {
		t.Fatalf("NewSessionStore() error = %v", err)
	}
	handler, err := NewHandler(Options{
		Verifier:     fixedVerifier{},
		Sessions:     sessions,
		Profiles:     nginxprofile.Store{CandidatePath: filepath.Join(dir, "candidate.json"), ActivePath: filepath.Join(dir, "active.json")},
		ApplyTrigger: &countingTrigger{},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	page := performRequest(handler, http.MethodGet, "/login", nil)
	csrfToken := extractCSRF(t, page.Body.String())
	cookie := findCookie(t, page.Result().Cookies(), loginCSRFCookieName)
	form := url.Values{
		"csrf_token": {csrfToken},
		"username":   {"unknown"},
		"password":   {"wrong"},
	}
	response := performRequest(handler, http.MethodPost, "/login", form, cookie)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "用户名或密码错误") {
		t.Fatalf("bad login body = %s", response.Body.String())
	}
}

func TestLoginRequiresTOTPAndRotatesPendingSession(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	passwordHash, err := auth.HashPassword("secret-password")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.NewVerifier(auth.Credentials{
		Username:     "admin",
		PasswordHash: passwordHash,
		TOTP:         &auth.TOTPConfig{Secret: secret},
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := auth.NewSessionStore(30*time.Minute, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Verifier:            verifier,
		SecurityCredentials: verifier,
		Sessions:            sessions,
		Profiles:            nginxprofile.Store{CandidatePath: filepath.Join(directory, "candidate.json")},
		ApplyTrigger:        &countingTrigger{},
		TOTPState:           &auth.TOTPStateStore{Path: filepath.Join(directory, "totp-state.json")},
		Sleep:               func(time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}

	loginPage := performRequest(handler, http.MethodGet, "/login", nil)
	loginCSRF := extractCSRF(t, loginPage.Body.String())
	loginCookie := findCookie(t, loginPage.Result().Cookies(), loginCSRFCookieName)
	passwordResponse := performRequest(handler, http.MethodPost, "/login", url.Values{
		"csrf_token": {loginCSRF},
		"username":   {"admin"},
		"password":   {"secret-password"},
	}, loginCookie)
	if passwordResponse.Code != http.StatusSeeOther || passwordResponse.Header().Get("Location") != "/login/2fa" {
		t.Fatalf("password stage = %d, location %q", passwordResponse.Code, passwordResponse.Header().Get("Location"))
	}
	pendingCookie := findCookie(t, passwordResponse.Result().Cookies(), sessionCookieName)
	pendingCSRF, ok := sessions.GetPending(pendingCookie.Value)
	if !ok {
		t.Fatal("password stage did not create a pending session")
	}
	if _, ok := sessions.Get(pendingCookie.Value); ok {
		t.Fatal("pending session was accepted as an authenticated session")
	}

	code := testTOTPCode(t, secret, time.Now())
	totpResponse := performRequest(handler, http.MethodPost, "/login/2fa", url.Values{
		"csrf_token": {pendingCSRF},
		"code":       {code},
	}, pendingCookie)
	if totpResponse.Code != http.StatusSeeOther || totpResponse.Header().Get("Location") != "/" {
		t.Fatalf("TOTP stage = %d, body %s", totpResponse.Code, totpResponse.Body.String())
	}
	authenticatedCookie := findCookie(t, totpResponse.Result().Cookies(), sessionCookieName)
	if authenticatedCookie.Value == pendingCookie.Value {
		t.Fatal("pending session ID was not rotated")
	}
	if _, ok := sessions.Get(authenticatedCookie.Value); !ok {
		t.Fatal("rotated session is not authenticated")
	}
}

func TestSecurityPasswordAndTOTPChangesInvalidateSessions(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	credentialsPath := filepath.Join(directory, "auth.json")
	candidatePath := filepath.Join(directory, "staging", "auth-candidate.json")
	statePath := filepath.Join(directory, "auth", "totp-state.json")
	passwordHash, err := auth.HashPassword("initial-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveCredentials(credentialsPath, auth.Credentials{Username: "admin", PasswordHash: passwordHash}); err != nil {
		t.Fatal(err)
	}
	manager, err := auth.LoadManager(credentialsPath)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := auth.NewSessionStore(30*time.Minute, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	totpState := &auth.TOTPStateStore{Path: statePath}
	trigger := directCredentialTrigger{
		credentialsPath: credentialsPath,
		candidatePath:   candidatePath,
		totpStatePath:   statePath,
		manager:         manager,
	}
	handler, err := NewHandler(Options{
		Verifier:            manager,
		SecurityCredentials: manager,
		Sessions:            sessions,
		Profiles:            nginxprofile.Store{CandidatePath: filepath.Join(directory, "profile-candidate.json")},
		ApplyTrigger:        &countingTrigger{},
		AuthChangeTrigger:   trigger,
		AuthCandidatePath:   candidatePath,
		TOTPState:           totpState,
		Sleep:               func(time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}

	passwordSessionID, passwordCSRF, err := sessions.Create()
	if err != nil {
		t.Fatal(err)
	}
	passwordCookie := &http.Cookie{Name: sessionCookieName, Value: passwordSessionID}

	securityPage := performRequest(handler, http.MethodGet, "/settings/security", nil, passwordCookie)
	if securityPage.Code != http.StatusOK || !strings.Contains(securityPage.Body.String(), "账号与系统安全配置") {
		t.Fatalf("get security page = %d: %s", securityPage.Code, securityPage.Body.String())
	}
	if !strings.Contains(securityPage.Body.String(), "json.qrCodeDataUrl") || strings.Contains(securityPage.Body.String(), "makeQRMatrix") {
		t.Fatal("security page did not use the backend QR code image")
	}

	passwordResponse := performRequest(handler, http.MethodPost, "/api/security/password", url.Values{
		"csrf_token":      {passwordCSRF},
		"currentPassword": {"initial-password"},
		"newPassword":     {"changed-password"},
		"confirmPassword": {"changed-password"},
	}, passwordCookie)
	if passwordResponse.Code != http.StatusAccepted {
		t.Fatalf("change password = %d: %s", passwordResponse.Code, passwordResponse.Body.String())
	}
	if manager.Verify("admin", "initial-password") || !manager.Verify("admin", "changed-password") {
		t.Fatal("password change was not reloaded")
	}
	if response := performRequest(handler, http.MethodGet, "/api/security", nil, passwordCookie); response.Code != http.StatusSeeOther {
		t.Fatalf("old session after password change = %d", response.Code)
	}

	setupSessionID, setupCSRF, err := sessions.Create()
	if err != nil {
		t.Fatal(err)
	}
	setupCookie := &http.Cookie{Name: sessionCookieName, Value: setupSessionID}
	setupResponse := performRequest(handler, http.MethodPost, "/api/security/2fa/setup", url.Values{
		"csrf_token":      {setupCSRF},
		"currentPassword": {"changed-password"},
	}, setupCookie)
	if setupResponse.Code != http.StatusOK {
		t.Fatalf("setup TOTP = %d: %s", setupResponse.Code, setupResponse.Body.String())
	}
	var setup totpSetupResponse
	if err := json.Unmarshal(setupResponse.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if setup.Secret == "" || !strings.HasPrefix(setup.ProvisioningURI, "otpauth://totp/") {
		t.Fatalf("setup response = %#v", setup)
	}
	const qrCodeDataURLPrefix = "data:image/png;base64,"
	if !strings.HasPrefix(setup.QRCodeDataURL, qrCodeDataURLPrefix) {
		t.Fatalf("QR code data URL prefix = %q", setup.QRCodeDataURL)
	}
	qrCodePNG, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(setup.QRCodeDataURL, qrCodeDataURLPrefix))
	if err != nil {
		t.Fatalf("decode QR code data URL: %v", err)
	}
	qrCodeImage, err := png.Decode(bytes.NewReader(qrCodePNG))
	if err != nil {
		t.Fatalf("decode QR code PNG: %v", err)
	}
	if bounds := qrCodeImage.Bounds(); bounds.Dx() != totpQRCodeSize || bounds.Dy() != totpQRCodeSize {
		t.Fatalf("QR code dimensions = %dx%d", bounds.Dx(), bounds.Dy())
	}
	enableResponse := performRequest(handler, http.MethodPost, "/api/security/2fa/enable", url.Values{
		"csrf_token": {setupCSRF},
		"code":       {testTOTPCode(t, setup.Secret, time.Now())},
	}, setupCookie)
	if enableResponse.Code != http.StatusAccepted || manager.TOTPSecret() != setup.Secret {
		t.Fatalf("enable TOTP = %d, secret configured = %t: %s", enableResponse.Code, manager.TOTPSecret() == setup.Secret, enableResponse.Body.String())
	}
	if response := performRequest(handler, http.MethodGet, "/api/security", nil, setupCookie); response.Code != http.StatusSeeOther {
		t.Fatalf("old session after enabling TOTP = %d", response.Code)
	}

	disableSessionID, disableCSRF, err := sessions.Create()
	if err != nil {
		t.Fatal(err)
	}
	disableCookie := &http.Cookie{Name: sessionCookieName, Value: disableSessionID}
	future := time.Now().Add(30 * time.Second)
	totpState.Now = func() time.Time { return future }
	disableResponse := performRequest(handler, http.MethodPost, "/api/security/2fa/disable", url.Values{
		"csrf_token":      {disableCSRF},
		"currentPassword": {"changed-password"},
		"code":            {testTOTPCode(t, setup.Secret, future)},
	}, disableCookie)
	if disableResponse.Code != http.StatusAccepted || manager.TOTPSecret() != "" {
		t.Fatalf("disable TOTP = %d, configured = %t: %s", disableResponse.Code, manager.TOTPSecret() != "", disableResponse.Body.String())
	}
	if response := performRequest(handler, http.MethodGet, "/api/security", nil, disableCookie); response.Code != http.StatusSeeOther {
		t.Fatalf("old session after disabling TOTP = %d", response.Code)
	}
}

func TestExternalHost(t *testing.T) {
	t.Parallel()

	sessions, err := auth.NewSessionStore(30*time.Minute, 12*time.Hour)
	if err != nil {
		t.Fatalf("NewSessionStore() error = %v", err)
	}
	handler, err := NewHandler(Options{
		Verifier:     fixedVerifier{},
		Sessions:     sessions,
		Profiles:     nginxprofile.Store{CandidatePath: filepath.Join(t.TempDir(), "candidate.json")},
		ApplyTrigger: &countingTrigger{},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.Host = "attacker.example"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("external host = %d", response.Code)
	}
}

func TestProjectDraftFlowAndPreview(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sessions, err := auth.NewSessionStore(30*time.Minute, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, csrfToken, err := sessions.Create()
	if err != nil {
		t.Fatal(err)
	}
	profiles := nginxprofile.Store{CandidatePath: filepath.Join(dir, "profile-candidate.json"), ActivePath: filepath.Join(dir, "profile.json")}
	if err := profiles.SaveActive(nginxprofile.Profile{BinaryPath: "/usr/sbin/nginx", ConfigPath: "/etc/nginx/nginx.conf", ServiceName: "nginx.service", HTTPIncludeFile: "/etc/nginx/conf.d/manager.conf", RealIPSnippetPath: "/etc/nginx/snippets/real.conf"}); err != nil {
		t.Fatal(err)
	}
	releases := release.Store{AccessControlRoot: filepath.Join(dir, "acl"), CandidatePath: filepath.Join(dir, "candidate.json")}
	if _, err := releases.EnsureInitialRelease(); err != nil {
		t.Fatal(err)
	}
	drafts := draft.Store{Directory: filepath.Join(dir, "drafts")}
	handler, err := NewHandler(Options{Verifier: fixedVerifier{}, Sessions: sessions, Profiles: profiles, ApplyTrigger: &countingTrigger{}, PublishTrigger: &countingTrigger{}, Drafts: drafts, Releases: releases})
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: sessionCookieName, Value: sessionID}
	newPage := performRequest(handler, http.MethodGet, "/projects/new", nil, cookie)
	if newPage.Code != http.StatusOK || !strings.Contains(newPage.Body.String(), "新建 ACL 项目草稿") {
		t.Fatalf("get new project page = %d: %s", newPage.Code, newPage.Body.String())
	}
	create := performRequest(handler, http.MethodPost, "/projects", url.Values{"csrf_token": {csrfToken}, "slug": {"demo"}, "displayName": {"Demo"}}, cookie)
	if create.Code != http.StatusSeeOther {
		t.Fatalf("create project = %d: %s", create.Code, create.Body.String())
	}
	instance := url.Values{"csrf_token": {csrfToken}, "key": {"main"}, "displayName": {"主实例"}, "enabled": {"on"}, "localPort": {"8080"}, "denyStatus": {"404"}}
	if response := performRequest(handler, http.MethodPost, "/projects/demo/instances", instance, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("create instance = %d: %s", response.Code, response.Body.String())
	}
	allowlist := url.Values{"csrf_token": {csrfToken}, "cidr": {"203.0.113.10"}, "label": {"出口"}}
	if response := performRequest(handler, http.MethodPost, "/projects/demo/instances/main/allowlist", allowlist, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("create allowlist = %d: %s", response.Code, response.Body.String())
	}
	rule := url.Values{"csrf_token": {csrfToken}, "name": {"账户"}, "methods": {"GET", "HEAD"}, "pathType": {"numeric_segment"}, "pathValue": {"/accounts/{id}"}, "optionalTrailingSlash": {"on"}}
	if response := performRequest(handler, http.MethodPost, "/projects/demo/instances/main/rules", rule, cookie); response.Code != http.StatusSeeOther {
		t.Fatalf("create rule = %d: %s", response.Code, response.Body.String())
	}
	project, err := drafts.Load("demo")
	if err != nil || len(project.Instances) != 1 || len(project.Instances[0].Rules) != 1 || project.Instances[0].Rules[0].Enabled {
		t.Fatalf("draft = %#v, %v", project, err)
	}
	preview := performRequest(handler, http.MethodPost, "/projects/demo/preview", url.Values{"csrf_token": {csrfToken}}, cookie)
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), "projects/demo/instances/main") {
		t.Fatalf("preview = %d: %s", preview.Code, preview.Body.String())
	}
}

func performRequest(handler http.Handler, method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request := httptest.NewRequest(method, path, body)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func extractCSRF(t *testing.T, body string) string {
	t.Helper()
	match := csrfPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("CSRF token not found in %s", body)
	}
	return match[1]
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatalf("cookie %q not found in %#v", name, cookies)
	return nil
}

func validProfileForm(csrfToken string) url.Values {
	return url.Values{
		"csrf_token":        {csrfToken},
		"binaryPath":        {"/usr/sbin/nginx"},
		"configPath":        {"/etc/nginx/nginx.conf"},
		"prefixPath":        {""},
		"serviceName":       {"nginx.service"},
		"httpIncludeFile":   {"/etc/nginx/conf.d/50-nginx-acl-manager.conf"},
		"realIpSnippetPath": {"/etc/nginx/snippets/cloudflare-real-ip.conf"},
	}
}

func testTOTPCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	counter := uint64(now.Unix() / 30)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	digest := hmac.New(sha1.New, decoded)
	_, _ = digest.Write(message[:])
	sum := digest.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}
