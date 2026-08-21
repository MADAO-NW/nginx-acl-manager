package web

import (
	"context"
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
