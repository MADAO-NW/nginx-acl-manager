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
	"nginx-acl-manager/internal/nginxprofile"
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

func TestAllowedHost(t *testing.T) {
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
		AllowedHost:  "127.0.0.1:7582",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.Host = "attacker.example"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("untrusted host = %d", response.Code)
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
