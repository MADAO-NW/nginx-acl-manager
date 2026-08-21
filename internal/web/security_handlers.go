package web

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"nginx-acl-manager/internal/auth"
)

const (
	// totpIssuer 是写入认证器 provisioning URI 的固定产品标识。
	totpIssuer = "Nginx ACL Manager"
	// totpQRCodeSize 保持安全设置页现有二维码显示尺寸。
	totpQRCodeSize = 180
)

type securityStatusResponse struct {
	Username         string `json:"username"`
	TwoFactorEnabled bool   `json:"twoFactorEnabled"`
	CSRFToken        string `json:"csrfToken"`
}

type totpSetupResponse struct {
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioningUri"`
	QRCodeDataURL   string `json:"qrCodeDataUrl"`
}

type securityMutationResponse struct {
	Status string `json:"status"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type securityPageData struct {
	CSRFToken        string
	Username         string
	TwoFactorEnabled bool
}

func (s *server) handleSecuritySettingsPage(w http.ResponseWriter, r *http.Request) {
	if s.securityCredentials == nil {
		http.Error(w, "安全设置尚未配置", http.StatusServiceUnavailable)
		return
	}
	_, csrfToken, _ := s.currentSession(r)
	s.render(w, http.StatusOK, "security_settings.html", securityPageData{
		CSRFToken:        csrfToken,
		Username:         s.securityCredentials.Username(),
		TwoFactorEnabled: s.securityCredentials.TOTPSecret() != "",
	})
}

func (s *server) handleLoginTOTPPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_, csrfToken, ok := s.pendingSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login.html", loginPageData{CSRFToken: csrfToken, TwoFactorRequired: true})
}

func (s *server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	sessionID, csrfToken, ok := s.pendingSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !sameToken(csrfToken, r.FormValue("csrf_token")) {
		http.Error(w, "登录请求已失效，请刷新页面重试", http.StatusBadRequest)
		return
	}
	if s.securityCredentials == nil || s.totpState == nil {
		http.Error(w, "TOTP 登录尚未配置", http.StatusServiceUnavailable)
		return
	}
	secret := s.securityCredentials.TOTPSecret()
	if secret == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	rateKey := loginRateKey(r, s.securityCredentials.Username(), "totp")
	if !s.totpState.VerifyAndConsume(secret, r.FormValue("code")) {
		s.sleep(s.loginLimiter.Failure(rateKey))
		s.render(w, http.StatusUnauthorized, "login.html", loginPageData{
			CSRFToken:         csrfToken,
			Error:             "动态验证码错误",
			TwoFactorRequired: true,
		})
		return
	}
	s.loginLimiter.Success(rateKey)
	newSessionID, _, promoted, err := s.sessions.PromotePending(sessionID)
	if err != nil {
		s.logger.Error("轮换 TOTP 登录 Session 失败", "error", err)
		http.Error(w, "暂时无法登录", http.StatusInternalServerError)
		return
	}
	if !promoted {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.setCookie(w, sessionCookieName, newSessionID, true)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleCancelLoginTOTP(w http.ResponseWriter, r *http.Request) {
	sessionID, csrfToken, ok := s.pendingSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !sameToken(csrfToken, r.FormValue("csrf_token")) {
		http.Error(w, "登录请求已失效，请刷新页面重试", http.StatusBadRequest)
		return
	}
	s.sessions.Delete(sessionID)
	s.deleteCookie(w, sessionCookieName, true)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	if s.securityCredentials == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "安全设置尚未配置"})
		return
	}
	_, csrfToken, _ := s.currentSession(r)
	writeJSON(w, http.StatusOK, securityStatusResponse{
		Username:         s.securityCredentials.Username(),
		TwoFactorEnabled: s.securityCredentials.TOTPSecret() != "",
		CSRFToken:        csrfToken,
	})
}

func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.securityReady(w) {
		return
	}
	if !s.verifyCurrentPassword(r) {
		s.securityFailure(w, r, "当前密码错误")
		return
	}
	newPassword := r.FormValue("newPassword")
	if newPassword != r.FormValue("confirmPassword") {
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse{Error: "两次输入的新密码不一致"})
		return
	}
	passwordHash, err := auth.HashPassword(newPassword)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse{Error: err.Error()})
		return
	}
	candidate := auth.Candidate{
		Action:              auth.CandidateChangePassword,
		ExpectedFingerprint: s.securityCredentials.Fingerprint(),
		PasswordHash:        passwordHash,
	}
	if err := s.applyCredentialCandidate(r, candidate); err != nil {
		s.logger.Error("应用密码变更失败", "error", err)
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: "暂时无法修改密码"})
		return
	}
	writeJSON(w, http.StatusAccepted, securityMutationResponse{Status: "applied"})
}

func (s *server) handleSetupTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.securityReady(w) {
		return
	}
	if s.securityCredentials.TOTPSecret() != "" {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "双因素认证已经启用"})
		return
	}
	if !s.verifyCurrentPassword(r) {
		s.securityFailure(w, r, "当前密码错误")
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		s.logger.Error("生成 TOTP 密钥失败", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "暂时无法开始双因素认证设置"})
		return
	}
	uri, err := auth.ProvisioningURI(totpIssuer, s.securityCredentials.Username(), secret)
	if err != nil {
		s.logger.Error("生成 TOTP provisioning URI 失败", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "暂时无法开始双因素认证设置"})
		return
	}
	qrCodeDataURL, err := generateTOTPQRCodeDataURL(uri)
	if err != nil {
		s.logger.Error("生成 TOTP 二维码失败", "error", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "暂时无法生成双因素认证二维码"})
		return
	}
	sessionID, _, _ := s.currentSession(r)
	s.pendingTOTPMu.Lock()
	s.pendingTOTP[sessionID] = secret
	s.pendingTOTPMu.Unlock()
	writeJSON(w, http.StatusOK, totpSetupResponse{
		Secret:          secret,
		ProvisioningURI: uri,
		QRCodeDataURL:   qrCodeDataURL,
	})
}

// generateTOTPQRCodeDataURL 使用标准 QR 编码器生成不依赖外部服务的内嵌 PNG。
func generateTOTPQRCodeDataURL(provisioningURI string) (string, error) {
	png, err := qrcode.Encode(provisioningURI, qrcode.Medium, totpQRCodeSize)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

func (s *server) handleEnableTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.securityReady(w) {
		return
	}
	if s.securityCredentials.TOTPSecret() != "" {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "双因素认证已经启用"})
		return
	}
	sessionID, _, _ := s.currentSession(r)
	s.pendingTOTPMu.Lock()
	secret := s.pendingTOTP[sessionID]
	s.pendingTOTPMu.Unlock()
	if secret == "" {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "请先重新生成双因素认证配置"})
		return
	}
	step, ok := auth.VerifyTOTP(secret, r.FormValue("code"), time.Now(), -1)
	if !ok {
		s.securityFailure(w, r, "动态验证码错误")
		return
	}
	candidate := auth.Candidate{
		Action:              auth.CandidateEnableTOTP,
		ExpectedFingerprint: s.securityCredentials.Fingerprint(),
		TOTPSecret:          secret,
		TOTPInitialStep:     step,
	}
	if err := s.applyCredentialCandidate(r, candidate); err != nil {
		s.logger.Error("启用 TOTP 失败", "error", err)
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: "暂时无法启用双因素认证"})
		return
	}
	writeJSON(w, http.StatusAccepted, securityMutationResponse{Status: "applied"})
}

func (s *server) handleDisableTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.securityReady(w) {
		return
	}
	secret := s.securityCredentials.TOTPSecret()
	if secret == "" {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "双因素认证尚未启用"})
		return
	}
	if !s.verifyCurrentPassword(r) {
		s.securityFailure(w, r, "当前密码错误")
		return
	}
	if s.totpState == nil || !s.totpState.VerifyAndConsume(secret, r.FormValue("code")) {
		s.securityFailure(w, r, "动态验证码错误")
		return
	}
	candidate := auth.Candidate{
		Action:              auth.CandidateDisableTOTP,
		ExpectedFingerprint: s.securityCredentials.Fingerprint(),
	}
	if err := s.applyCredentialCandidate(r, candidate); err != nil {
		s.logger.Error("停用 TOTP 失败", "error", err)
		writeJSON(w, http.StatusBadGateway, errorResponse{Error: "暂时无法停用双因素认证"})
		return
	}
	writeJSON(w, http.StatusAccepted, securityMutationResponse{Status: "applied"})
}

func (s *server) securityReady(w http.ResponseWriter) bool {
	if s.securityCredentials == nil || s.authChangeTrigger == nil || s.authCandidatePath == "" {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "安全设置尚未配置"})
		return false
	}
	return true
}

func (s *server) verifyCurrentPassword(r *http.Request) bool {
	rateKey := loginRateKey(r, s.securityCredentials.Username(), "security")
	verified := s.securityCredentials.Verify(s.securityCredentials.Username(), r.FormValue("currentPassword"))
	if verified {
		s.loginLimiter.Success(rateKey)
	}
	return verified
}

func (s *server) securityFailure(w http.ResponseWriter, r *http.Request, message string) {
	s.sleep(s.loginLimiter.Failure(loginRateKey(r, s.securityCredentials.Username(), "security")))
	writeJSON(w, http.StatusUnauthorized, errorResponse{Error: message})
}

func (s *server) applyCredentialCandidate(r *http.Request, candidate auth.Candidate) error {
	s.authChangeMu.Lock()
	defer s.authChangeMu.Unlock()
	if err := auth.SaveCandidate(s.authCandidatePath, candidate); err != nil {
		return err
	}
	if err := s.authChangeTrigger.Trigger(r.Context()); err != nil {
		return err
	}
	s.loginLimiter.Success(loginRateKey(r, s.securityCredentials.Username(), "security"))
	s.sessions.DeleteAll()
	s.pendingTOTPMu.Lock()
	clear(s.pendingTOTP)
	s.pendingTOTPMu.Unlock()
	return nil
}

func loginRateKey(r *http.Request, account, stage string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host + "\x00" + account + "\x00" + stage
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
