package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"nginx-acl-manager/internal/draft"
	"nginx-acl-manager/internal/generator"
	"nginx-acl-manager/internal/model"
	"nginx-acl-manager/internal/release"
	"nginx-acl-manager/internal/validation"
)

type projectPageData struct {
	CSRFToken       string
	Project         model.Project
	History         []release.Manifest
	CurrentRevision string
	Message         string
	Error           string
	PublishResult   *release.Result
}

type previewPageData struct {
	CSRFToken string
	Project   model.Project
	Files     generator.FileSet
	Diff      string
	Warnings  []string
}

type newProjectPageData struct {
	CSRFToken string
	Error     string
}

func (s *server) handleNewProjectPage(w http.ResponseWriter, r *http.Request) {
	if !s.projectFeaturesReady(w) {
		return
	}
	_, csrfToken, _ := s.currentSession(r)
	s.render(w, http.StatusOK, "new_project.html", newProjectPageData{
		CSRFToken: csrfToken,
	})
}

func (s *server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	if !s.projectFeaturesReady(w) {
		return
	}
	project := model.Project{Slug: r.FormValue("slug"), DisplayName: r.FormValue("displayName"), Instances: []model.Instance{}}
	if err := s.drafts.Create(project); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/projects/"+project.Slug+"?created=1", http.StatusSeeOther)
}

func (s *server) handleProject(w http.ResponseWriter, r *http.Request) {
	if !s.projectFeaturesReady(w) {
		return
	}
	_, csrfToken, _ := s.currentSession(r)
	data, err := s.loadProjectPage(r.PathValue("slug"), csrfToken)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, draft.ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	switch {
	case r.URL.Query().Get("created") == "1":
		data.Message = "项目草稿已创建"
	case r.URL.Query().Get("saved") == "1":
		data.Message = "草稿已保存，发布后才会影响 Nginx"
	case r.URL.Query().Get("publish") == "1":
		data.Message = "已触发 root 发布，请稍后刷新查看发布结果"
	case r.URL.Query().Get("restore") == "1":
		data.Message = "已按历史项目快照触发新版本发布"
	}
	s.render(w, http.StatusOK, "project.html", data)
}

func (s *server) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	err := s.drafts.Update(slug, func(project *model.Project) error {
		project.DisplayName = r.FormValue("displayName")
		return nil
	})
	s.redirectAfterMutation(w, r, slug, err)
}

func (s *server) handleCreateInstance(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	port, err := strconv.Atoi(r.FormValue("localPort"))
	if err != nil {
		http.Error(w, "本地端口格式无效", http.StatusUnprocessableEntity)
		return
	}
	denyStatus, err := strconv.Atoi(r.FormValue("denyStatus"))
	if err != nil {
		http.Error(w, "拒绝状态格式无效", http.StatusUnprocessableEntity)
		return
	}
	instance := model.Instance{
		Key: r.FormValue("key"), DisplayName: r.FormValue("displayName"), Enabled: r.FormValue("enabled") != "",
		LocalPort: port, ServerName: r.FormValue("serverName"), DenyStatus: denyStatus,
		AllowedCIDRs: []model.AllowlistEntry{}, Rules: []model.Rule{},
	}
	err = s.drafts.Update(slug, func(project *model.Project) error {
		for _, existing := range project.Instances {
			if existing.Key == instance.Key {
				return errors.New("实例标识已存在")
			}
		}
		project.Instances = append(project.Instances, instance)
		return nil
	})
	s.redirectAfterMutation(w, r, slug, err)
}

func (s *server) handleUpdateInstance(w http.ResponseWriter, r *http.Request) {
	slug, key := r.PathValue("slug"), r.PathValue("key")
	err := s.drafts.Update(slug, func(project *model.Project) error {
		index := instanceIndex(project, key)
		if index < 0 {
			return errors.New("实例不存在")
		}
		port, err := strconv.Atoi(r.FormValue("localPort"))
		if err != nil {
			return errors.New("本地端口格式无效")
		}
		denyStatus, err := strconv.Atoi(r.FormValue("denyStatus"))
		if err != nil {
			return errors.New("拒绝状态格式无效")
		}
		instance := &project.Instances[index]
		instance.DisplayName = r.FormValue("displayName")
		instance.Enabled = r.FormValue("enabled") != ""
		instance.LocalPort = port
		instance.ServerName = r.FormValue("serverName")
		instance.DenyStatus = denyStatus
		return nil
	})
	s.redirectAfterMutation(w, r, slug, err)
}

func (s *server) handleCreateAllowlist(w http.ResponseWriter, r *http.Request) {
	slug, key := r.PathValue("slug"), r.PathValue("key")
	cidr, err := validation.NormalizeCIDR(r.FormValue("cidr"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	id, err := newStableID()
	if err != nil {
		http.Error(w, "无法生成白名单标识", http.StatusInternalServerError)
		return
	}
	err = s.drafts.Update(slug, func(project *model.Project) error {
		index := instanceIndex(project, key)
		if index < 0 {
			return errors.New("实例不存在")
		}
		project.Instances[index].AllowedCIDRs = append(project.Instances[index].AllowedCIDRs, model.AllowlistEntry{ID: id, CIDR: cidr, Label: r.FormValue("label")})
		return nil
	})
	s.redirectAfterMutation(w, r, slug, err)
}

func (s *server) handleUpdateAllowlist(w http.ResponseWriter, r *http.Request) {
	slug, key, id := r.PathValue("slug"), r.PathValue("key"), r.PathValue("id")
	action := r.FormValue("action")
	err := s.drafts.Update(slug, func(project *model.Project) error {
		instancePosition := instanceIndex(project, key)
		if instancePosition < 0 {
			return errors.New("实例不存在")
		}
		entries := project.Instances[instancePosition].AllowedCIDRs
		index := slices.IndexFunc(entries, func(entry model.AllowlistEntry) bool { return entry.ID == id })
		if index < 0 {
			return errors.New("白名单条目不存在")
		}
		if action == "delete" {
			project.Instances[instancePosition].AllowedCIDRs = slices.Delete(entries, index, index+1)
			return nil
		}
		cidr, err := validation.NormalizeCIDR(r.FormValue("cidr"))
		if err != nil {
			return err
		}
		entries[index].CIDR = cidr
		entries[index].Label = r.FormValue("label")
		project.Instances[instancePosition].AllowedCIDRs = entries
		return nil
	})
	s.redirectAfterMutation(w, r, slug, err)
}

func (s *server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	slug, key := r.PathValue("slug"), r.PathValue("key")
	id, err := newStableID()
	if err != nil {
		http.Error(w, "无法生成规则标识", http.StatusInternalServerError)
		return
	}
	rule := ruleFromRequest(r, id, false)
	err = s.drafts.Update(slug, func(project *model.Project) error {
		index := instanceIndex(project, key)
		if index < 0 {
			return errors.New("实例不存在")
		}
		project.Instances[index].Rules = append(project.Instances[index].Rules, rule)
		return nil
	})
	s.redirectAfterMutation(w, r, slug, err)
}

func (s *server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	slug, key, id := r.PathValue("slug"), r.PathValue("key"), r.PathValue("id")
	action := r.FormValue("action")
	err := s.drafts.Update(slug, func(project *model.Project) error {
		instancePosition := instanceIndex(project, key)
		if instancePosition < 0 {
			return errors.New("实例不存在")
		}
		rules := project.Instances[instancePosition].Rules
		index := slices.IndexFunc(rules, func(rule model.Rule) bool { return rule.ID == id })
		if index < 0 {
			return errors.New("规则不存在")
		}
		switch action {
		case "delete":
			project.Instances[instancePosition].Rules = slices.Delete(rules, index, index+1)
		case "enable":
			rules[index].Enabled = true
		case "disable":
			rules[index].Enabled = false
		default:
			rules[index] = ruleFromRequest(r, id, rules[index].Enabled)
		}
		return nil
	})
	s.redirectAfterMutation(w, r, slug, err)
}

func (s *server) handlePreviewProject(w http.ResponseWriter, r *http.Request) {
	project, err := s.drafts.Load(r.PathValue("slug"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	candidate, err := s.releases.PrepareProjectCandidate(project, "publish")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	files, diff, err := s.releases.Preview(candidate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_, csrfToken, _ := s.currentSession(r)
	s.render(w, http.StatusOK, "preview.html", previewPageData{CSRFToken: csrfToken, Project: project, Files: files, Diff: diff, Warnings: projectWarnings(project)})
}

func (s *server) handlePublishProject(w http.ResponseWriter, r *http.Request) {
	if s.publishTrigger == nil {
		http.Error(w, "发布服务尚未配置", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.profiles.LoadActive(); err != nil {
		http.Error(w, "请先验证并应用 Nginx 设置", http.StatusConflict)
		return
	}
	s.publishMu.Lock()
	defer s.publishMu.Unlock()
	project, err := s.drafts.Load(r.PathValue("slug"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	candidate, err := s.releases.PrepareProjectCandidate(project, "publish")
	if err == nil {
		err = s.releases.SaveCandidate(candidate)
	}
	if err == nil {
		err = s.publishTrigger.Trigger(r.Context())
	}
	if err != nil {
		http.Error(w, "无法启动 root 发布: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/projects/"+project.Slug+"?publish=1", http.StatusSeeOther)
}

func (s *server) handleRestoreProject(w http.ResponseWriter, r *http.Request) {
	if s.publishTrigger == nil {
		http.Error(w, "发布服务尚未配置", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.profiles.LoadActive(); err != nil {
		http.Error(w, "请先验证并应用 Nginx 设置", http.StatusConflict)
		return
	}
	s.publishMu.Lock()
	defer s.publishMu.Unlock()
	candidate, err := s.releases.PrepareRestoreCandidate(r.PathValue("slug"), r.PathValue("revision"))
	if err == nil {
		err = s.releases.SaveCandidate(candidate)
	}
	if err == nil {
		err = s.publishTrigger.Trigger(r.Context())
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/projects/"+r.PathValue("slug")+"?restore=1", http.StatusSeeOther)
}

func (s *server) loadProjectPage(slug, csrfToken string) (projectPageData, error) {
	project, err := s.drafts.Load(slug)
	if err != nil {
		return projectPageData{}, err
	}
	history, err := s.releases.ListManifests()
	if err != nil && !errors.Is(err, release.ErrNoCurrent) {
		return projectPageData{}, err
	}
	filtered := make([]release.Manifest, 0)
	for _, manifest := range history {
		projects, loadErr := s.releases.LoadRevisionProjects(manifest.Revision)
		if loadErr != nil {
			return projectPageData{}, loadErr
		}
		if slices.ContainsFunc(projects, func(item model.Project) bool { return item.Slug == slug }) {
			filtered = append(filtered, manifest)
		}
	}
	current, _ := s.releases.CurrentRevision()
	data := projectPageData{CSRFToken: csrfToken, Project: project, History: filtered, CurrentRevision: current}
	if result, resultErr := s.releases.LoadResult(); resultErr == nil && result.Project == slug {
		data.PublishResult = &result
	}
	return data, nil
}

func (s *server) redirectAfterMutation(w http.ResponseWriter, r *http.Request, slug string, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/projects/"+slug+"?saved=1", http.StatusSeeOther)
}

func (s *server) projectFeaturesReady(w http.ResponseWriter) bool {
	if s.drafts.Directory == "" || s.releases.AccessControlRoot == "" {
		http.Error(w, "项目功能尚未配置", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func instanceIndex(project *model.Project, key string) int {
	return slices.IndexFunc(project.Instances, func(instance model.Instance) bool { return instance.Key == key })
}

func ruleFromRequest(r *http.Request, id string, enabled bool) model.Rule {
	_ = r.ParseForm()
	return model.Rule{
		ID: id, Name: r.FormValue("name"), Enabled: enabled, Methods: r.Form["methods"],
		Path: model.RulePath{Type: r.FormValue("pathType"), Value: r.FormValue("pathValue"), OptionalTrailingSlash: r.FormValue("optionalTrailingSlash") != ""},
	}
}

func newStableID() (string, error) {
	data := make([]byte, 12)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func projectWarnings(project model.Project) []string {
	warnings := []string{}
	for _, instance := range project.Instances {
		if !instance.Enabled || !slices.ContainsFunc(instance.Rules, func(rule model.Rule) bool { return rule.Enabled }) {
			continue
		}
		if slices.ContainsFunc(instance.AllowedCIDRs, func(entry model.AllowlistEntry) bool { return entry.CIDR == "0.0.0.0/0" }) {
			warnings = append(warnings, fmt.Sprintf("%s：全部 IPv4 来源均可访问已启用的受保护接口", instance.DisplayName))
		}
		if len(instance.AllowedCIDRs) == 0 {
			warnings = append(warnings, fmt.Sprintf("%s：白名单为空，所有来源命中规则时都会被拒绝", instance.DisplayName))
		}
	}
	return warnings
}

func methodChecked(methods []string, method string) bool {
	return slices.Contains(methods, method)
}
