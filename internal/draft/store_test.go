package draft

import (
	"path/filepath"
	"sync"
	"testing"

	"nginx-acl-manager/internal/model"
)

func TestUpdateKeepsConcurrentChanges(t *testing.T) {
	t.Parallel()
	store := Store{Directory: filepath.Join(t.TempDir(), "projects")}
	if err := store.Create(model.Project{Slug: "demo", DisplayName: "Demo", Instances: []model.Instance{}}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	var group sync.WaitGroup
	for _, key := range []string{"one", "two"} {
		key := key
		group.Add(1)
		go func() {
			defer group.Done()
			err := store.Update("demo", func(project *model.Project) error {
				project.Instances = append(project.Instances, model.Instance{Key: key, DisplayName: key, LocalPort: 8000, DenyStatus: 403, AllowedCIDRs: []model.AllowlistEntry{}, Rules: []model.Rule{}})
				return nil
			})
			if err != nil {
				t.Errorf("Update(%s) error = %v", key, err)
			}
		}()
	}
	group.Wait()
	project, err := store.Load("demo")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(project.Instances) != 2 {
		t.Fatalf("instances = %#v", project.Instances)
	}
}
