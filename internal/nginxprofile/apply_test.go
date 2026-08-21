package nginxprofile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateProtectedParentStopsAtNearestExistingDirectory(t *testing.T) {
	t.Parallel()

	worldWritable := filepath.Join(t.TempDir(), "world-writable")
	if err := os.Mkdir(worldWritable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldWritable, 0o777); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(worldWritable, "protected")
	if err := os.Mkdir(protected, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := validateProtectedParent(filepath.Join(protected, "missing"), -1, -1); err != nil {
		t.Fatalf("安全的最近父目录不应受更上层目录影响: %v", err)
	}
	if err := os.Chmod(protected, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateProtectedParent(filepath.Join(protected, "missing"), -1, -1); err == nil {
		t.Fatal("最近父目录可被任意用户写入时应拒绝")
	}
}
