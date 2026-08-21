package release

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"nginx-acl-manager/internal/generator"
)

// UnifiedDiff 生成稳定、逐文件的完整 unified diff。
func UnifiedDiff(oldFiles, newFiles generator.FileSet) string {
	pathSet := make(map[string]struct{}, len(oldFiles)+len(newFiles))
	for path := range oldFiles {
		pathSet[path] = struct{}{}
	}
	for path := range newFiles {
		pathSet[path] = struct{}{}
	}
	paths := make([]string, 0, len(pathSet))
	for path := range pathSet {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	var result strings.Builder
	for _, path := range paths {
		oldContent, oldExists := oldFiles[path]
		newContent, newExists := newFiles[path]
		if string(oldContent) == string(newContent) && oldExists == newExists {
			continue
		}
		fmt.Fprintf(&result, "--- a/%s\n+++ b/%s\n", path, path)
		oldLines := splitLines(oldContent)
		newLines := splitLines(newContent)
		fmt.Fprintf(&result, "@@ -1,%d +1,%d @@\n", len(oldLines), len(newLines))
		for _, line := range oldLines {
			fmt.Fprintf(&result, "-%s\n", line)
		}
		for _, line := range newLines {
			fmt.Fprintf(&result, "+%s\n", line)
		}
	}
	return result.String()
}

func splitLines(content []byte) []string {
	trimmed := strings.TrimSuffix(string(content), "\n")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "\n")
}

func readGeneratedFiles(root string) (generator.FileSet, error) {
	files := generator.FileSet{}
	err := filepath.WalkDir(filepath.Join(root, "projects"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".conf" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = content
		return nil
	})
	if os.IsNotExist(err) {
		return files, nil
	}
	return files, err
}
