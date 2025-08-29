package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Dependency represents a project dependency
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Vulnerability represents a known vulnerability
type Vulnerability struct {
	Dependency string   `json:"dependency"`
	Version    string   `json:"version"`
	Summary    string   `json:"summary"`
	References []string `json:"references"`
}

// LoadLocalVulnDB loads a local JSON vulnerability database
func LoadLocalVulnDB(path string) ([]Vulnerability, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var vulns []Vulnerability
	err = json.NewDecoder(file).Decode(&vulns)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

// ScanProject scans a directory for dependency files
func ScanProject(path string) ([]Dependency, error) {
	var deps []Dependency
	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch d.Name() {
		case "go.mod":
			fileDeps, _ := parseGoMod(p)
			deps = append(deps, fileDeps...)
		case "package.json":
			fileDeps, _ := parsePackageJSON(p)
			deps = append(deps, fileDeps...)
		case "requirements.txt":
			fileDeps, _ := parseRequirements(p)
			deps = append(deps, fileDeps...)
		}
		return nil
	})
	return deps, err
}

func parseGoMod(path string) ([]Dependency, error) {
	file, _ := os.Open(path)
	defer file.Close()
	var deps []Dependency
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "require") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				deps = append(deps, Dependency{Name: parts[1], Version: parts[2]})
			}
		}
	}
	return deps, nil
}

func parsePackageJSON(path string) ([]Dependency, error) {
	data, _ := os.ReadFile(path)
	var pkg map[string]map[string]string
	json.Unmarshal(data, &pkg)
	var deps []Dependency
	for n, v := range pkg["dependencies"] {
		deps = append(deps, Dependency{Name: n, Version: v})
	}
	for n, v := range pkg["devDependencies"] {
		deps = append(deps, Dependency{Name: n, Version: v})
	}
	return deps, nil
}

func parseRequirements(path string) ([]Dependency, error) {
	file, _ := os.Open(path)
	defer file.Close()
	var deps []Dependency
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "==")
		if len(parts) == 2 {
			deps = append(deps, Dependency{Name: parts[0], Version: parts[1]})
		}
	}
	return deps, nil
}

// CheckVulnsOffline checks dependencies against a local vulnerability DB
func CheckVulnsOffline(deps []Dependency, db []Vulnerability) []string {
	var results []string
	for _, dep := range deps {
		found := false
		msg := fmt.Sprintf("- %s@%s", dep.Name, dep.Version)
		for _, v := range db {
			if v.Dependency == dep.Name && v.Version == dep.Version {
				found = true
				msg += fmt.Sprintf("\n  Vulnerability: %s\n", v.Summary)
				for _, ref := range v.References {
					msg += fmt.Sprintf("    Ref: %s\n", ref)
				}
			}
		}
		if !found {
			msg += "\n  No known vulnerabilities."
		}
		results = append(results, msg)
	}
	return results
}

func main() {
	// Use current directory
	projectPath := "./"

	// Load local vulnerability database
	vulnDB, err := LoadLocalVulnDB("local_vulns.json")
	if err != nil {
		fmt.Println("Error loading local vulnerability database:", err)
		return
	}

	// Scan project dependencies
	deps, err := ScanProject(projectPath)
	if err != nil {
		fmt.Println("Error scanning project:", err)
		return
	}

	fmt.Printf("Found %d dependencies:\n", len(deps))

	// Check offline for vulnerabilities
	results := CheckVulnsOffline(deps, vulnDB)
	for _, res := range results {
		fmt.Println(res)
	}
}
