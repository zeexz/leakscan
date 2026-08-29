package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildConfig(t *testing.T) {
	// Default args
	cfg := buildConfig([]string{})
	if cfg.TargetPath != "." {
		t.Errorf("Expected target path '.', got %q", cfg.TargetPath)
	}

	// Specified path
	cfg2 := buildConfig([]string{"/custom/path"})
	if cfg2.TargetPath != "/custom/path" {
		t.Errorf("Expected target path '/custom/path', got %q", cfg2.TargetPath)
	}
}

func TestInitCmd(t *testing.T) {
	dir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// Run initCmd
	err = initCmd.RunE(initCmd, []string{})
	if err != nil {
		t.Fatalf("initCmd failed: %v", err)
	}

	// Check that .leakscanner-ignore was created
	ignoreFile := filepath.Join(dir, ".leakscanner-ignore")
	if _, err := os.Stat(ignoreFile); os.IsNotExist(err) {
		t.Errorf(".leakscanner-ignore was not created")
	}

	// Running again should not fail
	err = initCmd.RunE(initCmd, []string{})
	if err != nil {
		t.Fatalf("Second initCmd run failed: %v", err)
	}
}

func TestRootHelpTemplate(t *testing.T) {
	tmpl := lazyVimHelpTemplate()
	if len(tmpl) == 0 {
		t.Errorf("Expected non-empty help template")
	}
}

func TestScanCmd_Execution(t *testing.T) {
	dir := t.TempDir()
	// Plant a secret
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("API_KEY=AKIAIOSFODNN7EXAMPLE123"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test clean terminal run
	cleanDir := t.TempDir()
	formatFlag = "terminal"
	quietFlag = false
	failSeverityFlag = "none"
	var buf bytes.Buffer
	scanCmd.SetOut(&buf)

	err := scanCmd.RunE(scanCmd, []string{cleanDir})
	if err != nil {
		t.Fatalf("scanCmd on clean directory failed: %v", err)
	}
}
