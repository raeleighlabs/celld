package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArguments(t *testing.T) {
	token := strings.Repeat("a", 64)
	_, command, err := arguments([]string{"--release", releasePath, "--token", token, "--", "/app", "flag"})
	if err != nil || len(command) != 2 || command[0] != "/app" || command[1] != "flag" {
		t.Fatalf("command mismatch: %v %v", command, err)
	}
	if _, _, err := arguments([]string{"--release", releasePath, "--token", token, "--", "/app"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"--release", releasePath, "--token", token, "--"},
		{"--release", "/arbitrary", "--token", token, "--", "/app", "flag"},
		{"--release", releasePath, "--token", "invalid", "--", "/app", "flag"}} {
		if _, _, err := arguments(args); err == nil {
			t.Fatal("invalid gate arguments accepted")
		}
	}
}

func TestReleaseIsExactAndBounded(t *testing.T) {
	token := strings.Repeat("b", 64)
	path := filepath.Join(t.TempDir(), "release")
	for _, content := range []string{"0" + token + "\n", "1" + strings.Repeat("c", 64) + "\n", "1" + token, "1" + token + "\nextra"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := waitRelease(path, token, time.Time{}); err == nil {
			t.Fatal("unreleased or malformed file authorised execution")
		}
	}
	if err := os.WriteFile(path, []byte("1"+token+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := waitRelease(path, token, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}
