package externalweb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDuplicatePublicBindRejectedBeforeStartingProcesses(t *testing.T) {
	m := Manager{nodes: map[string]Node{"first": {Tag: "first", Listen: "0.0.0.0", Port: 443}}}
	if err := m.Add(Node{Tag: "second", Listen: "127.0.0.1", Port: 443}); err == nil {
		t.Fatal("overlapping public port accepted")
	}
	if m.cmd != nil || len(m.nodes) != 1 {
		t.Fatal("rejected node changed the running frontend set")
	}
}

func TestMissingPythonDoesNotMoveACMEOrPublishReadiness(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	m := Manager{StatusFile: filepath.Join(t.TempDir(), "ready.json")}
	if err := m.Add(Node{Tag: "test", Listen: "127.0.0.1", Port: 8443}); err == nil {
		t.Fatal("missing dependency accepted")
	}
	if m.cmd != nil || m.restore != nil || m.published {
		t.Fatal("failed preflight changed runtime state")
	}
}

func TestStartupFailureSurvivesCleanupAndSuccessClearsIt(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	m := Manager{StatusFile: filepath.Join(t.TempDir(), "ready.json")}
	if err := m.Add(Node{Tag: "test", Listen: "127.0.0.1", Port: 8443}); err == nil {
		t.Fatal("missing dependency accepted")
	}
	m.Close()
	data, err := os.ReadFile(m.failurePath())
	if err != nil {
		t.Fatal(err)
	}
	var failure struct {
		PID   int    `json:"pid"`
		Error string `json:"error"`
	}
	if err = json.Unmarshal(data, &failure); err != nil || failure.PID != os.Getpid() || !strings.Contains(failure.Error, "python3") {
		t.Fatalf("failure state: %s %v", data, err)
	}
	info, err := os.Stat(m.failurePath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("failure state is not private")
	}
	if err = m.publish(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(m.failurePath()); !os.IsNotExist(err) {
		t.Fatal("successful startup retained old failure")
	}
	m.Close()
}
