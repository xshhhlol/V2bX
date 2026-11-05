package externalweb

import "testing"

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
	var m Manager
	if err := m.Add(Node{Tag: "test", Listen: "127.0.0.1", Port: 8443}); err == nil {
		t.Fatal("missing dependency accepted")
	}
	if m.cmd != nil || m.restore != nil || m.published {
		t.Fatal("failed preflight changed runtime state")
	}
}
