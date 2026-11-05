// Package externalweb supervises an optional OpenSSL/HAProxy TLS terminator
// and nginx website. The children belong to the V2bX service, not the host's
// nginx/haproxy system services, and are never installed or enabled here.
package externalweb

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/common/port80"
)

//go:embed supervisor.py
var supervisor []byte

type Node struct {
	Tag              string `json:"tag"`
	Listen           string `json:"listen"`
	Port             uint16 `json:"port"`
	Backend          uint16 `json:"backend"`
	HTTP1            uint16 `json:"http1"`
	HTTP2            uint16 `json:"http2"`
	Certificate      string `json:"certificate"`
	Key              string `json:"key"`
	Root             string `json:"root"`
	Domain           string `json:"domain"`
	RejectUnknownSNI bool   `json:"reject_unknown_sni"`
}

// Ports allocates distinct ephemeral loopback ports. The listeners are bound
// by V2bX/nginx immediately after planning and never exposed publicly.
func Ports() (backend, h1, h2 uint16, err error) {
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	ports := []*uint16{&backend, &h1, &h2}
	for _, port := range ports {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			err = e
			return
		}
		listeners = append(listeners, l)
		*port = uint16(l.Addr().(*net.TCPAddr).Port)
	}
	return
}

type Manager struct {
	// HTTPListen defaults to :80; tests can use an unprivileged loopback port.
	HTTPListen string
	StatusFile string
	mu         sync.Mutex
	nodes      map[string]Node
	dir        string
	acme       string
	restore    func()
	cmd        *exec.Cmd
	done       chan error
	generation uint64
	published  bool
}

func (m *Manager) Add(node Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nodes == nil {
		m.nodes = make(map[string]Node)
	}
	if _, exists := m.nodes[node.Tag]; exists {
		return fmt.Errorf("external frontend already exists")
	}
	for _, existing := range m.nodes {
		if existing.Port == node.Port && (existing.Listen == node.Listen || existing.Listen == "0.0.0.0" || node.Listen == "0.0.0.0" || existing.Listen == "::" || node.Listen == "::") {
			return fmt.Errorf("external frontend public port is already owned by another node")
		}
	}
	if m.cmd == nil {
		if err := m.start(); err != nil {
			m.recordFailure(err)
			return err
		}
	}
	m.nodes[node.Tag] = node
	err := m.update()
	if err == nil {
		err = m.publish()
	}
	if err != nil {
		m.recordFailure(err)
		delete(m.nodes, node.Tag)
		if len(m.nodes) == 0 {
			m.close()
		} else {
			_ = m.update()
		}
		return err
	}
	return nil
}

func (m *Manager) Remove(tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[tag]; !ok {
		return nil
	}
	delete(m.nodes, tag)
	if len(m.nodes) == 0 {
		m.close()
		return nil
	}
	if err := m.update(); err != nil {
		return err
	}
	return m.publish()
}

func (m *Manager) start() error {
	python, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("external frontend requires python3, haproxy and nginx; install them using the configuration wizard: %w", err)
	}
	m.dir, err = os.MkdirTemp("", "v2bx-web-")
	if err != nil {
		return err
	}
	if err = os.Chmod(m.dir, 0755); err != nil {
		os.RemoveAll(m.dir)
		return err
	}
	if err = os.WriteFile(filepath.Join(m.dir, "supervisor.py"), supervisor, 0600); err != nil {
		os.RemoveAll(m.dir)
		return err
	}
	m.acme, m.restore, err = port80.MoveToLoopback()
	if err != nil {
		os.RemoveAll(m.dir)
		return err
	}
	m.cmd = exec.Command(python, filepath.Join(m.dir, "supervisor.py"), m.dir)
	m.cmd.Stdout, m.cmd.Stderr = os.Stdout, os.Stderr
	if err = m.cmd.Start(); err != nil {
		m.cmd = nil
		m.close()
		return err
	}
	m.done = make(chan error, 1)
	cmd := m.cmd
	go func() { m.done <- cmd.Wait() }()
	return nil
}

func (m *Manager) update() error {
	m.generation++
	nodes := make([]Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodes = append(nodes, n)
	}
	manifest := struct {
		Generation uint64 `json:"generation"`
		ACME       string `json:"acme"`
		Nodes      []Node `json:"nodes"`
		HTTPListen string `json:"http_listen,omitempty"`
	}{m.generation, m.acme, nodes, m.HTTPListen}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	p := filepath.Join(m.dir, "manifest.json")
	if err = os.WriteFile(p+".tmp", data, 0600); err != nil {
		return err
	}
	if err = os.Rename(p+".tmp", p); err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-m.done:
			m.done <- e
			return fmt.Errorf("external web supervisor exited: %v", e)
		default:
		}
		if data, e := os.ReadFile(filepath.Join(m.dir, "status.json")); e == nil {
			var status struct {
				Generation uint64 `json:"generation"`
				Error      string `json:"error"`
			}
			if json.Unmarshal(data, &status) == nil && status.Generation == m.generation {
				if status.Error != "" {
					return fmt.Errorf("external frontend: %s", status.Error)
				}
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("external frontend did not become ready within 20 seconds")
}

func (m *Manager) Close() { m.mu.Lock(); defer m.mu.Unlock(); m.close() }

func (m *Manager) statusPath() string {
	if m.StatusFile != "" {
		return m.StatusFile
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return "/run/V2bX/external-web-ready.json"
	}
	return filepath.Join(m.dir, "ready.json")
}

func (m *Manager) publish() error {
	path := m.statusPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(struct {
		PID   int `json:"pid"`
		Nodes int `json:"nodes"`
	}{os.Getpid(), len(m.nodes)})
	if err != nil {
		return err
	}
	if err = os.WriteFile(path+".tmp", data, 0600); err != nil {
		return err
	}
	if err = os.Rename(path+".tmp", path); err != nil {
		return err
	}
	m.published = true
	os.Remove(m.failurePath())
	return nil
}

func (m *Manager) failurePath() string {
	return strings.TrimSuffix(m.statusPath(), ".json") + ".error.json"
}

// Keep startup errors outside the temporary child directory so the wizard
// can report a definitive failure even after this process has exited.
func (m *Manager) recordFailure(failure error) {
	if m.StatusFile == "" && m.dir == "" && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
		return
	}
	path := m.failurePath()
	if os.MkdirAll(filepath.Dir(path), 0700) != nil {
		return
	}
	data, err := json.Marshal(struct {
		PID   int    `json:"pid"`
		Error string `json:"error"`
	}{os.Getpid(), failure.Error()})
	if err != nil {
		return
	}
	if os.WriteFile(path+".tmp", data, 0600) == nil {
		_ = os.Rename(path+".tmp", path)
	}
}

func (m *Manager) close() {
	if m.published {
		os.Remove(m.statusPath())
		m.published = false
	}
	if m.cmd != nil {
		_ = m.cmd.Process.Signal(os.Interrupt)
		select {
		case <-m.done:
		case <-time.After(5 * time.Second):
			_ = m.cmd.Process.Kill()
			<-m.done
		}
		m.cmd = nil
	}
	if m.restore != nil {
		m.restore()
		m.restore = nil
	}
	if m.dir != "" {
		os.RemoveAll(m.dir)
		m.dir = ""
	}
	m.nodes = nil
}
