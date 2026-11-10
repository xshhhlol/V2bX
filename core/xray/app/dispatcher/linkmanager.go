package dispatcher

import (
	sync "sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type ManagedWriter struct {
	writer  buf.Writer
	manager *LinkManager
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	return common.Close(w.writer)
}

type LinkManager struct {
	links  map[*ManagedWriter]buf.Reader
	mu     sync.Mutex
	closed bool
}

func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		common.Close(writer)
		common.Interrupt(reader)
		return
	}
	m.links[writer] = reader
	m.mu.Unlock()
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.links, writer)
}

func (m *LinkManager) CloseAll() {
	m.mu.Lock()
	m.closed = true
	links := m.links
	m.links = nil
	m.mu.Unlock()
	// Closing a ManagedWriter calls RemoveWriter; do not hold mu here.
	for w, r := range links {
		common.Close(w)
		common.Interrupt(r)
	}
}
