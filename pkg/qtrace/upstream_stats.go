package qtrace

import (
	"sort"
	"sync"
	"sync/atomic"
)

// UpstreamStat holds live counters for one configured forward upstream.
// Counters are plain atomics, so updating them on the query path is cheap
// and does not depend on a query_log recorder being installed.
type UpstreamStat struct {
	Plugin string // tag of the forward plugin that owns this upstream
	Name   string // upstream tag, or its address if no tag was configured
	Addr   string

	queries atomic.Uint64
	errors  atomic.Uint64
}

// IncQuery counts one query sent to this upstream.
func (s *UpstreamStat) IncQuery() { s.queries.Add(1) }

// IncError counts one failed query.
func (s *UpstreamStat) IncError() { s.errors.Add(1) }

// UpstreamSnapshot is the JSON-friendly view of an UpstreamStat.
type UpstreamSnapshot struct {
	Plugin  string `json:"plugin"`
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Queries uint64 `json:"queries"`
	Errors  uint64 `json:"errors"`
}

var (
	upstreamMu  sync.Mutex
	upstreamSet = make(map[*UpstreamStat]struct{})
)

// RegisterUpstream adds an upstream to the global list shown by the
// query_log web UI. Call UnregisterUpstream when the upstream is closed
// (config reload) so stale entries do not pile up.
func RegisterUpstream(plugin, name, addr string) *UpstreamStat {
	s := &UpstreamStat{Plugin: plugin, Name: name, Addr: addr}
	upstreamMu.Lock()
	upstreamSet[s] = struct{}{}
	upstreamMu.Unlock()
	return s
}

// UnregisterUpstream removes s from the global list. Safe to call with nil.
func UnregisterUpstream(s *UpstreamStat) {
	if s == nil {
		return
	}
	upstreamMu.Lock()
	delete(upstreamSet, s)
	upstreamMu.Unlock()
}

// SnapshotUpstreams returns all registered upstreams, ordered by plugin
// tag then name, with their current counters.
func SnapshotUpstreams() []UpstreamSnapshot {
	upstreamMu.Lock()
	out := make([]UpstreamSnapshot, 0, len(upstreamSet))
	for s := range upstreamSet {
		out = append(out, UpstreamSnapshot{
			Plugin:  s.Plugin,
			Name:    s.Name,
			Addr:    s.Addr,
			Queries: s.queries.Load(),
			Errors:  s.errors.Load(),
		})
	}
	upstreamMu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Plugin != out[j].Plugin {
			return out[i].Plugin < out[j].Plugin
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}
