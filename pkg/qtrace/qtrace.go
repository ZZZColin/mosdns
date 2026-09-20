// Package qtrace records, per DNS query, which sequence/plugin tags were
// executed and what each one returned, so a web UI can show the full
// resolution path (which tag ran, what result, which tag ran next, ...).
//
// It is designed to be zero-cost when no query_log plugin is configured:
// every hook first checks the global recorder pointer and returns
// immediately if it is nil.
package qtrace

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

// Step describes one node (one "- matches / exec" rule) that a sequence
// attempted to run.
type Step struct {
	Depth   int           `json:"depth"`   // nesting depth, 0 = top level sequence
	Seq     string        `json:"seq"`     // tag of the sequence this step belongs to
	Name    string        `json:"name"`    // plugin tag ($xxx) or type name that was run
	Kind    string        `json:"kind"`    // "tag" or "type"
	Skipped bool          `json:"skipped"` // true if this node's matches failed, so it did not run
	Elapsed time.Duration `json:"-"`
	ElapsedMS float64     `json:"elapsed_ms"`
	Rcode   string        `json:"rcode"`             // response rcode right after this step ran, if any
	Answer  string        `json:"answer,omitempty"`  // brief answer summary right after this step ran
	Err     string        `json:"err,omitempty"`     // error returned by this step, if any
}

// Record is the full trace of one finished query.
type Record struct {
	ID        uint32    `json:"id"`
	Time      time.Time `json:"time"`
	Client    string    `json:"client,omitempty"`
	Qname     string    `json:"qname"`
	Qtype     string    `json:"qtype"`
	Elapsed   time.Duration `json:"-"`
	ElapsedMS float64   `json:"elapsed_ms"`
	Rcode     string    `json:"rcode"`
	Answer    string    `json:"answer,omitempty"`
	Steps     []Step    `json:"steps"`
}

// Recorder keeps the most recent N finished records in memory (ring buffer).
type Recorder struct {
	mu   sync.Mutex
	cap  int
	recs []*Record
}

// NewRecorder creates a Recorder that keeps at most capacity records.
func NewRecorder(capacity int) *Recorder {
	if capacity <= 0 {
		capacity = 200
	}
	return &Recorder{cap: capacity}
}

func (r *Recorder) add(rec *Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
	if len(r.recs) > r.cap {
		r.recs = r.recs[len(r.recs)-r.cap:]
	}
}

// Recent returns up to n most recent records, newest first.
// n <= 0 means "all of them".
func (r *Recorder) Recent(n int) []*Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := len(r.recs)
	if n <= 0 || n > total {
		n = total
	}
	out := make([]*Record, n)
	for i := 0; i < n; i++ {
		out[i] = r.recs[total-1-i]
	}
	return out
}

// ---------------------------------------------------------------------
// global recorder: installed once by the query_log plugin.
// ---------------------------------------------------------------------

var globalRecorder atomic.Pointer[Recorder]

// SetGlobalRecorder installs r as the recorder that sequence/chain hooks
// report to. Only the query_log plugin should call this, and only once.
// It returns false if a recorder has already been installed.
func SetGlobalRecorder(r *Recorder) bool {
	return globalRecorder.CompareAndSwap(nil, r)
}

// ClearGlobalRecorder removes the currently installed recorder, if it is r.
// Used by query_log's Close() so a config reload can install a fresh one.
func ClearGlobalRecorder(r *Recorder) {
	globalRecorder.CompareAndSwap(r, nil)
}

func activeRecorder() *Recorder {
	return globalRecorder.Load()
}

// ---------------------------------------------------------------------
// per-query state, stashed on the query_context.Context itself so there
// is no separate global map to leak or to lock across queries.
//
// IMPORTANT: mosdns's fallback plugin runs its primary/secondary branches
// concurrently, each on its own qCtx.Copy(). Context.CopyTo shallow-copies
// the kv map, so both copies end up pointing at the SAME *state value
// (state is a pointer stored as the map value). That means EnterSeq/
// LeaveSeq/RecordStep can legitimately be called from two goroutines at
// once for the same query, so every field access below is protected by
// state.mu. Once a record has been handed to the Recorder (done==true),
// further calls become no-ops so a slow, already-abandoned branch can
// never mutate a Record that the HTTP handler may be reading/encoding
// concurrently.
// ---------------------------------------------------------------------

var stateKey = query_context.RegKey()

type state struct {
	mu    sync.Mutex
	rec   *Record
	depth int
	done  bool
}

func getOrCreateState(qCtx *query_context.Context) *state {
	if v, ok := qCtx.GetValue(stateKey); ok {
		return v.(*state)
	}
	q := qCtx.QQuestion()
	s := &state{
		rec: &Record{
			ID:     qCtx.Id(),
			Time:   qCtx.StartTime(),
			Client: clientAddrString(qCtx),
			Qname:  q.Name,
			Qtype:  dns.TypeToString[q.Qtype],
		},
	}
	qCtx.StoreValue(stateKey, s)
	return s
}

func getState(qCtx *query_context.Context) *state {
	if v, ok := qCtx.GetValue(stateKey); ok {
		return v.(*state)
	}
	return nil
}

func clientAddrString(qCtx *query_context.Context) string {
	if a := qCtx.ServerMeta.ClientAddr; a.IsValid() {
		return a.String()
	}
	return ""
}

// EnterSeq must be called at the start of a Sequence's Exec.
// It returns true when a global recorder is active and tracing for this
// query has not finished yet; in that case the caller MUST defer
// LeaveSeq(qCtx).
func EnterSeq(qCtx *query_context.Context, seqTag string) bool {
	if activeRecorder() == nil {
		return false
	}
	s := getOrCreateState(qCtx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return false
	}
	s.depth++
	return true
}

// LeaveSeq must be deferred right after a successful EnterSeq call.
// When the outermost sequence returns, the finished record is handed to
// the global recorder.
func LeaveSeq(qCtx *query_context.Context) {
	s := getState(qCtx)
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	s.depth--
	finalize := s.depth <= 0
	s.mu.Unlock()
	if finalize {
		finish(qCtx, s)
	}
}

func finish(qCtx *query_context.Context, s *state) {
	r := activeRecorder()
	if r == nil {
		return
	}
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	rec := s.rec
	rec.Elapsed = time.Since(qCtx.StartTime())
	rec.ElapsedMS = ms(rec.Elapsed)
	if resp := qCtx.R(); resp != nil {
		rec.Rcode = rcodeString(resp.Rcode)
		rec.Answer = summarizeAnswer(resp)
	} else {
		rec.Rcode = "(no response)"
	}
	s.done = true
	s.mu.Unlock()

	r.add(rec)
	qCtx.DeleteValue(stateKey)
}

// RecordStep records the outcome of one sequence node (one rule), or of
// any other plugin invocation a patch chooses to instrument directly
// (e.g. the fallback plugin's primary/secondary branches).
// skipped=true means the node's matches did not pass, so it never ran.
func RecordStep(qCtx *query_context.Context, seqTag, name, kind string, skipped bool, elapsed time.Duration, err error) {
	s := getState(qCtx)
	if s == nil {
		return
	}

	st := Step{
		Seq:       seqTag,
		Name:      name,
		Kind:      kind,
		Skipped:   skipped,
		Elapsed:   elapsed,
		ElapsedMS: ms(elapsed),
	}
	if err != nil {
		st.Err = err.Error()
	} else if !skipped {
		if resp := qCtx.R(); resp != nil {
			st.Rcode = rcodeString(resp.Rcode)
			st.Answer = summarizeAnswer(resp)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	depth := s.depth - 1
	if depth < 0 {
		depth = 0
	}
	st.Depth = depth
	s.rec.Steps = append(s.rec.Steps, st)
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func rcodeString(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return "RCODE" + itoa(rcode)
}

func summarizeAnswer(m *dns.Msg) string {
	if len(m.Answer) == 0 {
		return ""
	}
	rr := m.Answer[0]
	var s string
	switch v := rr.(type) {
	case *dns.A:
		s = v.A.String()
	case *dns.AAAA:
		s = v.AAAA.String()
	case *dns.CNAME:
		s = "CNAME " + v.Target
	default:
		s = dns.TypeToString[rr.Header().Rrtype]
	}
	if n := len(m.Answer); n > 1 {
		s = s + " (+" + itoa(n-1) + ")"
	}
	return s
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
