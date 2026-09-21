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
	Depth     int           `json:"depth"`   // nesting depth, 0 = top level sequence
	Seq       string        `json:"seq"`     // tag of the sequence this step belongs to
	Name      string        `json:"name"`    // plugin tag ($xxx) or type name that was run
	Kind      string        `json:"kind"`    // "tag" or "type"
	Skipped   bool          `json:"skipped"` // true if this node's matches failed, so it did not run
	Elapsed   time.Duration `json:"-"`
	ElapsedMS float64       `json:"elapsed_ms"`
	Rcode     string        `json:"rcode"`            // response rcode right after this step ran, if any
	Answer    string        `json:"answer,omitempty"` // brief answer summary right after this step ran
	Err       string        `json:"err,omitempty"`    // error returned by this step, if any

	// Children holds everything a concurrent branch recorded about
	// itself (see BeginBranch/EndBranch/RecordBranchStep below), nested
	// under the branch's own marker step instead of being spliced into
	// the parent's Steps list. Empty/omitted for ordinary steps.
	Children []Step `json:"children,omitempty"`
}

// Record is the full trace of one finished query.
type Record struct {
	ID        uint32        `json:"id"`
	Time      time.Time     `json:"time"`
	Client    string        `json:"client,omitempty"`
	Qname     string        `json:"qname"`
	Qtype     string        `json:"qtype"`
	Elapsed   time.Duration `json:"-"`
	ElapsedMS float64       `json:"elapsed_ms"`
	Rcode     string        `json:"rcode"`
	Answer    string        `json:"answer,omitempty"`
	Steps     []Step        `json:"steps"`
}

// Recorder keeps the most recent N finished records in memory.
//
// It is a true fixed-size ring buffer: buf is allocated once at
// capacity, and once full, new records overwrite the oldest slot in
// place instead of growing/reslicing a backing array. This avoids the
// transient ~2x-capacity memory retention that an append+reslice
// "ring buffer" has, since dropped *Record pointers (and everything
// they retain: Steps, Answer, Qname strings) are cleared immediately
// instead of waiting for the backing array to be reallocated.
type Recorder struct {
	mu    sync.Mutex
	cap   int
	buf   []*Record
	head  int
	count int

	// hideClient, when true, makes getOrCreateState skip populating
	// Record.Client, so /api/records never exposes querying client IPs.
	hideClient bool
}

// NewRecorder creates a Recorder that keeps at most capacity records.
// hideClient controls whether Record.Client (the querying client's IP)
// is recorded at all; pass true to keep it out of every record.
func NewRecorder(capacity int, hideClient bool) *Recorder {
	if capacity <= 0 {
		capacity = 200
	}
	return &Recorder{cap: capacity, buf: make([]*Record, capacity), hideClient: hideClient}
}

func (r *Recorder) add(rec *Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := (r.head + r.count) % r.cap
	if r.count < r.cap {
		r.buf[idx] = rec
		r.count++
	} else {
		r.buf[r.head] = rec
		r.head = (r.head + 1) % r.cap
	}
}

// Recent returns up to n most recent records, newest first.
// n <= 0 means "all of them".
func (r *Recorder) Recent(n int) []*Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > r.count {
		n = r.count
	}
	out := make([]*Record, n)
	for i := 0; i < n; i++ {
		idx := (r.head + r.count - 1 - i) % r.cap
		out[i] = r.buf[idx]
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
//
// depth is intentionally NOT a field on state: state is shared (aliased)
// across every qCtx.Copy() of a query, but nesting depth must NOT be
// shared across concurrently-running branches (fallback's primary vs
// secondary, dual_selector's two branches) or their trace indentation
// corrupts each other. depth is instead stored directly in qCtx's own
// kv map (see depthKey below); query_context.Context.CopyTo's copyMap
// gives every qCtx.Copy() its own independent map, so a plain int value
// re-stored there is naturally per-branch instead of shared.
//
// The same problem exists one level up: even with depth fixed, two
// concurrent branches calling RecordStep still append into the SAME
// s.rec.Steps slice, so their steps interleave in whatever order the two
// goroutines happen to acquire state.mu - not in any order that reflects
// which branch a step actually belongs to. sinkKey (see BeginBranch/
// EndBranch below) fixes this the same way depthKey fixes depth: each
// branch gets its own private, per-qCtx-copy slice to append into, and
// only the finished branch's own marker step (via RecordBranchStep) is
// spliced into the shared s.rec.Steps, once, as a single atomic append
// with everything the branch recorded attached as Children.
// ---------------------------------------------------------------------

var stateKey = query_context.RegKey()
var depthKey = query_context.RegKey()
var sinkKey = query_context.RegKey()

type state struct {
	mu   sync.Mutex
	rec  *Record
	done bool
}

func getOrCreateState(qCtx *query_context.Context) *state {
	if v, ok := qCtx.GetValue(stateKey); ok {
		return v.(*state)
	}
	q := qCtx.QQuestion()
	client := ""
	if r := activeRecorder(); r != nil && !r.hideClient {
		client = clientAddrString(qCtx)
	}
	s := &state{
		rec: &Record{
			ID:     qCtx.Id(),
			Time:   qCtx.StartTime(),
			Client: client,
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

func getDepth(qCtx *query_context.Context) int {
	if v, ok := qCtx.GetValue(depthKey); ok {
		return v.(int)
	}
	return 0
}

func setDepth(qCtx *query_context.Context, d int) {
	qCtx.StoreValue(depthKey, d)
}

// currentSink returns whatever step slice new steps on qCtx should be
// appended to right now: a branch-private one if BeginBranch installed
// one on qCtx (or on whatever qCtx this one was itself Copy()'d from,
// since CopyTo carries the same pointer forward), or the query's shared
// s.rec.Steps otherwise.
func currentSink(qCtx *query_context.Context, s *state) *[]Step {
	if v, ok := qCtx.GetValue(sinkKey); ok {
		return v.(*[]Step)
	}
	return &s.rec.Steps
}

// BeginBranch installs a private step buffer on qCtx. Call it on a
// qCtx.Copy() right before handing that copy to one goroutine of a
// concurrent branch (fallback's primary/secondary, dual_selector's two
// lookups, ...). Every RecordStep/RecordStepStart/RecordBranchStep call
// made on that qCtx - or reached through it, however deep - appends into
// this private buffer instead of the shared Record.Steps, so concurrent
// branches never contend for, or interleave into, the same slice.
//
// No-op if tracing is inactive (no query_log plugin configured).
func BeginBranch(qCtx *query_context.Context) {
	if activeRecorder() == nil {
		return
	}
	buf := make([]Step, 0, 4)
	qCtx.StoreValue(sinkKey, &buf)
}

// EndBranch removes the private buffer BeginBranch installed on qCtx and
// returns everything the branch recorded into it. Pass the result to
// RecordBranchStep as that branch's Children.
//
// After EndBranch, further RecordStep-family calls on this same qCtx
// fall back to writing straight into the shared Record.Steps (state
// itself, unlike depth or the branch sink, is shared/aliased across
// every qCtx.Copy() of a query), which is exactly what RecordBranchStep
// relies on to splice the branch's marker step into its parent's list.
func EndBranch(qCtx *query_context.Context) []Step {
	v, ok := qCtx.GetValue(sinkKey)
	if !ok {
		return nil
	}
	qCtx.DeleteValue(sinkKey)
	return *(v.(*[]Step))
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
	done := s.done
	s.mu.Unlock()
	if done {
		return false
	}
	setDepth(qCtx, getDepth(qCtx)+1)
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
	d := getDepth(qCtx) - 1
	setDepth(qCtx, d)
	if d <= 0 {
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

	depth := getDepth(qCtx) - 1
	if depth < 0 {
		depth = 0
	}
	st.Depth = depth

	sink := currentSink(qCtx, s)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	*sink = append(*sink, st)
}

// BranchOrigin captures everything a later RecordBranchStep call needs -
// the query's shared *state, which sink to splice into, and the depth
// the marker step should carry - resolved ONCE, synchronously, from a
// qCtx you currently have exclusive access to (in practice: the shared
// parent qCtx, resolved via NewBranchOrigin before spawning any
// goroutines that race against each other to decide who reports last).
//
// This exists because qCtx itself is NOT safe for concurrent use (its
// own doc comment says so), and a naive "pass the shared parent qCtx to
// whichever goroutine finishes last, and have it call qCtx.GetValue(...)
// then" is exactly the bug this type prevents: if the main call stack
// returns from this plugin's Exec before both branches have reported in
// (very much the common case - e.g. fallback's primary already
// succeeded and secondary never even ran), the enclosing Sequence.Exec's
// deferred qtrace.LeaveSeq(qCtx) writes to that SAME qCtx's kv map
// (via setDepth) with no synchronization against a background branch
// goroutine concurrently reading it via getDepth/currentSink - a real,
// frequently-hit "concurrent map read and map write" crash, not just a
// -race finding.
//
// BranchOrigin has no such problem: once created, it never touches any
// qCtx again. s is a pointer guarded by its own mutex, sink is a pointer
// to a slice variable also only ever mutated under that mutex, and depth
// is a plain int copied by value - none of that requires touching a
// qCtx's kv map, so RecordBranchStep is safe to call from any goroutine,
// at any time, no matter what the qCtx it was resolved from is doing
// concurrently by then.
type BranchOrigin struct {
	s     *state
	sink  *[]Step
	depth int
}

// NewBranchOrigin resolves a BranchOrigin from qCtx. Call it exactly
// once, synchronously, before spawning any goroutines that will
// eventually call RecordBranchStep - see the type's doc comment for why
// that ordering matters. The zero BranchOrigin (returned when tracing is
// inactive) is valid to use; RecordBranchStep on it is simply a no-op.
func NewBranchOrigin(qCtx *query_context.Context) BranchOrigin {
	s := getState(qCtx)
	if s == nil {
		return BranchOrigin{}
	}
	depth := getDepth(qCtx) - 1
	if depth < 0 {
		depth = 0
	}
	return BranchOrigin{s: s, sink: currentSink(qCtx, s), depth: depth}
}

// RecordBranchStep records a marker step for one branch of a concurrent
// operation - fallback's primary/secondary, dual_selector's reference
// check vs. original query - with everything that branch itself recorded
// (via BeginBranch/EndBranch) attached as Children instead of being
// spliced flat into the parent's Steps list.
//
// resp is the branch's own response (its qCtx.R(), read by the caller on
// that branch's own, exclusively-owned qCtx - never through o), or nil.
// Passing it in rather than having RecordBranchStep fetch it avoids the
// same class of cross-goroutine qCtx access BranchOrigin exists to
// avoid, and also avoids a subtler correctness bug: fetching the
// response from a single shared qCtx at flush time would show whichever
// branch's response happened to be set there by then for BOTH branches'
// markers, not each branch's own actual result.
func (o BranchOrigin) RecordBranchStep(seqTag, name, kind string, elapsed time.Duration, resp *dns.Msg, err error, children []Step) {
	if o.s == nil {
		return
	}

	st := Step{
		Seq:       seqTag,
		Name:      name,
		Kind:      kind,
		Elapsed:   elapsed,
		ElapsedMS: ms(elapsed),
		Children:  children,
		Depth:     o.depth,
	}
	if err != nil {
		st.Err = err.Error()
	} else if resp != nil {
		st.Rcode = rcodeString(resp.Rcode)
		st.Answer = summarizeAnswer(resp)
	}

	o.s.mu.Lock()
	defer o.s.mu.Unlock()
	if o.s.done {
		return
	}
	*o.sink = append(*o.sink, st)
}

// RecordStepStart appends a placeholder step for a RecursiveExecutable
// node BEFORE it runs, and returns an index for RecordStepFinish.
//
// RecursiveExecutable nodes (jump, goto, ecs_handler, cache,
// dual_selector's prefer_ipv4/ipv6, ...) call next.ExecNext() themselves
// to continue the rest of the chain BEFORE their own Exec returns. If the
// step were recorded only after Exec returns (as a plain RecordStep call
// would), every step the node triggers downstream would already be in
// Steps by the time this node's own step is appended, so the trace would
// show this node's step AFTER the steps it caused - backwards from what
// actually happened. Reserving the slot up front fixes the ordering.
//
// This does NOT fix elapsed-time double counting: since the node's Exec
// call structurally wraps the rest of the chain, elapsed here still
// includes all downstream execution time. That is inherent to how
// RecursiveExecutable works and cannot be separated without changing
// every RecursiveExecutable implementation to report its own vs.
// downstream time itself.
//
// The returned index is relative to whatever sink is active on qCtx at
// call time (the branch-private one if BeginBranch is active, otherwise
// the shared Record.Steps); RecordStepFinish must be called on the same
// qCtx before anything changes that sink (in practice: before any nested
// BeginBranch on this exact qCtx, which normal chain execution never
// does - BeginBranch is only ever called on a qCtx.Copy()).
//
// A negative returned index means tracing is inactive; pass it to
// RecordStepFinish unchanged, which will then no-op.
func RecordStepStart(qCtx *query_context.Context, seqTag, name, kind string) int {
	s := getState(qCtx)
	if s == nil {
		return -1
	}
	depth := getDepth(qCtx) - 1
	if depth < 0 {
		depth = 0
	}
	sink := currentSink(qCtx, s)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return -1
	}
	*sink = append(*sink, Step{Seq: seqTag, Name: name, Kind: kind, Depth: depth})
	return len(*sink) - 1
}

// RecordStepFinish fills in the outcome of a step previously created by
// RecordStepStart, in place, without moving its position in Steps.
func RecordStepFinish(qCtx *query_context.Context, idx int, elapsed time.Duration, err error) {
	if idx < 0 {
		return
	}
	s := getState(qCtx)
	if s == nil {
		return
	}
	sink := currentSink(qCtx, s)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || idx >= len(*sink) {
		return
	}
	st := &(*sink)[idx]
	st.Elapsed = elapsed
	st.ElapsedMS = ms(elapsed)
	if err != nil {
		st.Err = err.Error()
	} else if resp := qCtx.R(); resp != nil {
		st.Rcode = rcodeString(resp.Rcode)
		st.Answer = summarizeAnswer(resp)
	}
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
