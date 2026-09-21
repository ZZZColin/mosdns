/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ---------------------------------------------------------------------
 * Modified by ZZZColin to add query tracing hooks (pkg/qtrace).
 *
 * Selector.Exec spawns two goroutines - a "reference check" that probes
 * whether the domain has the preferred record type, and the "original
 * query" that continues the rest of the chain - each on its own
 * qCtx.Copy(). Each branch collects its own steps into a private buffer
 * (qtrace.BeginBranch/EndBranch) instead of writing straight into the
 * shared trace, so the two branches' steps never interleave with each
 * other. On top of that, pairReporter (same pattern as
 * plugin/executable/sequence/fallback/fallback.go) guarantees the two
 * branches' marker steps always land in the shared trace in a FIXED
 * order - reference_check, then original_query - regardless of which
 * goroutine actually finishes first. Neither goroutine blocks waiting
 * for the other; whichever "reports in" second is the one that actually
 * writes both entries to qtrace, back to back, in that fixed order.
 *
 * pairReporter holds a qtrace.BranchOrigin, resolved ONCE up front on
 * the original qCtx before either goroutine starts, rather than the
 * qCtx itself. Selector.Exec routinely returns (e.g. via <-shouldBlock,
 * the instant reference_check finds a match) while original_query is
 * still running in the background; at that point the enclosing
 * RecursiveExecutable machinery in chain.go (RecordStepFinish) and
 * Sequence.Exec's deferred qtrace.LeaveSeq start touching that same
 * qCtx, concurrently with original_query's goroutine if it later calls
 * reportSecond and that turns out to be the one that flushes. qCtx is
 * documented as not safe for concurrent use, so reading from it inside
 * flush() would risk a real "concurrent map read and map write" crash.
 * BranchOrigin (and each branch's own captured *dns.Msg response) never
 * touch qCtx again once resolved, so flush() is safe no matter which
 * goroutine runs it or when.
 *
 * Also re-gofmt'd: earlier edits in this file had mixed tabs and spaces.
 */

package dual_selector

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/qtrace" // query_log: tracing hooks
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	referenceWaitTimeout     = time.Millisecond * 500
	defaultSubRoutineTimeout = time.Second * 5

	// TODO: Make cache configurable?
	cacheSize       = 64 * 1024
	cacheTlt        = time.Hour
	cacheGcInterval = time.Minute
)

func init() {
	sequence.MustRegExecQuickSetup("prefer_ipv4", func(bq sequence.BQ, _ string) (any, error) {
		return NewPreferIpv4(bq), nil
	})
	sequence.MustRegExecQuickSetup("prefer_ipv6", func(bq sequence.BQ, _ string) (any, error) {
		return NewPreferIpv6(bq), nil
	})
}

var _ sequence.RecursiveExecutable = (*Selector)(nil)
var _ io.Closer = (*Selector)(nil)

type Selector struct {
	sequence.BQ
	prefer uint16

	wg               sync.WaitGroup
	preferTypOkCache *cache.Cache[key, bool]
}

// branchOutcome is what one branch (reference_check or original_query)
// collected about itself once it finished: how long it took, its error
// (if any), and everything it recorded internally via
// qtrace.BeginBranch/EndBranch. query_log:
type branchOutcome struct {
	name     string
	elapsed  time.Duration
	resp     *dns.Msg // query_log: this branch's OWN qCtx.R(), captured on its own qCtx
	err      error
	children []qtrace.Step
}

// pairReporter publishes two concurrent branches' qtrace marker steps in
// a fixed order - first, then second - no matter which one actually
// finishes first. See plugin/executable/sequence/fallback/fallback.go
// for the full reasoning; this is the same pattern, duplicated here
// because it is a small, self-contained, unexported type and the two
// packages have no natural common home for it.
//
// origin is a qtrace.BranchOrigin, not a qCtx - see this file's top
// comment for why that distinction matters. query_log:
type pairReporter struct {
	origin qtrace.BranchOrigin
	tag    string

	mu       sync.Mutex
	first    *branchOutcome
	second   *branchOutcome
	firstIn  bool
	secondIn bool
}

func newPairReporter(origin qtrace.BranchOrigin, tag string) *pairReporter {
	return &pairReporter{origin: origin, tag: tag}
}

func (p *pairReporter) reportFirst(o *branchOutcome) {
	p.mu.Lock()
	p.first = o
	p.firstIn = true
	ready := p.secondIn
	p.mu.Unlock()
	if ready {
		p.flush()
	}
}

func (p *pairReporter) reportSecond(o *branchOutcome) {
	p.mu.Lock()
	p.second = o
	p.secondIn = true
	ready := p.firstIn
	p.mu.Unlock()
	if ready {
		p.flush()
	}
}

func (p *pairReporter) flush() {
	if p.first != nil {
		p.origin.RecordBranchStep(p.tag, p.first.name, "branch", p.first.elapsed, p.first.resp, p.first.err, p.first.children)
	}
	if p.second != nil {
		p.origin.RecordBranchStep(p.tag, p.second.name, "branch", p.second.elapsed, p.second.resp, p.second.err, p.second.children)
	}
}

// Exec implements handler.Executable.
func (s *Selector) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	q := qCtx.Q()
	if len(q.Question) != 1 { // skip wired query with multiple questions.
		return next.ExecNext(ctx, qCtx)
	}

	qtype := q.Question[0].Qtype
	// skip queries that have other unrelated types.
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return next.ExecNext(ctx, qCtx)
	}

	qName := key(q.Question[0].Name)
	if qtype == s.prefer {
		err := next.ExecNext(ctx, qCtx)
		if err != nil {
			return err
		}

		if r := qCtx.R(); r != nil && msgAnsHasRR(r, s.prefer) {
			s.preferTypOkCache.Store(qName, true, time.Now().Add(cacheTlt))
		}
		return nil
	}

	// Qtype is not the preferred type.
	preferredTypOk, _, _ := s.preferTypOkCache.Get(qName)
	if preferredTypOk {
		// We know that domain has preferred type so this qtype can be blocked
		// right away.
		r := dnsutils.GenEmptyReply(q, dns.RcodeSuccess)
		qCtx.SetResponse(r)
		return nil
	}

	// async check whether domain has the preferred type
	qCtxPreferred := qCtx.Copy()
	qCtxPreferred.Q().Question[0].Qtype = s.prefer

	ddl, cacheOk := ctx.Deadline()
	if !cacheOk {
		ddl = time.Now().Add(defaultSubRoutineTimeout)
	}

	// query_log: resolved ONCE, synchronously, here - before either
	// goroutine below starts - so pairReporter never has to touch qCtx
	// again from whichever goroutine ends up flushing. See this file's
	// top comment and qtrace.BranchOrigin's doc comment for why.
	origin := qtrace.NewBranchOrigin(qCtx)
	reporter := newPairReporter(origin, next.SeqTag())

	shouldBlock := make(chan struct{})
	shouldPass := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		qCtx := qCtxPreferred
		qtrace.BeginBranch(qCtx) // query_log: give this branch its own step buffer
		ctx, cancel := context.WithDeadline(context.Background(), ddl)
		defer cancel()
		start := time.Now() // query_log
		err := next.ExecNext(ctx, qCtx)
		children := qtrace.EndBranch(qCtx) // query_log: pull out what this branch recorded
		r := qCtx.R()                      // query_log: this branch's own response, captured on its own qCtx
		reporter.reportFirst(&branchOutcome{ // query_log: always slot 1 in the trace
			name:     "reference_check",
			elapsed:  time.Since(start),
			resp:     r,
			err:      err,
			children: children,
		})
		if err != nil {
			s.L().Warn("reference query routine err", qCtx.InfoField(), zap.Error(err))
			close(shouldPass)
			return
		}
		if r != nil && msgAnsHasRR(r, s.prefer) {
			// Target domain has preferred type.
			s.preferTypOkCache.Store(qName, true, time.Now().Add(cacheTlt))
			close(shouldBlock)
			return
		}
		close(shouldPass)
	}()

	// start original query goroutine
	doneChan := make(chan error, 1)
	qCtxOrg := qCtx.Copy()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		qCtx := qCtxOrg
		qtrace.BeginBranch(qCtx) // query_log
		ctx, cancel := context.WithDeadline(context.Background(), ddl)
		defer cancel()
		start := time.Now() // query_log
		err := next.ExecNext(ctx, qCtx)
		children := qtrace.EndBranch(qCtx) // query_log
		r := qCtx.R()                      // query_log: this branch's own response, captured on its own qCtx
		reporter.reportSecond(&branchOutcome{ // query_log: always slot 2 in the trace
			name:     "original_query",
			elapsed:  time.Since(start),
			resp:     r,
			err:      err,
			children: children,
		})
		doneChan <- err
	}()

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-shouldBlock: // Domain has preferred type. Block this type now.
		r := dnsutils.GenEmptyReply(q, dns.RcodeSuccess)
		qCtx.SetResponse(r)
		return nil
	case err := <-doneChan: // The original query finished. Waiting for preferred type check.
		waitTimeoutTimer := pool.GetTimer(referenceWaitTimeout)
		defer pool.ReleaseTimer(waitTimeoutTimer)
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-shouldBlock:
			r := dnsutils.GenEmptyReply(q, dns.RcodeSuccess)
			qCtx.SetResponse(r)
			return nil
		case <-shouldPass:
			*qCtx = *qCtxOrg // replace qCtx
			return err
		case <-waitTimeoutTimer.C:
			// We have been waiting the reference query for too long.
			// Something may go wrong. We accept the original reply.
			*qCtx = *qCtxOrg
			return err
		}
	}
}

func (s *Selector) Close() error {
	s.wg.Wait()
	s.preferTypOkCache.Close()
	return nil
}

func NewPreferIpv4(bq sequence.BQ) *Selector {
	return newSelector(bq, dns.TypeA)
}

func NewPreferIpv6(bq sequence.BQ) *Selector {
	return newSelector(bq, dns.TypeAAAA)
}

func newSelector(bq sequence.BQ, preferType uint16) *Selector {
	if preferType != dns.TypeA && preferType != dns.TypeAAAA {
		panic("dual_selector: invalid dns qtype")
	}
	return &Selector{
		BQ:               bq,
		prefer:           preferType,
		preferTypOkCache: cache.New[key, bool](cache.Opts{Size: cacheSize, CleanerInterval: cacheGcInterval}),
	}
}

func msgAnsHasRR(m *dns.Msg, t uint16) bool {
	if len(m.Answer) == 0 {
		return false
	}

	for _, rr := range m.Answer {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}
