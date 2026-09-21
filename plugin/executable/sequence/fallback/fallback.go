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
 * Why this file needs its own hooks (unlike most other plugins):
 * fallback runs its primary and secondary branches concurrently, each on
 * its own qCtx.Copy(). If the secondary happens to be a plain plugin
 * (e.g. "forward_remote" referenced directly, not through a sequence),
 * it never passes through sequence/chain.go's ExecNext, so it would
 * otherwise be invisible in the query log. All additions are marked
 * "query_log:".
 *
 * Each branch collects its own steps into a private buffer
 * (qtrace.BeginBranch/EndBranch) instead of writing straight into the
 * shared trace, so the two branches' steps never interleave with each
 * other. On top of that, pairReporter guarantees the two branches'
 * marker steps always land in the shared trace in a FIXED order -
 * primary, then secondary - regardless of which goroutine actually
 * finishes first. Neither goroutine ever blocks waiting for the other:
 * each just "reports in" the instant it is done (or, for a secondary
 * that never ran because primary already succeeded, reports in with a
 * nil outcome so primary's own report is never left waiting forever);
 * whichever report call turns out to be the second one to arrive is the
 * one that actually writes both entries to qtrace, back to back, in
 * that fixed order.
 *
 * pairReporter deliberately holds a qtrace.BranchOrigin, resolved ONCE
 * up front on the original qCtx before either goroutine starts, rather
 * than the qCtx itself. doFallback can (and very often does - primary
 * succeeding fast is the common case) return before both branches have
 * reported in, at which point the enclosing Sequence.Exec's deferred
 * qtrace.LeaveSeq(qCtx) starts writing to that same qCtx concurrently
 * with whichever branch goroutine is still running. qCtx is documented
 * as not safe for concurrent use, so a flush() that read from it here
 * would risk a real "concurrent map read and map write" crash - not a
 * rare corner case, but the everyday "secondary got skipped" path.
 * BranchOrigin (and each branch's own captured *dns.Msg response) never
 * touch qCtx again once resolved, so flush() is safe no matter which
 * goroutine runs it or when.
 */

package fallback

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/qtrace" // query_log: tracing hooks
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "fallback"

const (
	defaultParallelTimeout   = time.Second * 5
	defaultFallbackThreshold = time.Millisecond * 500
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type fallback struct {
	tag           string // query_log: this plugin's own tag, for tracing/logging
	primaryName   string // query_log: args.Primary, for tracing/logging
	secondaryName string // query_log: args.Secondary, for tracing/logging

	logger               *zap.Logger
	primary              sequence.Executable
	secondary            sequence.Executable
	fastFallbackDuration time.Duration
	alwaysStandby        bool
}

type Args struct {
	// Primary exec sequence.
	Primary string `yaml:"primary"`
	// Secondary exec sequence.
	Secondary string `yaml:"secondary"`

	// Threshold in milliseconds. Default is 500.
	Threshold int `yaml:"threshold"`

	// AlwaysStandby: secondary should always stand by in fallback.
	AlwaysStandby bool `yaml:"always_standby"`
}

func Init(bp *coremain.BP, args any) (any, error) {
	return newFallbackPlugin(bp, args.(*Args))
}

func newFallbackPlugin(bp *coremain.BP, args *Args) (*fallback, error) {
	if len(args.Primary) == 0 || len(args.Secondary) == 0 {
		return nil, errors.New("args missing primary or secondary")
	}

	pe := sequence.ToExecutable(bp.M().GetPlugin(args.Primary))
	if pe == nil {
		return nil, fmt.Errorf("can not find primary executable %s", args.Primary)
	}
	se := sequence.ToExecutable(bp.M().GetPlugin(args.Secondary))
	if se == nil {
		return nil, fmt.Errorf("can not find secondary executable %s", args.Secondary)
	}
	threshold := time.Duration(args.Threshold) * time.Millisecond
	if threshold <= 0 {
		threshold = defaultFallbackThreshold
	}

	s := &fallback{
		tag:                  bp.Tag(),       // query_log
		primaryName:          args.Primary,   // query_log
		secondaryName:        args.Secondary, // query_log
		logger:               bp.L(),
		primary:              pe,
		secondary:            se,
		fastFallbackDuration: threshold,
		alwaysStandby:        args.AlwaysStandby,
	}
	return s, nil
}

var (
	ErrFailed = errors.New("no valid response from both primary and secondary")
)

var _ sequence.Executable = (*fallback)(nil)

func (f *fallback) Exec(ctx context.Context, qCtx *query_context.Context) error {
	return f.doFallback(ctx, qCtx)
}

// branchOutcome is what one branch (primary or secondary) collected
// about itself once it finished: how long it took, its error (if any),
// and everything it recorded internally via qtrace.BeginBranch/EndBranch.
// query_log:
type branchOutcome struct {
	name     string
	elapsed  time.Duration
	resp     *dns.Msg // query_log: this branch's OWN qCtx.R(), captured on its own qCtx
	err      error
	children []qtrace.Step
}

// pairReporter publishes two concurrent branches' qtrace marker steps in
// a fixed order - first, then second - no matter which one actually
// finishes first. reportFirst/reportSecond never block: each just
// records its own outcome (nil is a valid outcome, meaning "this branch
// never ran") and, if the other side has already reported in, performs
// the actual qtrace writes; otherwise it returns immediately and leaves
// the writing to whichever call arrives second. Exactly one of the two
// calls ever sees "the other side is ready", since both checks happen
// under the same mutex, so flush() runs exactly once.
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

func (f *fallback) doFallback(ctx context.Context, qCtx *query_context.Context) error {
	respChan := make(chan *dns.Msg, 2) // resp could be nil.
	primFailed := make(chan struct{})
	primDone := make(chan struct{})

	// query_log: resolved ONCE, synchronously, here - before either
	// goroutine below starts - so pairReporter never has to touch qCtx
	// again from whichever goroutine ends up flushing. See this file's
	// top comment and qtrace.BranchOrigin's doc comment for why.
	origin := qtrace.NewBranchOrigin(qCtx)
	reporter := newPairReporter(origin, f.tag)

	// primary goroutine.
	qCtxP := qCtx.Copy()
	go func() {
		qCtx := qCtxP
		qtrace.BeginBranch(qCtx) // query_log: give this branch its own step buffer
		ctx, cancel := makeDdlCtx(ctx, defaultParallelTimeout)
		defer cancel()
		start := time.Now() // query_log
		err := f.primary.Exec(ctx, qCtx)
		children := qtrace.EndBranch(qCtx) // query_log: pull out what this branch recorded
		r := qCtx.R()                      // query_log: this branch's own response, captured on its own qCtx
		reporter.reportFirst(&branchOutcome{ // query_log: always slot 1 in the trace
			name:     "primary: " + f.primaryName,
			elapsed:  time.Since(start),
			resp:     r,
			err:      err,
			children: children,
		})
		if err != nil {
			f.logger.Warn("primary error", qCtx.InfoField(), zap.Error(err))
		}

		if err != nil || r == nil {
			close(primFailed)
			respChan <- nil
		} else {
			close(primDone)
			respChan <- r
		}
	}()

	// Secondary goroutine.
	qCtxS := qCtx.Copy()
	go func() {
		timer := pool.GetTimer(f.fastFallbackDuration)
		defer pool.ReleaseTimer(timer)
		if !f.alwaysStandby { // not always standby, wait here.
			select {
			case <-primDone: // primary is done, no need to exec this.
				// query_log: secondary never ran, but it still has to
				// "report in" (with nothing to add) so primary's own
				// report is never left waiting on a branch that will
				// never call in.
				reporter.reportSecond(nil)
				return
			case <-primFailed: // primary failed
			case <-timer.C: // timed out
			}
		}

		qCtx := qCtxS
		qtrace.BeginBranch(qCtx) // query_log
		ctx, cancel := makeDdlCtx(ctx, defaultParallelTimeout)
		defer cancel()
		start := time.Now() // query_log
		err := f.secondary.Exec(ctx, qCtx)
		children := qtrace.EndBranch(qCtx) // query_log
		r := qCtx.R()                      // query_log: this branch's own response, captured on its own qCtx
		reporter.reportSecond(&branchOutcome{ // query_log: always slot 2 in the trace
			name:     "secondary: " + f.secondaryName,
			elapsed:  time.Since(start),
			resp:     r,
			err:      err,
			children: children,
		})
		if err != nil {
			f.logger.Warn("secondary error", qCtx.InfoField(), zap.Error(err))
			respChan <- nil
			return
		}

		// always standby is enabled. Wait until secondary resp is needed.
		if f.alwaysStandby && r != nil {
			select {
			case <-ctx.Done():
			case <-primDone:
			case <-primFailed: // only send secondary result when primary is failed.
			case <-timer.C: // or timed out.
			}
		}
		respChan <- r
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case r := <-respChan:
			if r == nil { // One of goroutines finished but failed.
				continue
			}
			qCtx.SetResponse(r)
			return nil
		}
	}

	// All goroutines finished but failed.
	return ErrFailed
}

func makeDdlCtx(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	ddl, ok := ctx.Deadline()
	if !ok {
		ddl = time.Now().Add(timeout)
	}
	return context.WithDeadline(ctx, ddl)
}
