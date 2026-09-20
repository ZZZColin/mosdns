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
 */

package fallback

import (
	"context"
	"errors"
	"fmt"
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
	tag                  string // query_log: this plugin's own tag, for tracing/logging
	primaryName          string // query_log: args.Primary, for tracing/logging
	secondaryName        string // query_log: args.Secondary, for tracing/logging

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
		tag:                  bp.Tag(),        // query_log
		primaryName:          args.Primary,    // query_log
		secondaryName:        args.Secondary,  // query_log
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

func (f *fallback) doFallback(ctx context.Context, qCtx *query_context.Context) error {
	respChan := make(chan *dns.Msg, 2) // resp could be nil.
	primFailed := make(chan struct{})
	primDone := make(chan struct{})

	// primary goroutine.
	qCtxP := qCtx.Copy()
	go func() {
		qCtx := qCtxP
		ctx, cancel := makeDdlCtx(ctx, defaultParallelTimeout)
		defer cancel()
		start := time.Now()                     // query_log
		err := f.primary.Exec(ctx, qCtx)
		// query_log: record this branch even if primaryName is itself a
		// sequence (whose own internal steps are already traced by
		// sequence.go) - this line just marks where the fallback picked it.
		qtrace.RecordStep(qCtx, f.tag, "primary: "+f.primaryName, "branch", false, time.Since(start), err) // query_log
		if err != nil {
			f.logger.Warn("primary error", qCtx.InfoField(), zap.Error(err))
		}

		r := qCtx.R()
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
				return
			case <-primFailed: // primary failed
			case <-timer.C: // timed out
			}
		}

		qCtx := qCtxS
		ctx, cancel := makeDdlCtx(ctx, defaultParallelTimeout)
		defer cancel()
		start := time.Now() // query_log
		err := f.secondary.Exec(ctx, qCtx)
		qtrace.RecordStep(qCtx, f.tag, "secondary: "+f.secondaryName, "branch", false, time.Since(start), err) // query_log
		if err != nil {
			f.logger.Warn("secondary error", qCtx.InfoField(), zap.Error(err))
			respChan <- nil
			return
		}

		r := qCtx.R()
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
	return context.WithDeadline(context.Background(), ddl)
}
