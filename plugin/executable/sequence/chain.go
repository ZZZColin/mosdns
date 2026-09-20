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
 * Modified by ZZZColin to add query tracing hooks (pkg/qtrace) so a
 * query_log plugin can show, for every query, which tag/type ran and
 * what it returned. All additions are marked "query_log:".
 */

package sequence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/qtrace" // query_log: tracing hooks
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
)

type ChainNode struct {
	Matches []Matcher // Can be empty, indicates this node has no match specified.

	// At least one of E or RE must not nil.
	// In case both are set. E is preferred.
	E  Executable
	RE RecursiveExecutable

	// query_log: display name for this node, used only for tracing/logging.
	Name string // plugin tag (if referenced by $tag) or type name
	Kind string // "tag" or "type"
}

type ChainWalker struct {
	p        int
	chain    []*ChainNode
	jumpBack *ChainWalker

	// query_log: tag of the Sequence plugin this walker belongs to.
	// Not part of NewChainWalker's signature so existing external callers
	// keep compiling; it defaults to "" (still functions, just unlabeled
	// in the trace) unless the sequence package itself sets it.
	seqTag string
}

func NewChainWalker(chain []*ChainNode, jumpBack *ChainWalker) ChainWalker {
	return ChainWalker{
		chain:    chain,
		jumpBack: jumpBack,
	}
}

func (w *ChainWalker) ExecNext(ctx context.Context, qCtx *query_context.Context) error {
	p := w.p
	// Evaluate rules' matchers in loop.
checkMatchesLoop:
	for p < len(w.chain) {
		n := w.chain[p]

		for _, match := range n.Matches {
			ok, err := match.Match(ctx, qCtx)
			if err != nil {
				return err
			}
			if !ok {
				// query_log: record that this node was skipped.
				qtrace.RecordStep(qCtx, w.seqTag, n.Name, n.Kind, true, 0, nil)
				// Skip this node if condition was not matched.
				p++
				continue checkMatchesLoop
			}
		}

		// Exec rules' executables in loop, or in stack if it is a recursive executable.
		switch {
		case n.E != nil:
			start := time.Now() // query_log
			err := n.E.Exec(ctx, qCtx)
			qtrace.RecordStep(qCtx, w.seqTag, n.Name, n.Kind, false, time.Since(start), err) // query_log
			if err != nil {
				return err
			}
			p++
			continue
		case n.RE != nil:
			next := ChainWalker{
				p:        p + 1,
				chain:    w.chain,
				jumpBack: w.jumpBack,
				seqTag:   w.seqTag, // query_log: keep the label for the rest of the chain
			}
			start := time.Now()                                                            // query_log
			err := n.RE.Exec(ctx, qCtx, next)                                               // query_log: note this may also run the remainder of the chain
			qtrace.RecordStep(qCtx, w.seqTag, n.Name, n.Kind, false, time.Since(start), err) // query_log
			return err
		default:
			panic("n cannot be executed")
		}
	}

	if w.jumpBack != nil { // End of chain, time to jump back.
		return w.jumpBack.ExecNext(ctx, qCtx)
	}

	// EoC.
	return nil
}

func (w *ChainWalker) nop() bool {
	return w.p >= len(w.chain)
}

func (s *Sequence) buildChain(bq BQ, rs []RuleConfig) error {
	c := make([]*ChainNode, 0, len(rs))
	for ri, r := range rs {
		n, err := s.newNode(bq, r, ri)
		if err != nil {
			return fmt.Errorf("failed to init rule #%d, %w", ri, err)
		}
		c = append(c, n)
	}
	s.chain = c
	return nil
}

func (s *Sequence) newNode(bq BQ, r RuleConfig, ri int) (*ChainNode, error) {
	n := new(ChainNode)

	// init matches
	for mi, mc := range r.Matches {
		m, err := s.newMatcher(bq, mc, ri, mi)
		if err != nil {
			return nil, fmt.Errorf("failed to init matcher #%d, %w", mi, err)
		}
		n.Matches = append(n.Matches, m)
	}

	// init exec
	e, re, err := s.newExec(bq, r, ri)
	if err != nil {
		return nil, fmt.Errorf("failed to init exec, %w", err)
	}
	n.E = e
	n.RE = re

	// query_log: remember how this node was referenced, for display only.
	if len(r.Tag) > 0 {
		n.Name = r.Tag
		n.Kind = "tag"
	} else {
		n.Name = r.Type
		n.Kind = "type"
	}

	return n, nil
}

func (s *Sequence) newMatcher(bq BQ, mc MatchConfig, ri, mi int) (Matcher, error) {
	var m Matcher
	switch {
	case len(mc.Tag) > 0:
		m, _ = bq.M().GetPlugin(mc.Tag).(Matcher)
		if m == nil {
			return nil, fmt.Errorf("can not find matcher %s", mc.Tag)
		}
		if qc, ok := m.(QuickConfigurableMatch); ok {
			v, err := qc.QuickConfigureMatch(mc.Args)
			if err != nil {
				return nil, fmt.Errorf("fail to configure plugin %s, %w", mc.Tag, err)
			}
			m = v
		}

	case len(mc.Type) > 0:
		f := GetMatchQuickSetup(mc.Type)
		if f == nil {
			return nil, fmt.Errorf("invalid matcher type %s", mc.Type)
		}
		p, err := f(NewBQ(bq.M(), bq.L().Named(fmt.Sprintf("r%d.m%d", ri, mi))), mc.Args)
		if err != nil {
			return nil, fmt.Errorf("failed to init matcher, %w", err)
		}
		s.anonymousPlugins = append(s.anonymousPlugins, p)
		m = p
	}
	if m == nil {
		return nil, errors.New("missing args")
	}
	if mc.Reverse {
		m = reverseMatcher(m)
	}
	return m, nil
}

func (s *Sequence) newExec(bq BQ, rc RuleConfig, ri int) (Executable, RecursiveExecutable, error) {
	var exec any
	switch {
	case len(rc.Tag) > 0:
		p := bq.M().GetPlugin(rc.Tag)
		if p == nil {
			return nil, nil, fmt.Errorf("can not find executable %s", rc.Tag)
		}
		if qc, ok := p.(QuickConfigurableExec); ok {
			v, err := qc.QuickConfigureExec(rc.Args)
			if err != nil {
				return nil, nil, fmt.Errorf("fail to configure plugin %s, %w", rc.Tag, err)
			}
			exec = v
		} else {
			exec = p
		}

	case len(rc.Type) > 0:
		f := GetExecQuickSetup(rc.Type)
		if f == nil {
			return nil, nil, fmt.Errorf("invalid executable type %s", rc.Type)
		}
		v, err := f(NewBQ(bq.M(), bq.L().Named(fmt.Sprintf("r%d", ri))), rc.Args)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to init executable, %w", err)
		}
		s.anonymousPlugins = append(s.anonymousPlugins, v)
		exec = v
	default:
		return nil, nil, errors.New("missing args")
	}

	e, _ := exec.(Executable)
	re, _ := exec.(RecursiveExecutable)

	if re == nil && e == nil {
		return nil, nil, errors.New("invalid args, initialized object is not executable")
	}
	return e, re, nil
}

func closePlugin(p any) {
	if c, ok := p.(io.Closer); ok {
		_ = c.Close()
	}
}

func reverseMatcher(m Matcher) Matcher {
	return reverseMatch{m: m}
}

type reverseMatch struct {
	m Matcher
}

func (r reverseMatch) Match(ctx context.Context, qCtx *query_context.Context) (bool, error) {
	ok, err := r.m.Match(ctx, qCtx)
	if err != nil {
		return false, err
	}
	return !ok, nil
}
