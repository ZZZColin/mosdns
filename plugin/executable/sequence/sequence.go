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

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/qtrace" // query_log: tracing hooks
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
)

const PluginType = "sequence"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })

	MustRegExecQuickSetup("accept", setupAccept)
	MustRegExecQuickSetup("reject", setupReject)
	MustRegExecQuickSetup("return", setupReturn)
	MustRegExecQuickSetup("goto", setupGoto)
	MustRegExecQuickSetup("jump", setupJump)
	MustRegMatchQuickSetup("_true", setupTrue) // add _ prefix to avoid being mis-parsed as bool
	MustRegMatchQuickSetup("_false", setupFalse)
}

type Sequence struct {
	tag string // query_log: this Sequence plugin's own tag, used only for tracing/logging.

	chain            []*ChainNode
	anonymousPlugins []any
}

func (s *Sequence) Close() error {
	for _, plugin := range s.anonymousPlugins {
		closePlugin(plugin)
	}
	return nil
}

type Args = []RuleArgs

func Init(bp *coremain.BP, args any) (any, error) {
	s, err := NewSequence(bp, *args.(*Args))
	if err != nil {
		return nil, err
	}
	s.tag = bp.Tag() // query_log: capture the tag this sequence is registered under
	return s, nil
}

func NewSequence(bq BQ, ra []RuleArgs) (*Sequence, error) {
	s := &Sequence{}

	var rc []RuleConfig
	for _, ra := range ra {
		rc = append(rc, parseArgs(ra))
	}
	if err := s.buildChain(bq, rc); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Sequence) Exec(ctx context.Context, qCtx *query_context.Context) error {
	// query_log: mark entry/exit of this sequence so nested $tag calls to
	// other sequences (e.g. a fallback's primary/secondary) show up
	// correctly nested in the trace. This is a no-op unless a query_log
	// plugin has been configured.
	if qtrace.EnterSeq(qCtx, s.tag) {
		defer qtrace.LeaveSeq(qCtx)
	}

	walker := NewChainWalker(s.chain, nil)
	walker.seqTag = s.tag // query_log
	return walker.ExecNext(ctx, qCtx)
}
