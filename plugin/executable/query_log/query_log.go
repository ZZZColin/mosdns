// Package query_log implements a "query_log" mosdns plugin.
//
// It does not sit in any sequence itself. Simply adding one instance of
// it anywhere in the config's plugins list turns on tracing for every
// query processed by every `sequence` plugin (main, primary_seq, etc.),
// and serves a small built-in web page showing, for each query, which
// tag/type ran, what it returned, and what ran next - all the way to
// the final answer.
//
// Example config:
//
//	- tag: query_log
//	  type: query_log
//	  args:
//	    listen: "0.0.0.0:9092"
//	    max_records: 300
package query_log

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/qtrace"
)

const PluginType = "query_log"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	// Listen is the address the built-in web page listens on.
	// Default ":9092".
	Listen string `yaml:"listen"`

	// MaxRecords is how many recent queries are kept in memory.
	// Default 200.
	MaxRecords int `yaml:"max_records"`
}

type QueryLog struct {
	rec *qtrace.Recorder
	srv *http.Server
	ln  net.Listener
}

func Init(bp *coremain.BP, args any) (any, error) {
	a := args.(*Args)
	if len(a.Listen) == 0 {
		a.Listen = ":9092"
	}

	rec := qtrace.NewRecorder(a.MaxRecords)
	if !qtrace.SetGlobalRecorder(rec) {
		return nil, fmt.Errorf("query_log: a query_log plugin is already running, only one instance is supported")
	}

	ln, err := net.Listen("tcp", a.Listen)
	if err != nil {
		qtrace.ClearGlobalRecorder(rec)
		return nil, fmt.Errorf("query_log: failed to listen on %s: %w", a.Listen, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/records", func(w http.ResponseWriter, r *http.Request) {
		handleAPIRecords(w, r, rec)
	})

	srv := &http.Server{Handler: mux}
	q := &QueryLog{rec: rec, srv: srv, ln: ln}

	go func() {
		bp.L().Sugar().Infof("query_log: web ui listening on %s", a.Listen)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			bp.L().Sugar().Errorf("query_log: http server exited: %v", err)
		}
	}()

	return q, nil
}

func (q *QueryLog) Close() error {
	qtrace.ClearGlobalRecorder(q.rec)
	return q.srv.Close()
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func handleAPIRecords(w http.ResponseWriter, r *http.Request, rec *qtrace.Recorder) {
	n := 200
	if s := r.URL.Query().Get("n"); len(s) > 0 {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			n = v
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"records": rec.Recent(n),
	})
}
