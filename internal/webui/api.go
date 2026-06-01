package webui

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/conantorreswf/limithit/internal/attacks"
	_ "github.com/conantorreswf/limithit/internal/attacks/all" // register all attack implementations
	"github.com/conantorreswf/limithit/internal/client"
	"github.com/conantorreswf/limithit/internal/metrics"
	"github.com/conantorreswf/limithit/internal/safety"
)

// attackMeta is the JSON shape returned by GET /api/attacks.
type attackMeta struct {
	Name     string      `json:"name"`
	Synopsis string      `json:"synopsis"`
	Fields   []fieldMeta `json:"fields"`
}

type fieldMeta struct {
	Flag    string   `json:"flag"`
	Label   string   `json:"label"`
	Help    string   `json:"help,omitempty"`
	Default string   `json:"default"`
	Kind    string   `json:"kind"`
	Choices []string `json:"choices,omitempty"`
}

// runRequest is the JSON body for POST /api/run.
type runRequest struct {
	Attack string            `json:"attack"`
	Flags  map[string]string `json:"flags"`
}

// donePayload wraps the final report sent in the "done" SSE event.
type donePayload struct {
	Type      string          `json:"type"`
	Report    json.RawMessage `json:"report"`
	FuzzRunID string          `json:"fuzz_run_id,omitempty"`
}

func handleAttacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	all := attacks.All()
	out := make([]attackMeta, 0, len(all))
	for _, a := range all {
		out = append(out, attackMeta{
			Name:     a.Name(),
			Synopsis: a.Synopsis(),
			Fields:   toFieldMeta(a.FormFields()),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req runRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	a, ok := attacks.Lookup(req.Attack)
	if !ok {
		http.Error(w, "unknown attack: "+req.Attack, http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	// Parse common + attack-specific flags from the request map.
	fs := flag.NewFlagSet(req.Attack, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		urlFlag     = fs.String("url", "", "")
		total       = fs.Int("total", 100, "")
		concurrency = fs.Int("concurrency", 10, "")
		timeoutSec  = fs.Int("timeout", 10, "")
		keepalive   = fs.Bool("keepalive", true, "")
	)
	a.Flags(fs)

	args := flagsToArgs(req.Flags)
	if err := fs.Parse(args); err != nil {
		sseError(w, flusher, "flags: "+err.Error())
		return
	}
	if err := a.Validate(); err != nil {
		sseError(w, flusher, "validate: "+err.Error())
		return
	}

	// Safety: i-understand passed as a flag value in the map.
	iUnderstand, _ := strconv.ParseBool(req.Flags["i-understand"])
	if err := safety.Confirm(req.Attack, *urlFlag, safety.Opts{IUnderstand: iUnderstand}, io.Discard); err != nil {
		sseError(w, flusher, err.Error())
		return
	}

	timeout := time.Duration(*timeoutSec) * time.Second
	progressCh := make(chan metrics.Progress, 8)

	attackCtx, attackCancel := context.WithCancel(r.Context())
	defer attackCancel()

	base := attacks.Base{
		URL: *urlFlag,
		Client: client.New(client.Config{
			Timeout:           timeout,
			DisableKeepAlives: !*keepalive,
		}, *concurrency),
		Common: attacks.CommonOpts{
			Total:       *total,
			Concurrency: *concurrency,
			Timeout:     timeout,
		},
		ProgressCh: progressCh,
	}

	type result struct {
		rep attacks.Report
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		rep, err := a.Run(attackCtx, base)
		resultCh <- result{rep, err}
	}()

	for {
		select {
		case p := <-progressCh:
			sseProgress(w, flusher, p)

		case res := <-resultCh:
			// Run() returned; safe to close the channel and drain.
			close(progressCh)
			for p := range progressCh {
				sseProgress(w, flusher, p)
			}
			if res.err != nil {
				sseError(w, flusher, res.err.Error())
				return
			}
			sseDone(w, flusher, res.rep)
			return

		case <-r.Context().Done():
			attackCancel()
			res := <-resultCh
			close(progressCh)
			_ = res
			sseError(w, flusher, "cancelled")
			return
		}
	}
}

// sseProgress emits a "progress" SSE event.
func sseProgress(w io.Writer, f http.Flusher, p metrics.Progress) {
	data, _ := json.Marshal(p)
	fmt.Fprintf(w, "event: progress\ndata: %s\n\n", data)
	f.Flush()
}

// sseDone emits a "done" SSE event with the full report.
func sseDone(w io.Writer, f http.Flusher, rep attacks.Report) {
	var payload donePayload
	switch rep.(type) {
	case *metrics.Report:
		payload.Type = "http"
	case *metrics.ConnReport:
		payload.Type = "conn"
	default:
		payload.Type = "unknown"
	}

	buf, err := json.Marshal(rep)
	if err != nil {
		buf = []byte(`{}`)
	}

	// For fuzz: persist routes to SQLite, strip path_status from SSE payload.
	if r, ok := rep.(*metrics.Report); ok && r.Attack == "fuzz" && len(r.PathStatus) > 0 && globalFuzzDB != nil {
		runID := newRunID()
		_ = globalFuzzDB.clearDB()
		_ = globalFuzzDB.saveRoutes(runID, r.PathStatus)
		payload.FuzzRunID = runID
		var raw map[string]json.RawMessage
		if json.Unmarshal(buf, &raw) == nil {
			delete(raw, "path_status")
			if b, err := json.Marshal(raw); err == nil {
				buf = b
			}
		}
	}

	payload.Report = json.RawMessage(buf)
	data, _ := json.Marshal(payload)
	fmt.Fprintf(w, "event: done\ndata: %s\n\n", data)
	f.Flush()
}

func handleFuzzRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if globalFuzzDB == nil {
		http.Error(w, "fuzz store not available", http.StatusInternalServerError)
		return
	}

	runID := r.URL.Query().Get("run_id")
	if runID == "" {
		http.Error(w, "run_id required", http.StatusBadRequest)
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 500 {
		perPage = 50
	}

	sortBy := r.URL.Query().Get("sort")
	sortOrder := r.URL.Query().Get("order")

	var filterStatuses []int
	if statusQ := r.URL.Query().Get("status"); statusQ != "" {
		for _, s := range strings.Split(statusQ, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
				filterStatuses = append(filterStatuses, n)
			}
		}
	}

	result, err := globalFuzzDB.queryRoutes(runID, page, perPage, queryOpts{
		SortBy:       sortBy,
		SortOrder:    sortOrder,
		FilterStatus: filterStatuses,
	})
	if err != nil {
		http.Error(w, "query: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// sseError emits an "error" SSE event.
func sseError(w io.Writer, f http.Flusher, msg string) {
	data, _ := json.Marshal(map[string]string{"message": msg})
	fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
	f.Flush()
}

func toFieldMeta(fields []attacks.FormField) []fieldMeta {
	out := make([]fieldMeta, 0, len(fields))
	for _, f := range fields {
		out = append(out, fieldMeta{
			Flag:    f.Flag,
			Label:   f.Label,
			Help:    f.Help,
			Default: f.Default,
			Kind:    kindStr(f.Kind),
			Choices: f.Choices,
		})
	}
	return out
}

func kindStr(k attacks.FieldKind) string {
	switch k {
	case attacks.FieldURL:
		return "url"
	case attacks.FieldInt:
		return "int"
	case attacks.FieldFloat:
		return "float"
	case attacks.FieldBool:
		return "bool"
	case attacks.FieldSelect:
		return "select"
	case attacks.FieldWarn:
		return "warn"
	case attacks.FieldFile:
		return "file"
	default:
		return "string"
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "bad multipart: "+err.Error(), http.StatusBadRequest)
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer f.Close()

	tmp, err := os.CreateTemp("", "limithit-upload-*-"+hdr.Filename)
	if err != nil {
		http.Error(w, "create temp: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer tmp.Close()

	if _, err := io.Copy(tmp, f); err != nil {
		http.Error(w, "write temp: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"path": tmp.Name()})
}

func flagsToArgs(flags map[string]string) []string {
	args := make([]string, 0, len(flags))
	for k, v := range flags {
		args = append(args, "--"+k+"="+v)
	}
	return args
}
