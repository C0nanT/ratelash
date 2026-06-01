package replay

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/conantorreswf/limithit/internal/attacks"
	"github.com/conantorreswf/limithit/internal/worker"
)

func init() {
	attacks.Register("replay", func() attacks.Attack { return &Replay{} })
}

type Replay struct {
	file string
	loop bool
	reqs []savedReq
}

type savedReq struct {
	Method string
	URL    string
}

func (r *Replay) Name() string { return "replay" }
func (r *Replay) Synopsis() string {
	return "replay captured requests from a HAR or line-delimited file"
}

func (r *Replay) Flags(fs *flag.FlagSet) {
	fs.StringVar(&r.file, "file", "", "HAR file or newline-delimited \"METHOD URL\" file (required)")
	fs.BoolVar(&r.loop, "loop", false, "loop through the request list until --total is reached")
}

func (r *Replay) FormFields() []attacks.FormField {
	file := ""
	url := ""
	total := "0"
	concurrency := "10"
	loop := "false"
	return []attacks.FormField{
		{Flag: "file", Label: "Request file", Help: `HAR file or newline-delimited "METHOD URL" file`, Kind: attacks.FieldFile, Default: "", Value: &file},
		{Flag: "url", Label: "Base URL (report label)", Help: "Individual request URLs come from the file; this labels the report", Kind: attacks.FieldURL, Default: "", Value: &url},
		{Flag: "total", Label: "Total requests (0 = file length)", Kind: attacks.FieldInt, Default: "0", Validate: attacks.ValidateNonNegInt, Value: &total},
		{Flag: "concurrency", Label: "Concurrency (workers)", Kind: attacks.FieldInt, Default: "10", Validate: attacks.ValidatePosInt, Value: &concurrency},
		{Flag: "loop", Label: "Loop through request list", Help: "Replays in a cycle until --total is reached", Kind: attacks.FieldBool, Default: "false", Value: &loop},
	}
}

func (r *Replay) Validate() error {
	if r.file == "" {
		return errors.New("replay requires --file")
	}
	reqs, err := loadFile(r.file)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	if len(reqs) == 0 {
		return errors.New("replay: file contains no requests")
	}
	r.reqs = reqs
	return nil
}

func (r *Replay) Run(ctx context.Context, base attacks.Base) (attacks.Report, error) {
	reqs := r.reqs
	loop := r.loop

	build := func(ctx context.Context, idx int) (*http.Request, string, error) {
		var sr savedReq
		if loop {
			sr = reqs[idx%len(reqs)]
		} else if idx < len(reqs) {
			sr = reqs[idx]
		} else {
			return nil, "", fmt.Errorf("no request at index %d", idx)
		}
		req, err := http.NewRequestWithContext(ctx, sr.Method, sr.URL, nil)
		if err != nil {
			return nil, "", err
		}
		for k, vs := range base.Common.Headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		return req, sr.URL, nil
	}

	total := base.Common.Total
	if !loop && len(reqs) < total {
		total = len(reqs)
	}

	return worker.Run(ctx, base.Client, build, worker.Config{
		Total:       total,
		Concurrency: base.Common.Concurrency,
		Pacer:       base.Common.Pacer,
		Tag:         "replay",
		Attack:      "replay",
		Target:      base.URL,
		ProgressCh:  base.ProgressCh,
	}), nil
}

func loadFile(path string) ([]savedReq, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Try HAR first.
	if reqs, err := parseHAR(data); err == nil && len(reqs) > 0 {
		return reqs, nil
	}

	// Fall back to newline-delimited "METHOD URL" format.
	return parseLines(data)
}

// harFile is a minimal HAR structure.
type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method string `json:"method"`
				URL    string `json:"url"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

func parseHAR(data []byte) ([]savedReq, error) {
	var h harFile
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	reqs := make([]savedReq, 0, len(h.Log.Entries))
	for _, e := range h.Log.Entries {
		m := strings.ToUpper(e.Request.Method)
		if m == "" || e.Request.URL == "" {
			continue
		}
		reqs = append(reqs, savedReq{Method: m, URL: e.Request.URL})
	}
	return reqs, nil
}

func parseLines(data []byte) ([]savedReq, error) {
	var reqs []savedReq
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 1 {
			// Just a URL, default to GET.
			reqs = append(reqs, savedReq{Method: "GET", URL: parts[0]})
		} else if len(parts) >= 2 {
			reqs = append(reqs, savedReq{Method: strings.ToUpper(parts[0]), URL: parts[1]})
		}
	}
	return reqs, sc.Err()
}
