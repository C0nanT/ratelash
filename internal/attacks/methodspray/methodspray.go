package methodspray

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/conantorreswf/limithit/internal/attacks"
	"github.com/conantorreswf/limithit/internal/metrics"
	"github.com/conantorreswf/limithit/internal/worker"
)

func init() {
	attacks.Register("methodspray", func() attacks.Attack { return &MethodSpray{} })
}

type MethodSpray struct {
	methods  string
	wordlist string
	pairs    []pair
}

type pair struct {
	method string
	path   string
}

func (m *MethodSpray) Name() string { return "methodspray" }
func (m *MethodSpray) Synopsis() string {
	return "method × path matrix to find routes that bypass per-verb rate limits"
}

func (m *MethodSpray) Flags(fs *flag.FlagSet) {
	fs.StringVar(&m.methods, "methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD", "comma-separated HTTP methods to spray")
	fs.StringVar(&m.wordlist, "wordlist", "", "path-list file (overrides embedded default)")
}

func (m *MethodSpray) FormFields() []attacks.FormField {
	url := ""
	methods := "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD"
	wordlist := ""
	total := "1000"
	concurrency := "20"
	timeout := "10"
	return []attacks.FormField{
		{Flag: "url", Label: "Base URL", Help: "Scheme + host only; paths come from the wordlist", Kind: attacks.FieldURL, Default: "", Value: &url},
		{Flag: "methods", Label: "HTTP methods (comma-separated)", Help: "Cross-product of methods × wordlist paths is sprayed", Kind: attacks.FieldString, Default: "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD", Value: &methods},
		{Flag: "wordlist", Label: "Wordlist path (empty = built-in)", Kind: attacks.FieldFile, Default: "", Value: &wordlist},
		{Flag: "total", Label: "Total requests", Kind: attacks.FieldInt, Default: "1000", Validate: attacks.ValidatePosInt, Value: &total},
		{Flag: "concurrency", Label: "Concurrency (workers)", Kind: attacks.FieldInt, Default: "20", Validate: attacks.ValidatePosInt, Value: &concurrency},
		{Flag: "timeout", Label: "Timeout (s)", Kind: attacks.FieldInt, Default: "10", Validate: attacks.ValidatePosInt, Value: &timeout},
	}
}

func (m *MethodSpray) Validate() error {
	parts := strings.Split(m.methods, ",")
	var valid []string
	for _, p := range parts {
		v := strings.ToUpper(strings.TrimSpace(p))
		if v != "" {
			valid = append(valid, v)
		}
	}
	if len(valid) == 0 {
		return fmt.Errorf("methodspray: no valid methods in %q", m.methods)
	}
	m.methods = strings.Join(valid, ",")
	return nil
}

func (m *MethodSpray) Run(ctx context.Context, base attacks.Base) (attacks.Report, error) {
	u, err := url.Parse(base.URL)
	if err != nil {
		return nil, fmt.Errorf("methodspray: invalid base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("methodspray: base url must include scheme + host")
	}
	baseURL := strings.TrimRight(u.Scheme+"://"+u.Host, "/")

	var wl *metrics.Wordlist
	if m.wordlist != "" {
		wl, err = metrics.LoadWordlist(m.wordlist)
		if err != nil {
			return nil, fmt.Errorf("methodspray: %w", err)
		}
	} else {
		wl = metrics.DefaultWordlist()
	}
	if wl.Size() == 0 {
		return nil, fmt.Errorf("methodspray: wordlist is empty")
	}

	methods := strings.Split(m.methods, ",")
	// Build the cross-product pairs.
	paths := wl.All()
	m.pairs = make([]pair, 0, len(methods)*len(paths))
	for _, method := range methods {
		for _, path := range paths {
			m.pairs = append(m.pairs, pair{method: method, path: path})
		}
	}

	pairs := m.pairs
	build := func(ctx context.Context, idx int) (*http.Request, string, error) {
		p := pairs[idx%len(pairs)]
		target := baseURL + p.path
		req, err := http.NewRequestWithContext(ctx, p.method, target, nil)
		if err != nil {
			return nil, p.path, err
		}
		for k, vs := range base.Common.Headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		return req, p.method + " " + p.path, nil
	}

	tag := fmt.Sprintf("methodspray (methods=%d paths=%d)", len(methods), len(paths))
	return worker.Run(ctx, base.Client, build, worker.Config{
		Total:       base.Common.Total,
		Concurrency: base.Common.Concurrency,
		Pacer:       base.Common.Pacer,
		Tag:         tag,
		Attack:      "methodspray",
		Target:      base.URL,
		ProgressCh:  base.ProgressCh,
	}), nil
}
