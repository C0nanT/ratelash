package fuzz

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	attacks.Register("fuzz", func() attacks.Attack { return &Fuzz{} })
}

type Fuzz struct {
	wordlist  string
	cacheBust bool
}

func (f *Fuzz) Name() string     { return "fuzz" }
func (f *Fuzz) Synopsis() string { return "path enumeration from a wordlist (+ optional cache-bust)" }

func (f *Fuzz) Flags(fs *flag.FlagSet) {
	fs.StringVar(&f.wordlist, "wordlist", "", "path-list file (overrides embedded default)")
	fs.BoolVar(&f.cacheBust, "cache-bust", false, "append random _cb=<hex> to each request")
}

func (f *Fuzz) Validate() error { return nil }

func (f *Fuzz) FormFields() []attacks.FormField {
	url := ""
	concurrency := "20"
	timeout := "10"
	wordlist := ""
	cacheBust := "false"
	return []attacks.FormField{
		{Flag: "url", Label: "Base URL", Help: "Scheme + host; paths come from the wordlist", Kind: attacks.FieldURL, Default: "", Value: &url},
		{Flag: "concurrency", Label: "Concurrency (workers)", Kind: attacks.FieldInt, Default: "20", Validate: attacks.ValidatePosInt, Value: &concurrency},
		{Flag: "timeout", Label: "Timeout (s)", Kind: attacks.FieldInt, Default: "10", Validate: attacks.ValidatePosInt, Value: &timeout},
		{Flag: "wordlist", Label: "Wordlist path (empty = built-in)", Kind: attacks.FieldFile, Default: "", Value: &wordlist},
		{Flag: "cache-bust", Label: "Cache bust (append _cb=<hex>)", Kind: attacks.FieldBool, Default: "false", Value: &cacheBust},
	}
}

func (f *Fuzz) Run(ctx context.Context, base attacks.Base) (attacks.Report, error) {
	u, err := url.Parse(base.URL)
	if err != nil {
		return nil, fmt.Errorf("fuzz: invalid base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("fuzz: base url must include scheme + host")
	}
	basePath := strings.TrimRight(u.Path, "/")
	baseURL := u.Scheme + "://" + u.Host

	var wl *metrics.Wordlist
	if f.wordlist != "" {
		wl, err = metrics.LoadWordlist(f.wordlist)
		if err != nil {
			return nil, fmt.Errorf("fuzz: %w", err)
		}
	} else {
		wl = metrics.DefaultWordlist()
	}
	if wl.Size() == 0 {
		return nil, fmt.Errorf("fuzz: wordlist is empty")
	}

	base.Common.Total = wl.Size()

	cacheBust := f.cacheBust
	build := func(ctx context.Context, _ int) (*http.Request, string, error) {
		wordPath := wl.Next()
		fullPath := basePath + wordPath
		full := baseURL + fullPath
		if cacheBust {
			var buf [8]byte
			_, _ = rand.Read(buf[:])
			sep := "?"
			if strings.Contains(fullPath, "?") {
				sep = "&"
			}
			full = full + sep + "_cb=" + hex.EncodeToString(buf[:])
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
		if err != nil {
			return nil, fullPath, err
		}
		for k, vs := range base.Common.Headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		return req, fullPath, nil
	}

	tag := fmt.Sprintf("fuzz (paths=%d cache-bust=%v)", wl.Size(), f.cacheBust)
	report := worker.Run(ctx, base.Client, build, worker.Config{
		Total:       base.Common.Total,
		Concurrency: base.Common.Concurrency,
		Tag:         tag,
		Attack:      "fuzz",
		Target:      base.URL,
		ProgressCh:  base.ProgressCh,
	})
	return report, nil
}
