package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/conantorreswf/limithit/testserver/handler"
	"github.com/conantorreswf/limithit/testserver/ratelimit"
	"github.com/conantorreswf/limithit/testserver/store"
)

func envFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

// vulnSet holds which protections are disabled.
type vulnSet struct {
	slowloris  bool
	headerbomb bool
	lockout    bool
	decompress bool
}

func parseVulnSet(s string) vulnSet {
	var v vulnSet
	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(strings.ToLower(part)) {
		case "slowloris":
			v.slowloris = true
		case "headerbomb":
			v.headerbomb = true
		case "lockout":
			v.lockout = true
		case "decompress":
			v.decompress = true
		}
	}
	return v
}

// offenderAdapter exposes ratelimit.Registry top offenders as store.OffenderSource.
type offenderAdapter struct{ reg *ratelimit.Registry }

func (a offenderAdapter) TopOffenders(n int) []store.IPStat {
	src := a.reg.TopOffenders(n)
	out := make([]store.IPStat, 0, len(src))
	for _, s := range src {
		out = append(out, store.IPStat{IP: s.Key, Denied: s.Denied})
	}
	return out
}

func main() {
	port := flag.Int("port", envInt("PORT", 8080), "listen port")
	rate := flag.Float64("rate", envFloat("RATE_LIMIT_RPS", 0), "per-IP rate limit in req/s (0 = disabled)")
	burst := flag.Float64("burst", 0, "per-IP burst size (defaults to --rate)")
	algo := flag.String("algo", "tokenbucket", "rate-limit algorithm: tokenbucket, fixedwindow, slidingwindow, leakybucket")
	trustXFF := flag.String("trust-xff-cidr", "", `comma-separated CIDRs of trusted proxies whose XFF will be honoured`)
	authUser := flag.String("auth-user", "admin", "auth handler username")
	authPass := flag.String("auth-pass", "changeme", "auth handler password")
	maxConns := flag.Int("max-conns", 0, "max concurrent WebSocket connections (0=unlimited)")
	maxStreams := flag.Int("max-streams", 0, "max concurrent HTTP/2 streams per connection (0=unlimited)")
	http2Flag := flag.Bool("http2", false, "enable HTTP/2 via h2c (cleartext)")
	maxDecompress := flag.Int64("max-decompress", 1<<20, "decompression cap for /api/gzip in bytes (0=unlimited)")
	vulnerableStr := flag.String("vulnerable", "", "comma-separated protections to disable: slowloris,headerbomb,lockout,decompress")
	flag.Parse()

	if *burst == 0 {
		*burst = *rate
	}
	vuln := parseVulnSet(*vulnerableStr)

	trusted, err := ratelimit.ParseCIDRList(*trustXFF)
	if err != nil {
		log.Fatalf("invalid --trust-xff-cidr: %v", err)
	}
	if len(trusted) == 0 {
		log.Printf("XFF trust list empty — X-Forwarded-For headers ignored")
	} else {
		log.Printf("trusted proxy CIDRs: %v", trusted)
	}

	s := store.New()
	broadcaster := store.NewBroadcaster()

	var lim ratelimit.Limiter
	if *rate > 0 {
		var lerr error
		lim, lerr = ratelimit.NewLimiter(*algo, *rate, *burst)
		if lerr != nil {
			log.Fatalf("--algo: %v", lerr)
		}
		if reg, ok := lim.(*ratelimit.Registry); ok {
			s.SetOffenderSource(offenderAdapter{reg: reg})
			defer reg.Close()
		}
		log.Printf("rate limiting: algo=%s, %.0f req/s, burst %.0f", *algo, *rate, *burst)
	}

	if *vulnerableStr != "" {
		log.Printf("vulnerable mode: %s", *vulnerableStr)
	}

	decomposeCap := *maxDecompress
	if vuln.decompress {
		decomposeCap = 0 // unlimited
		log.Printf("vulnerable: decompression cap disabled")
	}

	s.SetConfig(store.ServerConfig{
		Algo:       *algo,
		MaxConns:   *maxConns,
		MaxStreams: *maxStreams,
		Vulnerable: *vulnerableStr,
	})

	authHandler := handler.NewAuthHandler(*authUser, *authPass, trusted)
	if vuln.lockout {
		authHandler.DisableLockout = true
		log.Printf("vulnerable: auth lockout disabled")
	}

	mux := http.NewServeMux()

	// dashboard + SSE (no rate limiting, no recording)
	mux.HandleFunc("/{$}", handler.DashboardHandler)
	mux.Handle("/metrics", handler.SSEHandler(broadcaster))

	limited := func(h http.Handler) http.Handler {
		return handler.RecordingMiddleware(s, ratelimit.Middleware(lim, trusted, h))
	}
	mux.Handle("/api/ping", limited(http.HandlerFunc(handler.PingHandler)))
	mux.Handle("/api/echo", limited(http.HandlerFunc(handler.EchoHandler)))
	mux.Handle("/api/auth", limited(authHandler))
	mux.Handle("/api/gzip", limited(handler.NewGzipHandler(decomposeCap)))
	mux.Handle("/ws/echo", handler.NewWsEchoHandler(*maxConns))

	// hidden routes — discoverable by fuzz but not advertised
	for _, p := range []string{"/admin", "/api/users", "/api/status", "/api/config", "/api/health", "/api/v2/ping", "/api/internal"} {
		mux.Handle(p, limited(http.HandlerFunc(handler.HiddenRouteHandler)))
	}

	// catch-all: 404 for anything else
	mux.Handle("/", http.HandlerFunc(handler.NotFoundHandler))

	// background broadcaster tick
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			broadcaster.Broadcast(s.Snapshot())
		}
	}()

	var httpHandler http.Handler = mux
	if *http2Flag {
		h2s := &http2.Server{}
		if *maxStreams > 0 {
			h2s.MaxConcurrentStreams = uint32(*maxStreams)
		}
		httpHandler = h2c.NewHandler(mux, h2s)
		log.Printf("HTTP/2 h2c enabled (max-streams=%d)", *maxStreams)
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: httpHandler,

		ReadTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second,
		// WriteTimeout must be 0 so SSE streams stay open
	}

	if !vuln.headerbomb {
		srv.MaxHeaderBytes = 16 << 10 // 16 KB — bars headerbomb
	} else {
		log.Printf("vulnerable: MaxHeaderBytes disabled")
	}
	if !vuln.slowloris {
		srv.ReadHeaderTimeout = 5 * time.Second
	} else {
		log.Printf("vulnerable: ReadHeaderTimeout disabled")
	}

	log.Printf("testserver listening on http://localhost:%d", *port)
	log.Printf("  GET  http://localhost:%d/api/ping", *port)
	log.Printf("  POST http://localhost:%d/api/echo", *port)
	log.Printf("  POST http://localhost:%d/api/auth", *port)
	log.Printf("  POST http://localhost:%d/api/gzip", *port)
	log.Printf("  WS   ws://localhost:%d/ws/echo", *port)
	log.Printf("  dashboard: http://localhost:%d/", *port)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}
