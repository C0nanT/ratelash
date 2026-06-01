package webui

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFiles embed.FS

// Serve starts the admin panel HTTP server on addr and blocks until ctx is cancelled.
func Serve(ctx context.Context, addr string) error {
	if err := openFuzzDB(); err != nil {
		return fmt.Errorf("fuzz db: %w", err)
	}
	fmt.Printf("fuzz db: %s\n", FuzzDBPath)

	mux := http.NewServeMux()

	mux.HandleFunc("/api/attacks", handleAttacks)
	mux.HandleFunc("/api/run", handleRun)
	mux.HandleFunc("/api/upload", handleUpload)
	mux.HandleFunc("/api/fuzz-routes", handleFuzzRoutes)

	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("embed static: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
