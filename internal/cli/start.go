package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"keyway/internal/api"
	"keyway/internal/flow"
)

// StartParams configures one server run. SPEntityID defaults to BaseURL
// when blank; SPKeyPath/SPCertPath both blank means an ephemeral identity
// with a loud warning, never a silent one.
type StartParams struct {
	Addr       string
	DBPath     string
	BaseURL    string
	SPEntityID string
	SPKeyPath  string
	SPCertPath string
}

// Start opens storage, builds the flow orchestrator and HTTP routes, and
// serves until interrupted. It returns only on error or shutdown.
func Start(params StartParams) error {
	if params.Addr == "" || params.BaseURL == "" {
		return fmt.Errorf("cli: start: addr and base URL are required")
	}
	entityID := params.SPEntityID
	if entityID == "" {
		entityID = params.BaseURL
	}
	pair, err := LoadKeyPair(params.SPKeyPath, params.SPCertPath)
	if err != nil {
		return err
	}
	if pair.Ephemeral {
		fmt.Fprintln(os.Stderr, "WARNING: no --sp-key/--sp-cert given; using an ephemeral SP identity. Restarts invalidate it at the IdP.")
	}
	store, err := OpenStore(params.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	svc, err := flow.NewService(store, flow.Config{
		BaseURL: params.BaseURL, SPEntityID: entityID,
		SPKey: pair.Key, SPCert: pair.Certificate,
	})
	if err != nil {
		return err
	}
	server, err := api.NewServer(svc, store, slog.Default())
	if err != nil {
		return err
	}
	httpServer := &http.Server{Addr: params.Addr, Handler: server.Routes()}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = httpServer.Close()
	}()
	fmt.Printf("keyway listening on %s\n", params.Addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("cli: start: %w", err)
	}
	return nil
}
