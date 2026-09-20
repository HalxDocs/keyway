// Command keyway is Keyway's single static binary: serve, provision, probe.
//
// WHY a thin dispatcher: every command delegates to testable run functions
// in internal/cli. main owns flags, output, and exit codes only, so adding
// a command means one case branch plus one cli function, never process
// plumbing mixed with logic.
package main

import (
	"flag"
	"fmt"
	"os"

	"keyway/internal/cli"
)

func dbPath(fs *flag.FlagSet) *string {
	if env := os.Getenv("KEYWAY_DB"); env != "" {
		return fs.String("db", env, "database file")
	}
	return fs.String("db", "./keyway.db", "database file")
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keyway <start|keygen|sp-keygen|tenant|connection|status>")
	}
	switch args[0] {
	case "start":
		return runStart(args[1:])
	case "keygen":
		out, err := cli.Keygen()
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil
	case "sp-keygen":
		return runSPKeygen(args[1:])
	case "tenant":
		return runTenant(args[1:])
	case "connection":
		return runConnection(args[1:])
	case "status":
		return runStatus(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address (localhost by default)")
	db := dbPath(fs)
	baseURL := fs.String("base-url", "http://127.0.0.1:8080", "public base URL for callbacks")
	entityID := fs.String("sp-entity-id", "", "SP entity ID (defaults to base URL)")
	keyPath := fs.String("sp-key", "", "SP signing key PEM file")
	certPath := fs.String("sp-cert", "", "SP certificate PEM file")
	adminToken := fs.String("admin-token", os.Getenv("KEYWAY_ADMIN_TOKEN"), "static bearer token for /admin/* (or KEYWAY_ADMIN_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return cli.Start(cli.StartParams{Addr: *addr, DBPath: *db, BaseURL: *baseURL,
		SPEntityID: *entityID, SPKeyPath: *keyPath, SPCertPath: *certPath, AdminToken: *adminToken})
}

func runSPKeygen(args []string) error {
	fs := flag.NewFlagSet("sp-keygen", flag.ContinueOnError)
	keyPath := fs.String("key", "./sp.key", "output path for the PEM signing key")
	certPath := fs.String("cert", "./sp.crt", "output path for the PEM certificate")
	cn := fs.String("cn", "keyway-sp", "certificate Common Name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	out, err := cli.SPKeygen(cli.SPKeygenParams{KeyPath: *keyPath, CertPath: *certPath, CN: *cn})
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

func runStatus(args []string) error {	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	db := dbPath(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := cli.OpenStore(*db)
	if err != nil {
		return err
	}
	defer store.Close()
	out, err := cli.Status(store, *db)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "keyway:", err)
		os.Exit(1)
	}
}
