package main

import (
	"flag"
	"fmt"
	"strings"

	"keyway/internal/cli"
	"keyway/internal/flow"
)

func runTenant(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keyway tenant <create|list|redirect>")
	}
	switch args[0] {
	case "redirect":
		return runTenantRedirect(args[1:])
	case "create":
		fs := flag.NewFlagSet("tenant create", flag.ContinueOnError)
		db := dbPath(fs)
		id := fs.String("id", "", "tenant handle")
		name := fs.String("name", "", "display name")
		uris := fs.String("redirect-uris", "", "comma-separated callback allowlist")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		store, err := cli.OpenStore(*db)
		if err != nil {
			return err
		}
		defer store.Close()
		var allowlist []string
		if *uris != "" {
			allowlist = strings.Split(*uris, ",")
		}
		out, err := cli.TenantCreate(store, *id, *name, allowlist)
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil
	case "list":
		fs := flag.NewFlagSet("tenant list", flag.ContinueOnError)
		db := dbPath(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		store, err := cli.OpenStore(*db)
		if err != nil {
			return err
		}
		defer store.Close()
		out, err := cli.TenantList(store)
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil
	default:
		return fmt.Errorf("unknown tenant subcommand %q", args[0])
	}
}

func runTenantRedirect(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keyway tenant redirect <add|remove>")
	}
	var run func(store interface {
	}, tenantID, uri string) (string, error)
	_ = run
	switch args[0] {
	case "add":
		return runTenantRedirectChange(args[1:], cli.TenantRedirectAdd)
	case "remove":
		return runTenantRedirectChange(args[1:], cli.TenantRedirectRemove)
	default:
		return fmt.Errorf("unknown tenant redirect subcommand %q", args[0])
	}
}

func runTenantRedirectChange(args []string, change func(flow.Storage, string, string) (string, error)) error {
	fs := flag.NewFlagSet("tenant redirect", flag.ContinueOnError)
	db := dbPath(fs)
	tenantID := fs.String("id", "", "tenant handle")
	uri := fs.String("uri", "", "callback URL to allowlist or remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := cli.OpenStore(*db)
	if err != nil {
		return err
	}
	defer store.Close()
	out, err := change(store, *tenantID, *uri)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}
