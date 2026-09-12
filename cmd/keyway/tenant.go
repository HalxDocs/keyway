package main

import (
	"flag"
	"fmt"
	"strings"

	"keyway/internal/cli"
)

func runTenant(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keyway tenant <create|list>")
	}
	switch args[0] {
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
