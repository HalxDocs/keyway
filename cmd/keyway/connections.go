package main

import (
	"flag"
	"fmt"
	"os"

	"keyway/internal/cli"
	"keyway/internal/connection"
)

func runConnection(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keyway connection <add|list|delete|test|activate>")
	}
	switch args[0] {
	case "add":
		return runConnectionAdd(args[1:])
	case "list":
		return runConnectionList(args[1:])
	case "delete":
		return runConnectionDelete(args[1:])
	case "test":
		return runConnectionTest(args[1:])
	case "activate":
		return runConnectionActivate(args[1:])
	default:
		return fmt.Errorf("unknown connection subcommand %q", args[0])
	}
}

func runConnectionAdd(args []string) error {
	fs := flag.NewFlagSet("connection add", flag.ContinueOnError)
	db := dbPath(fs)
	tenantID := fs.String("tenant", "", "owning tenant")
	connType := fs.String("type", "", "saml or oidc")
	metadata := fs.String("metadata", "", "SAML metadata XML file")
	issuer := fs.String("issuer", "", "OIDC issuer URL")
	clientID := fs.String("client-id", "", "OIDC client ID")
	clientSecret := fs.String("client-secret", "", "OIDC client secret")
	emailClaim := fs.String("email-claim", "", "IdP claim for email (required)")
	nameClaim := fs.String("name-claim", "", "IdP claim for name")
	groupsClaim := fs.String("groups-claim", "", "IdP claim for groups")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var metadataXML string
	if *metadata != "" {
		raw, err := os.ReadFile(*metadata)
		if err != nil {
			return fmt.Errorf("keyway: read metadata file: %w", err)
		}
		metadataXML = string(raw)
	}
	store, err := cli.OpenStore(*db)
	if err != nil {
		return err
	}
	defer store.Close()
	out, err := cli.ConnectionAdd(store, cli.ConnectionAddParams{TenantID: *tenantID,
		Type: connection.ConnectionType(*connType), MetadataXML: metadataXML,
		IssuerURL: *issuer, ClientID: *clientID, ClientSecret: *clientSecret,
		EmailClaim: *emailClaim, NameClaim: *nameClaim, GroupsClaim: *groupsClaim})
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

func runConnectionList(args []string) error {
	fs := flag.NewFlagSet("connection list", flag.ContinueOnError)
	db := dbPath(fs)
	tenantID := fs.String("tenant", "", "owning tenant")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := cli.OpenStore(*db)
	if err != nil {
		return err
	}
	defer store.Close()
	out, err := cli.ConnectionList(store, *tenantID)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

func runConnectionDelete(args []string) error {
	fs := flag.NewFlagSet("connection delete", flag.ContinueOnError)
	db := dbPath(fs)
	id := fs.String("id", "", "connection ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := cli.OpenStore(*db)
	if err != nil {
		return err
	}
	defer store.Close()
	out, err := cli.ConnectionDelete(store, *id)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

func runConnectionTest(args []string) error {
	fs := flag.NewFlagSet("connection test", flag.ContinueOnError)
	db := dbPath(fs)
	id := fs.String("id", "", "connection ID")
	entityID := fs.String("sp-entity-id", "", "SP entity ID (SAML, must match server)")
	acsURL := fs.String("sp-acs-url", "", "SP ACS URL (SAML, must match server)")
	keyPath := fs.String("sp-key", "", "SP signing key PEM file (SAML)")
	certPath := fs.String("sp-cert", "", "SP certificate PEM file (SAML)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := cli.OpenStore(*db)
	if err != nil {
		return err
	}
	defer store.Close()
	out, err := cli.ConnectionTest(store, *id, cli.SPTestParams{EntityID: *entityID,
		ACSURL: *acsURL, KeyPath: *keyPath, CertPath: *certPath})
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

func runConnectionActivate(args []string) error {
	fs := flag.NewFlagSet("connection activate", flag.ContinueOnError)
	db := dbPath(fs)
	id := fs.String("id", "", "connection ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := cli.OpenStore(*db)
	if err != nil {
		return err
	}
	defer store.Close()
	out, err := cli.ConnectionActivate(store, *id)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}
