package main

import (
	"os"
	"path/filepath"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// ConstructInput configures `ldap-wire-recorder construct-message-id-boundary`.
type ConstructInput struct {
	OutputDir       string   // e.g. internal/ldap/testdata/clickhouse-wire/constructed/message-id-boundary
	ApplicableLines []string
}

// ConstructMessageIDBoundary calls internal/wirefixture's committed
// generator (plan §29) and writes the resulting bundle: the two constructed
// .ber PDUs plus their session.json, written only through
// wirefixture.WriteSession. This subcommand never hand-encodes BER itself —
// internal/wirefixture/constructed.go is the sole generator, so
// regeneration here and the wire-profile contract's own regenerate-and-
// compare test always run the identical algorithm.
func ConstructMessageIDBoundary(in ConstructInput) (*wirefixture.Session, error) {
	session, files, err := wirefixture.BuildConstructedMessageIDBoundarySession(in.ApplicableLines)
	if err != nil {
		return nil, errConstructGeneration("build MessageID boundary fixtures", err)
	}

	if err := os.MkdirAll(in.OutputDir, 0o700); err != nil {
		return nil, errConstructGeneration("create output directory", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(in.OutputDir, name), content, 0o600); err != nil {
			return nil, errConstructGeneration("write constructed PDU file", err)
		}
	}
	if err := wirefixture.WriteSession(filepath.Join(in.OutputDir, "session.json"), &session); err != nil {
		return nil, errInvalidMetadata("write constructed session.json", err)
	}
	return &session, nil
}
