package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// CompareInput configures `ldap-wire-recorder compare` (plan §28).
// CommittedDir and FreshDir each hold a session.json plus its sanitized
// .ber PDU files (as produced by Sanitize / committed to the repo).
// ProfileDirs, if both set, additionally compares profile.json via
// wirefixture.StableProfile.
type CompareInput struct {
	CommittedDir        string
	FreshDir             string
	CommittedProfileDir string // optional; empty skips profile comparison
	FreshProfileDir      string // optional; empty skips profile comparison
}

// CompareResult reports the outcome. CredentialLengthMismatch is reported
// distinctly from wire drift (plan §41): when it is true, Diffs/Equal do
// not represent a meaningful wire-drift verdict, only that verification
// stopped at the credential-length check.
type CompareResult struct {
	CredentialLengthMismatch bool
	Diffs                     []string
	Equal                     bool

	// Diagnostic-only (plan §28.2): never contribute to Equal.
	TimeoutElapsedMSPositive bool
	SearchBeforeAbandon      bool
}

// Compare implements the exact stable comparison semantics of plan §28.1:
// after checking fresh placeholder length equals the committed one, it
// byte-compares every sanitized PDU file and the stable (ObservedElapsedMS-
// excluded) session/profile metadata projections, and separately computes
// two purely diagnostic timeout-mode observations that never affect Equal.
func Compare(in CompareInput) (*CompareResult, error) {
	committed, err := wirefixture.ReadSession(filepath.Join(in.CommittedDir, "session.json"))
	if err != nil {
		return nil, errInvalidMetadata("read committed session.json", err)
	}
	fresh, err := wirefixture.ReadSession(filepath.Join(in.FreshDir, "session.json"))
	if err != nil {
		return nil, errInvalidMetadata("read fresh session.json", err)
	}

	result := &CompareResult{}

	if fresh.PlaceholderLength != committed.PlaceholderLength {
		result.CredentialLengthMismatch = true
		return result, nil
	}

	stableCommitted := wirefixture.StableSession(committed)
	stableFresh := wirefixture.StableSession(fresh)
	if !reflect.DeepEqual(stableCommitted, stableFresh) {
		result.Diffs = append(result.Diffs, "stable session metadata differs from committed fixture")
	}

	if len(committed.PDUs) != len(fresh.PDUs) {
		result.Diffs = append(result.Diffs, fmt.Sprintf(
			"PDU count differs: committed=%d fresh=%d", len(committed.PDUs), len(fresh.PDUs)))
	} else {
		for i, cp := range committed.PDUs {
			fp := fresh.PDUs[i]
			if cp.Filename != fp.Filename {
				result.Diffs = append(result.Diffs, fmt.Sprintf(
					"PDU %d filename differs: committed=%s fresh=%s", i+1, cp.Filename, fp.Filename))
				continue
			}
			cb, err := os.ReadFile(filepath.Join(in.CommittedDir, cp.Filename))
			if err != nil {
				return nil, errInvalidMetadata("read committed PDU file", err)
			}
			fb, err := os.ReadFile(filepath.Join(in.FreshDir, fp.Filename))
			if err != nil {
				return nil, errInvalidMetadata("read fresh PDU file", err)
			}
			if !bytes.Equal(cb, fb) {
				result.Diffs = append(result.Diffs, fmt.Sprintf("PDU %s is not byte-equal to committed fixture", cp.Filename))
			}
		}
	}

	if in.CommittedProfileDir != "" && in.FreshProfileDir != "" {
		cprof, err := wirefixture.ReadProfile(filepath.Join(in.CommittedProfileDir, "profile.json"))
		if err != nil {
			return nil, errInvalidMetadata("read committed profile.json", err)
		}
		fprof, err := wirefixture.ReadProfile(filepath.Join(in.FreshProfileDir, "profile.json"))
		if err != nil {
			return nil, errInvalidMetadata("read fresh profile.json", err)
		}
		if !reflect.DeepEqual(wirefixture.StableProfile(cprof), wirefixture.StableProfile(fprof)) {
			result.Diffs = append(result.Diffs, "stable profile metadata differs from committed fixture")
		}
	}

	// Diagnostic-only timeout-mode observations (plan §28.2): computed from
	// the RAW (not stable-projected) fresh session, since ObservedElapsedMS
	// is exactly what StableSession strips.
	if fresh.Mode == "timeout-abandon" {
		searchSeq, abandonSeq := -1, -1
		for _, p := range fresh.PDUs {
			switch p.Operation {
			case wirefixture.OperationSearchRequest:
				searchSeq = p.Sequence
			case wirefixture.OperationAbandonRequest:
				abandonSeq = p.Sequence
				if p.ObservedElapsedMS != nil && *p.ObservedElapsedMS > 0 {
					result.TimeoutElapsedMSPositive = true
				}
			}
		}
		result.SearchBeforeAbandon = searchSeq != -1 && abandonSeq != -1 && searchSeq < abandonSeq
	}

	result.Equal = len(result.Diffs) == 0
	return result, nil
}
