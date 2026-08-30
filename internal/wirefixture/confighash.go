package wirefixture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// clickHouseConfigElementOpenTag/clickHouseConfigElementCloseTag delimit
// the executable configuration element that ClickHouseConfigElementSHA256
// hashes (plan §3.1): the exact literal opening/closing tags used by
// integration/clickhouse/clickhouse/common/config.d/ldap.xml, which wraps
// the real <clickhouse>...</clickhouse> element in an explanatory leading
// XML comment that must NOT contribute to the drift hash.
const (
	clickHouseConfigElementOpenTag  = "<clickhouse>"
	clickHouseConfigElementCloseTag = "</clickhouse>"
)

// ClickHouseConfigElementSHA256 returns the hex-encoded SHA-256 of
// strings.TrimSpace applied to the exact
// "<clickhouse>...</clickhouse>" substring of fileBytes (plan §3.1's
// "trimmed <clickhouse> hash" — drift hashing covers only the executable
// configuration element, not the whole file, so an edit to the file's
// leading explanatory comment never changes this hash while an edit
// inside the element, e.g. to <search_limit>, always does).
//
// It errors, rather than hashing an arbitrary occurrence, if the element
// is absent (no opening tag, or no closing tag) or duplicated (more than
// one opening tag, or more than one closing tag).
func ClickHouseConfigElementSHA256(fileBytes []byte) (string, error) {
	content := string(fileBytes)

	openCount := strings.Count(content, clickHouseConfigElementOpenTag)
	closeCount := strings.Count(content, clickHouseConfigElementCloseTag)
	switch {
	case openCount == 0 || closeCount == 0:
		return "", fmt.Errorf(
			"wirefixture: config content has no %s...%s element (open=%d, close=%d)",
			clickHouseConfigElementOpenTag, clickHouseConfigElementCloseTag, openCount, closeCount)
	case openCount > 1 || closeCount > 1:
		return "", fmt.Errorf(
			"wirefixture: config content has a duplicated %s...%s element (open=%d, close=%d)",
			clickHouseConfigElementOpenTag, clickHouseConfigElementCloseTag, openCount, closeCount)
	}

	start := strings.Index(content, clickHouseConfigElementOpenTag)
	end := strings.Index(content, clickHouseConfigElementCloseTag)
	if end < start {
		return "", fmt.Errorf(
			"wirefixture: config content's %s closing tag precedes its %s opening tag",
			clickHouseConfigElementCloseTag, clickHouseConfigElementOpenTag)
	}
	end += len(clickHouseConfigElementCloseTag)

	element := strings.TrimSpace(content[start:end])
	sum := sha256.Sum256([]byte(element))
	return hex.EncodeToString(sum[:]), nil
}
