package wirefixture

import (
	"fmt"
	"testing"
)

const testConfigTemplate = `<!--
  Explanatory leading comment, deliberately NOT part of the hashed
  element (plan §3.1). Editing this line must never change
  ClickHouseConfigElementSHA256's result.
-->
<clickhouse>
    <ldap_servers>
        <oauth_helper>
            <host>ch-oauth-ldap</host>
            <port>389</port>
            <search_limit>%s</search_limit>
        </oauth_helper>
    </ldap_servers>
</clickhouse>
`

func TestClickHouseConfigElementSHA256_CommentEditLeavesHashUnchanged(t *testing.T) {
	base := []byte(fmt.Sprintf(testConfigTemplate, "256"))
	commentEdited := []byte(fmt.Sprintf(testConfigTemplate, "256"))
	commentEdited = []byte("<!-- an entirely different, longer explanatory comment -->\n" + string(commentEdited))

	baseHash, err := ClickHouseConfigElementSHA256(base)
	if err != nil {
		t.Fatalf("ClickHouseConfigElementSHA256(base): %v", err)
	}
	editedHash, err := ClickHouseConfigElementSHA256(commentEdited)
	if err != nil {
		t.Fatalf("ClickHouseConfigElementSHA256(commentEdited): %v", err)
	}
	if baseHash != editedHash {
		t.Fatalf("hash changed after an edit OUTSIDE <clickhouse>: base=%s edited=%s", baseHash, editedHash)
	}
}

func TestClickHouseConfigElementSHA256_SearchLimitEditChangesHash(t *testing.T) {
	base := []byte(fmt.Sprintf(testConfigTemplate, "256"))
	changed := []byte(fmt.Sprintf(testConfigTemplate, "512"))

	baseHash, err := ClickHouseConfigElementSHA256(base)
	if err != nil {
		t.Fatalf("ClickHouseConfigElementSHA256(base): %v", err)
	}
	changedHash, err := ClickHouseConfigElementSHA256(changed)
	if err != nil {
		t.Fatalf("ClickHouseConfigElementSHA256(changed): %v", err)
	}
	if baseHash == changedHash {
		t.Fatalf("hash unchanged after an edit INSIDE <clickhouse> (<search_limit>): %s", baseHash)
	}
}

func TestClickHouseConfigElementSHA256_Deterministic(t *testing.T) {
	content := []byte(fmt.Sprintf(testConfigTemplate, "256"))
	first, err := ClickHouseConfigElementSHA256(content)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := ClickHouseConfigElementSHA256(content)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first != second {
		t.Fatalf("hash not deterministic across repeated calls on identical bytes: %s vs %s", first, second)
	}
}

func TestClickHouseConfigElementSHA256_AbsentElement(t *testing.T) {
	if _, err := ClickHouseConfigElementSHA256([]byte("<not-clickhouse><a>1</a></not-clickhouse>")); err == nil {
		t.Fatal("expected an error for content with no <clickhouse> element")
	}
}

func TestClickHouseConfigElementSHA256_MissingClosingTag(t *testing.T) {
	if _, err := ClickHouseConfigElementSHA256([]byte("<clickhouse><a>1</a>")); err == nil {
		t.Fatal("expected an error for content with an opening but no closing tag")
	}
}

func TestClickHouseConfigElementSHA256_DuplicatedElement(t *testing.T) {
	content := []byte("<clickhouse><a>1</a></clickhouse><clickhouse><a>2</a></clickhouse>")
	if _, err := ClickHouseConfigElementSHA256(content); err == nil {
		t.Fatal("expected an error for content with a duplicated <clickhouse> element")
	}
}

func TestClickHouseConfigElementSHA256_TrimsSurroundingWhitespace(t *testing.T) {
	tight := []byte("<clickhouse><a>1</a></clickhouse>")
	padded := []byte("   \n\t <clickhouse><a>1</a></clickhouse>  \n")

	tightHash, err := ClickHouseConfigElementSHA256(tight)
	if err != nil {
		t.Fatalf("ClickHouseConfigElementSHA256(tight): %v", err)
	}
	paddedHash, err := ClickHouseConfigElementSHA256(padded)
	if err != nil {
		t.Fatalf("ClickHouseConfigElementSHA256(padded): %v", err)
	}
	if tightHash != paddedHash {
		t.Fatalf("surrounding whitespace around the element changed the hash: tight=%s padded=%s", tightHash, paddedHash)
	}
}

