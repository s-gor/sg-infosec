package yamlmini

import (
	"strings"
	"testing"
)

func TestParseMappingAndSequence(t *testing.T) {
	node, err := Parse(strings.NewReader("root:\n  name: value\n  items:\n    - one\n    - two\n"))
	if err != nil {
		t.Fatal(err)
	}
	if node.Kind != Mapping || len(node.Pairs) != 1 || node.Pairs[0].Value.Kind != Mapping {
		t.Fatalf("node=%+v", node)
	}
	items := node.Pairs[0].Value.Pairs[1].Value
	if items.Kind != Sequence || len(items.Values) != 2 || items.Values[1].Value != "two" {
		t.Fatalf("items=%+v", items)
	}
}

func TestParseRejectsDuplicateKeys(t *testing.T) {
	_, err := Parse(strings.NewReader("a: 1\na: 2\n"))
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseRejectsMultipleDocuments(t *testing.T) {
	_, err := Parse(strings.NewReader("a: 1\n---\nb: 2\n"))
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseCommentsAndQuotes(t *testing.T) {
	node, err := Parse(strings.NewReader("a: \"x # y\" # comment\nb: 'it''s'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if node.Pairs[0].Value.Value != "x # y" || node.Pairs[1].Value.Value != "it's" {
		t.Fatalf("node=%+v", node)
	}
}
