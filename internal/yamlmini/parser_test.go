package yamlmini

import (
	"strings"
	"testing"
)

func TestParseMappingNestedMappingAndScalarSequence(t *testing.T) {
	node, err := Parse(strings.NewReader("root:\n  enabled: true\n  values:\n    - one\n    - two\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if node.Kind != Mapping || len(node.Pairs) != 1 {
		t.Fatalf("root = %#v", node)
	}
	nested := node.Pairs[0].Value
	if nested.Kind != Mapping || len(nested.Pairs) != 2 {
		t.Fatalf("nested = %#v", nested)
	}
	if nested.Pairs[1].Value.Kind != Sequence || len(nested.Pairs[1].Value.Values) != 2 {
		t.Fatalf("sequence = %#v", nested.Pairs[1].Value)
	}
}

func TestParseRejectsDuplicateMappingKeys(t *testing.T) {
	_, err := Parse(strings.NewReader("value: one\nvalue: two\n"))
	if err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("error = %v, want duplicate field", err)
	}
}

func TestParseRejectsAdvancedYAMLFeatures(t *testing.T) {
	for _, input := range []string{"value: [one, two]\n", "value: &anchor one\n", "value: |\n  multiline\n"} {
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Fatalf("Parse(%q) succeeded, want error", input)
		}
	}
}
