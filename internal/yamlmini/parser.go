package yamlmini

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Kind uint8

const (
	Invalid Kind = iota
	Scalar
	Mapping
	Sequence
)

type Pair struct {
	Key   string
	Value *Node
}

type Node struct {
	Kind   Kind
	Value  string
	Pairs  []Pair
	Values []*Node
	Line   int
}

type sourceLine struct {
	indent int
	text   string
	line   int
}

func Parse(r io.Reader) (*Node, error) {
	if r == nil {
		return nil, fmt.Errorf("nil YAML reader")
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), 1<<20)
	var lines []sourceLine
	documentSeen := false
	for number := 1; scanner.Scan(); number++ {
		raw := strings.TrimRight(scanner.Text(), " \r")
		if strings.ContainsRune(raw, '\t') {
			return nil, fmt.Errorf("line %d: tabs are not allowed", number)
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "---" {
			if documentSeen || len(lines) != 0 {
				return nil, fmt.Errorf("line %d: multiple YAML documents are not supported", number)
			}
			documentSeen = true
			continue
		}
		if trimmed == "..." {
			continue
		}
		documentSeen = true
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent%2 != 0 {
			return nil, fmt.Errorf("line %d: indentation must use multiples of two spaces", number)
		}
		text, err := stripComment(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", number, err)
		}
		if text == "" {
			continue
		}
		lines = append(lines, sourceLine{indent: indent, text: text, line: number})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read YAML: %w", err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty YAML document")
	}
	if lines[0].indent != 0 {
		return nil, fmt.Errorf("line %d: document must start at indentation zero", lines[0].line)
	}
	index := 0
	node, err := parseBlock(lines, &index, 0)
	if err != nil {
		return nil, err
	}
	if index != len(lines) {
		return nil, fmt.Errorf("line %d: unexpected YAML content", lines[index].line)
	}
	return node, nil
}

func parseBlock(lines []sourceLine, index *int, indent int) (*Node, error) {
	if *index >= len(lines) {
		return nil, fmt.Errorf("unexpected end of YAML document")
	}
	line := lines[*index]
	if line.indent != indent {
		return nil, fmt.Errorf("line %d: unexpected indentation", line.line)
	}
	if strings.HasPrefix(line.text, "- ") || line.text == "-" {
		return parseSequence(lines, index, indent)
	}
	return parseMapping(lines, index, indent)
}

func parseMapping(lines []sourceLine, index *int, indent int) (*Node, error) {
	node := &Node{Kind: Mapping, Line: lines[*index].line}
	seen := map[string]struct{}{}
	for *index < len(lines) {
		line := lines[*index]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", line.line)
		}
		if strings.HasPrefix(line.text, "- ") || line.text == "-" {
			return nil, fmt.Errorf("line %d: sequence item where mapping key was expected", line.line)
		}
		key, value, hasValue, err := splitMapping(line.text)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line.line, err)
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("line %d: duplicate key %q", line.line, key)
		}
		seen[key] = struct{}{}
		*index++
		var child *Node
		if hasValue {
			decoded, err := decodeScalar(value)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line.line, err)
			}
			child = &Node{Kind: Scalar, Value: decoded, Line: line.line}
		} else {
			if *index >= len(lines) || lines[*index].indent <= indent {
				return nil, fmt.Errorf("line %d: key %q requires a nested value", line.line, key)
			}
			if lines[*index].indent != indent+2 {
				return nil, fmt.Errorf("line %d: nested value for %q must be indented by two spaces", lines[*index].line, key)
			}
			child, err = parseBlock(lines, index, indent+2)
			if err != nil {
				return nil, err
			}
		}
		node.Pairs = append(node.Pairs, Pair{Key: key, Value: child})
	}
	return node, nil
}

func parseSequence(lines []sourceLine, index *int, indent int) (*Node, error) {
	node := &Node{Kind: Sequence, Line: lines[*index].line}
	for *index < len(lines) {
		line := lines[*index]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", line.line)
		}
		if !strings.HasPrefix(line.text, "-") {
			break
		}
		if line.text == "-" {
			return nil, fmt.Errorf("line %d: nested sequence objects are not supported", line.line)
		}
		if !strings.HasPrefix(line.text, "- ") {
			return nil, fmt.Errorf("line %d: malformed sequence item", line.line)
		}
		value := strings.TrimSpace(strings.TrimPrefix(line.text, "- "))
		if value == "" {
			return nil, fmt.Errorf("line %d: empty sequence item", line.line)
		}
		decoded, err := decodeScalar(value)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line.line, err)
		}
		node.Values = append(node.Values, &Node{Kind: Scalar, Value: decoded, Line: line.line})
		*index++
	}
	return node, nil
}

func splitMapping(text string) (string, string, bool, error) {
	quote := rune(0)
	escaped := false
	for position, r := range text {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if r == '\'' || r == '"' {
			if quote == 0 {
				quote = r
			} else if quote == r {
				quote = 0
			}
			continue
		}
		if r == ':' && quote == 0 {
			key := strings.TrimSpace(text[:position])
			if key == "" {
				return "", "", false, fmt.Errorf("empty mapping key")
			}
			if strings.ContainsAny(key, "{}[],&*!|>@`") {
				return "", "", false, fmt.Errorf("unsupported mapping key %q", key)
			}
			value := strings.TrimSpace(text[position+1:])
			return key, value, value != "", nil
		}
	}
	return "", "", false, fmt.Errorf("mapping entry is missing ':'")
}

func decodeScalar(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{") || strings.HasPrefix(value, "&") || strings.HasPrefix(value, "*") || strings.HasPrefix(value, "!") || strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") {
		return "", fmt.Errorf("unsupported YAML scalar %q", value)
	}
	if value[0] == '\'' {
		if len(value) < 2 || value[len(value)-1] != '\'' {
			return "", fmt.Errorf("unterminated single-quoted scalar")
		}
		return strings.ReplaceAll(value[1:len(value)-1], "''", "'"), nil
	}
	if value[0] == '"' {
		if len(value) < 2 || value[len(value)-1] != '"' {
			return "", fmt.Errorf("unterminated double-quoted scalar")
		}
		decoded, err := strconv.Unquote(value)
		if err != nil {
			return "", fmt.Errorf("invalid double-quoted scalar: %w", err)
		}
		return decoded, nil
	}
	return strings.TrimSpace(value), nil
}

func stripComment(value string) (string, error) {
	quote := rune(0)
	escaped := false
	for position, r := range value {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if r == '\'' || r == '"' {
			if quote == 0 {
				quote = r
			} else if quote == r {
				quote = 0
			}
			continue
		}
		if r == '#' && quote == 0 && (position == 0 || value[position-1] == ' ') {
			return strings.TrimSpace(value[:position]), nil
		}
	}
	if quote != 0 {
		return "", fmt.Errorf("unterminated quoted scalar")
	}
	return strings.TrimSpace(value), nil
}
