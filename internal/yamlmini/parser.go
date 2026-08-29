// Package yamlmini parses the deliberately small YAML subset used by SG InfoSec
// configuration files. It supports mappings, nested mappings, scalar sequences,
// quoted scalars, and comments. Advanced YAML features are rejected explicitly.
package yamlmini

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type Kind uint8

const (
	Scalar Kind = iota + 1
	Mapping
	Sequence
)

type Pair struct {
	Key   string
	Value *Node
	Line  int
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
	number int
}

var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

func Parse(r io.Reader) (*Node, error) {
	lines, err := scan(r)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty YAML document")
	}
	node, next, err := parseBlock(lines, 0, lines[0].indent)
	if err != nil {
		return nil, err
	}
	if next != len(lines) {
		return nil, fmt.Errorf("line %d: unexpected indentation", lines[next].number)
	}
	return node, nil
}

func scan(r io.Reader) ([]sourceLine, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	var lines []sourceLine
	seenContent := false
	seenEnd := false
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		raw := strings.TrimRight(scanner.Text(), " \r")
		if strings.ContainsRune(raw, '\t') {
			return nil, fmt.Errorf("line %d: tabs are not allowed", lineNumber)
		}
		raw = stripComment(raw)
		if strings.TrimSpace(raw) == "" {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		switch trimmed {
		case "---":
			if seenContent {
				return nil, fmt.Errorf("line %d: multiple YAML documents are not allowed", lineNumber)
			}
			seenContent = true
			continue
		case "...":
			seenEnd = true
			continue
		}
		if seenEnd {
			return nil, fmt.Errorf("line %d: content after YAML document end", lineNumber)
		}
		seenContent = true
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent%2 != 0 {
			return nil, fmt.Errorf("line %d: indentation must use multiples of two spaces", lineNumber)
		}
		lines = append(lines, sourceLine{indent: indent, text: strings.TrimSpace(raw), number: lineNumber})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read YAML: %w", err)
	}
	return lines, nil
}

func stripComment(s string) string {
	var quote rune
	escaped := false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' && (i == 0 || s[i-1] == ' ') {
			return strings.TrimRight(s[:i], " ")
		}
	}
	return s
}

func parseBlock(lines []sourceLine, index, indent int) (*Node, int, error) {
	if index >= len(lines) {
		return nil, index, fmt.Errorf("unexpected end of YAML")
	}
	if lines[index].indent != indent {
		return nil, index, fmt.Errorf("line %d: unexpected indentation", lines[index].number)
	}
	if strings.HasPrefix(lines[index].text, "-") {
		return parseSequence(lines, index, indent)
	}
	return parseMapping(lines, index, indent)
}

func parseMapping(lines []sourceLine, index, indent int) (*Node, int, error) {
	node := &Node{Kind: Mapping, Line: lines[index].number}
	seen := make(map[string]struct{})
	for index < len(lines) {
		line := lines[index]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return nil, index, fmt.Errorf("line %d: unexpected indentation", line.number)
		}
		if strings.HasPrefix(line.text, "-") {
			break
		}
		key, rawValue, err := splitPair(line.text)
		if err != nil {
			return nil, index, fmt.Errorf("line %d: %w", line.number, err)
		}
		if _, exists := seen[key]; exists {
			return nil, index, fmt.Errorf("line %d: duplicate field %q", line.number, key)
		}
		seen[key] = struct{}{}
		index++
		var value *Node
		if rawValue != "" {
			value, err = scalarNode(rawValue, line.number)
			if err != nil {
				return nil, index, err
			}
		} else {
			if index >= len(lines) || lines[index].indent <= indent {
				return nil, index, fmt.Errorf("line %d: field %q requires a value", line.number, key)
			}
			value, index, err = parseBlock(lines, index, lines[index].indent)
			if err != nil {
				return nil, index, err
			}
		}
		node.Pairs = append(node.Pairs, Pair{Key: key, Value: value, Line: line.number})
	}
	return node, index, nil
}

func parseSequence(lines []sourceLine, index, indent int) (*Node, int, error) {
	node := &Node{Kind: Sequence, Line: lines[index].number}
	for index < len(lines) {
		line := lines[index]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return nil, index, fmt.Errorf("line %d: nested sequence values are not supported", line.number)
		}
		if !strings.HasPrefix(line.text, "-") {
			break
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line.text, "-"))
		if raw == "" {
			return nil, index, fmt.Errorf("line %d: sequence item requires a scalar value", line.number)
		}
		value, err := scalarNode(raw, line.number)
		if err != nil {
			return nil, index, err
		}
		node.Values = append(node.Values, value)
		index++
	}
	return node, index, nil
}

func splitPair(s string) (string, string, error) {
	quote := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == ':' {
			key := strings.TrimSpace(s[:i])
			if !keyPattern.MatchString(key) {
				return "", "", fmt.Errorf("invalid field name %q", key)
			}
			return key, strings.TrimSpace(s[i+1:]), nil
		}
	}
	return "", "", fmt.Errorf("expected field: value")
}

func scalarNode(raw string, line int) (*Node, error) {
	if strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "{") || raw == "|" || raw == ">" {
		return nil, fmt.Errorf("line %d: flow collections and multiline scalars are not supported", line)
	}
	if strings.HasPrefix(raw, "&") || strings.HasPrefix(raw, "*") || strings.HasPrefix(raw, "!") {
		return nil, fmt.Errorf("line %d: YAML anchors, aliases, and tags are not supported", line)
	}
	value := raw
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		decoded, err := strconv.Unquote(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid quoted scalar: %w", line, err)
		}
		value = decoded
	} else if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		value = strings.ReplaceAll(raw[1:len(raw)-1], "''", "'")
	}
	return &Node{Kind: Scalar, Value: value, Line: line}, nil
}
