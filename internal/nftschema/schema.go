//go:build linux

package nftschema

import (
	"errors"
	"fmt"
)

const (
	FamilyINET    Family = "inet"
	tableName            = "sg_infosec"
	schemaComment        = "sg-infosec:schema-v1"
)

var ErrSchemaConflict = errors.New("nftables owned schema conflict")

type Family string

type Chain struct {
	Name     string
	Comment  string
	Hook     string
	Priority int32
}

type Set struct {
	Name    string
	Comment string
	KeyType string
	Timeout bool
}

type Rule struct {
	Name       string
	Comment    string
	Expression string
	Port       uint16
}

type Schema struct {
	Family  Family
	Table   string
	Comment string
	Chains  []Chain
	Sets    []Set
	Rules   []Rule
}

type ChainState = Chain
type SetState = Set
type RuleState = Rule

type TableState struct {
	Family  Family
	Name    string
	Comment string
	Chains  []ChainState
	Sets    []SetState
	Rules   []RuleState
}

type Snapshot struct {
	Tables []TableState
}

type OperationKind string

const (
	CreateTable OperationKind = "create-table"
	DeleteTable OperationKind = "delete-table"
	CreateChain OperationKind = "create-chain"
	CreateSet   OperationKind = "create-set"
	CreateRule  OperationKind = "create-rule"
)

type Operation struct {
	Kind  OperationKind
	Name  string
	Chain *Chain
	Set   *Set
	Rule  *Rule
}

func Expected() Schema {
	return Schema{
		Family: FamilyINET, Table: tableName, Comment: schemaComment,
		Chains: []Chain{{
			Name: "input", Comment: "sg-infosec:schema-v1:chain:input", Hook: "input", Priority: -10,
		}},
		Sets: []Set{
			{Name: "panel_v4", Comment: "sg-infosec:schema-v1:set:panel-v4", KeyType: "ipv4_addr . inet_service", Timeout: true},
			{Name: "panel_v6", Comment: "sg-infosec:schema-v1:set:panel-v6", KeyType: "ipv6_addr . inet_service", Timeout: true},
			{Name: "ssh_v4", Comment: "sg-infosec:schema-v1:set:ssh-v4", KeyType: "ipv4_addr", Timeout: true},
			{Name: "ssh_v6", Comment: "sg-infosec:schema-v1:set:ssh-v6", KeyType: "ipv6_addr", Timeout: true},
		},
		Rules: []Rule{
			{Name: "panel_v4_drop", Comment: "sg-infosec:schema-v1:rule:panel-v4-drop", Expression: "ip saddr . tcp dport @panel_v4 drop"},
			{Name: "panel_v6_drop", Comment: "sg-infosec:schema-v1:rule:panel-v6-drop", Expression: "ip6 saddr . tcp dport @panel_v6 drop"},
			{Name: "ssh_v4_drop", Comment: "sg-infosec:schema-v1:rule:ssh-v4-drop", Expression: "ip saddr @ssh_v4 tcp dport 22 drop", Port: 22},
			{Name: "ssh_v6_drop", Comment: "sg-infosec:schema-v1:rule:ssh-v6-drop", Expression: "ip6 saddr @ssh_v6 tcp dport 22 drop", Port: 22},
		},
	}
}

func CompleteSnapshot() Snapshot {
	expected := Expected()
	return Snapshot{Tables: []TableState{{
		Family: expected.Family, Name: expected.Table, Comment: expected.Comment,
		Chains: append([]ChainState(nil), expected.Chains...),
		Sets:   append([]SetState(nil), expected.Sets...),
		Rules:  append([]RuleState(nil), expected.Rules...),
	}}}
}

func PlanEnsure(snapshot Snapshot) ([]Operation, error) {
	expected := Expected()
	table, found, err := inspectOwnedTable(snapshot, expected)
	if err != nil {
		return nil, err
	}
	if !found {
		return createAll(expected), nil
	}
	operations := make([]Operation, 0)
	chains, err := missingChains(table.Chains, expected.Chains)
	if err != nil {
		return nil, err
	}
	for index := range chains {
		chain := chains[index]
		operations = append(operations, Operation{Kind: CreateChain, Name: chain.Name, Chain: &chain})
	}
	sets, err := missingSets(table.Sets, expected.Sets)
	if err != nil {
		return nil, err
	}
	for index := range sets {
		set := sets[index]
		operations = append(operations, Operation{Kind: CreateSet, Name: set.Name, Set: &set})
	}
	rules, err := missingRules(table.Rules, expected.Rules)
	if err != nil {
		return nil, err
	}
	for index := range rules {
		rule := rules[index]
		operations = append(operations, Operation{Kind: CreateRule, Name: rule.Name, Rule: &rule})
	}
	return operations, nil
}

func PlanDelete(snapshot Snapshot) ([]Operation, error) {
	expected := Expected()
	_, found, err := inspectOwnedTable(snapshot, expected)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return []Operation{{Kind: DeleteTable, Name: expected.Table}}, nil
}

func createAll(expected Schema) []Operation {
	operations := []Operation{{Kind: CreateTable, Name: expected.Table}}
	for index := range expected.Chains {
		chain := expected.Chains[index]
		operations = append(operations, Operation{Kind: CreateChain, Name: chain.Name, Chain: &chain})
	}
	for index := range expected.Sets {
		set := expected.Sets[index]
		operations = append(operations, Operation{Kind: CreateSet, Name: set.Name, Set: &set})
	}
	for index := range expected.Rules {
		rule := expected.Rules[index]
		operations = append(operations, Operation{Kind: CreateRule, Name: rule.Name, Rule: &rule})
	}
	return operations
}

func inspectOwnedTable(snapshot Snapshot, expected Schema) (TableState, bool, error) {
	var owned *TableState
	for index := range snapshot.Tables {
		table := snapshot.Tables[index]
		if table.Name != expected.Table {
			continue
		}
		if owned != nil {
			return TableState{}, false, conflict("duplicate table")
		}
		copy := table
		owned = &copy
	}
	if owned == nil {
		return TableState{}, false, nil
	}
	if owned.Family != expected.Family || owned.Comment != expected.Comment {
		return TableState{}, false, conflict("table identity differs")
	}
	if _, err := missingChains(owned.Chains, expected.Chains); err != nil {
		return TableState{}, false, err
	}
	if _, err := missingSets(owned.Sets, expected.Sets); err != nil {
		return TableState{}, false, err
	}
	if _, err := missingRules(owned.Rules, expected.Rules); err != nil {
		return TableState{}, false, err
	}
	return *owned, true, nil
}

func missingChains(actual []ChainState, expected []Chain) ([]Chain, error) {
	known := make(map[string]Chain, len(expected))
	for _, item := range expected {
		known[item.Name] = item
	}
	seen := make(map[string]struct{}, len(actual))
	for _, item := range actual {
		want, ok := known[item.Name]
		if !ok || item != want {
			return nil, conflict("unknown or modified chain %q", item.Name)
		}
		if _, duplicate := seen[item.Name]; duplicate {
			return nil, conflict("duplicate chain %q", item.Name)
		}
		seen[item.Name] = struct{}{}
	}
	missing := make([]Chain, 0)
	for _, item := range expected {
		if _, ok := seen[item.Name]; !ok {
			missing = append(missing, item)
		}
	}
	return missing, nil
}

func missingSets(actual []SetState, expected []Set) ([]Set, error) {
	known := make(map[string]Set, len(expected))
	for _, item := range expected {
		known[item.Name] = item
	}
	seen := make(map[string]struct{}, len(actual))
	for _, item := range actual {
		want, ok := known[item.Name]
		if !ok || item != want {
			return nil, conflict("unknown or modified set %q", item.Name)
		}
		if _, duplicate := seen[item.Name]; duplicate {
			return nil, conflict("duplicate set %q", item.Name)
		}
		seen[item.Name] = struct{}{}
	}
	missing := make([]Set, 0)
	for _, item := range expected {
		if _, ok := seen[item.Name]; !ok {
			missing = append(missing, item)
		}
	}
	return missing, nil
}

func missingRules(actual []RuleState, expected []Rule) ([]Rule, error) {
	known := make(map[string]Rule, len(expected))
	for _, item := range expected {
		known[item.Name] = item
	}
	seen := make(map[string]struct{}, len(actual))
	for _, item := range actual {
		want, ok := known[item.Name]
		if !ok || item != want {
			return nil, conflict("unknown or modified rule %q", item.Name)
		}
		if _, duplicate := seen[item.Name]; duplicate {
			return nil, conflict("duplicate rule %q", item.Name)
		}
		seen[item.Name] = struct{}{}
	}
	missing := make([]Rule, 0)
	for _, item := range expected {
		if _, ok := seen[item.Name]; !ok {
			missing = append(missing, item)
		}
	}
	return missing, nil
}

func conflict(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrSchemaConflict, fmt.Sprintf(format, arguments...))
}
