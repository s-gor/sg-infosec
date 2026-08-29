//go:build linux

package nftschema

import (
	"errors"
	"reflect"
	"testing"
)

func TestExpectedSchemaIsFixedAndContainsNoVPNPorts(t *testing.T) {
	schema := Expected()
	if schema.Family != FamilyINET || schema.Table != "sg_infosec" || schema.Comment != "sg-infosec:schema-v1" {
		t.Fatalf("schema=%+v", schema)
	}
	if len(schema.Chains) != 1 || schema.Chains[0].Name != "input" || schema.Chains[0].Hook != "input" {
		t.Fatalf("chains=%+v", schema.Chains)
	}
	wantSets := []string{"panel_v4", "panel_v6", "ssh_v4", "ssh_v6"}
	gotSets := make([]string, 0, len(schema.Sets))
	for _, set := range schema.Sets {
		gotSets = append(gotSets, set.Name)
	}
	if !reflect.DeepEqual(gotSets, wantSets) {
		t.Fatalf("sets=%v", gotSets)
	}
	for _, rule := range schema.Rules {
		for _, port := range []uint16{585, 586, 587} {
			if rule.Port == port {
				t.Fatalf("VPN port %d appears in rule %+v", port, rule)
			}
		}
	}
}

func TestPlanEnsureCreatesCompleteSchemaInDeterministicOrder(t *testing.T) {
	operations, err := PlanEnsure(Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	want := []OperationKind{
		CreateTable,
		CreateChain,
		CreateSet, CreateSet, CreateSet, CreateSet,
		CreateRule, CreateRule, CreateRule, CreateRule,
	}
	got := make([]OperationKind, 0, len(operations))
	for _, operation := range operations {
		got = append(got, operation.Kind)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("operations=%+v", operations)
	}
	if operations[0].Name != "sg_infosec" || operations[2].Name != "panel_v4" || operations[len(operations)-1].Name != "ssh_v6_drop" {
		t.Fatalf("operations=%+v", operations)
	}
}

func TestPlanEnsureRepairsOnlyMissingKnownObjects(t *testing.T) {
	expected := Expected()
	snapshot := Snapshot{Tables: []TableState{{
		Family: expected.Family, Name: expected.Table, Comment: expected.Comment,
		Chains: []ChainState{{Name: expected.Chains[0].Name, Comment: expected.Chains[0].Comment, Hook: expected.Chains[0].Hook, Priority: expected.Chains[0].Priority}},
		Sets: []SetState{
			{Name: expected.Sets[0].Name, Comment: expected.Sets[0].Comment, KeyType: expected.Sets[0].KeyType, Timeout: true},
			{Name: expected.Sets[1].Name, Comment: expected.Sets[1].Comment, KeyType: expected.Sets[1].KeyType, Timeout: true},
		},
	}}}
	operations, err := PlanEnsure(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 6 {
		t.Fatalf("operations=%+v", operations)
	}
	if operations[0].Kind != CreateSet || operations[0].Name != "ssh_v4" || operations[2].Kind != CreateRule {
		t.Fatalf("operations=%+v", operations)
	}
}

func TestForeignTablesAreIgnored(t *testing.T) {
	snapshot := Snapshot{Tables: []TableState{{Family: FamilyINET, Name: "sg_gateway_awg", Comment: "foreign"}}}
	operations, err := PlanEnsure(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 10 || operations[0].Kind != CreateTable {
		t.Fatalf("operations=%+v", operations)
	}
}

func TestPlanEnsureCompleteSchemaIsNoOp(t *testing.T) {
	operations, err := PlanEnsure(CompleteSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 0 {
		t.Fatalf("operations=%+v", operations)
	}
}

func TestUnknownOrModifiedOwnedObjectsStopEnsure(t *testing.T) {
	cases := []Snapshot{
		{Tables: []TableState{{Family: FamilyINET, Name: "sg_infosec", Comment: "foreign"}}},
		func() Snapshot {
			s := CompleteSnapshot()
			s.Tables[0].Sets = append(s.Tables[0].Sets, SetState{Name: "mystery", Comment: "foreign", KeyType: "ipv4_addr"})
			return s
		}(),
		func() Snapshot { s := CompleteSnapshot(); s.Tables[0].Chains[0].Priority++; return s }(),
		func() Snapshot {
			s := CompleteSnapshot()
			s.Tables[0].Rules[0].Expression = "accept everything"
			return s
		}(),
		func() Snapshot { s := CompleteSnapshot(); s.Tables = append(s.Tables, s.Tables[0]); return s }(),
	}
	for index, snapshot := range cases {
		operations, err := PlanEnsure(snapshot)
		if !errors.Is(err, ErrSchemaConflict) || len(operations) != 0 {
			t.Fatalf("case %d operations=%+v err=%v", index, operations, err)
		}
	}
}

func TestPlanDeleteRemovesOnlyRecognizedOwnedTable(t *testing.T) {
	operations, err := PlanDelete(CompleteSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].Kind != DeleteTable || operations[0].Name != "sg_infosec" {
		t.Fatalf("operations=%+v", operations)
	}
	operations, err = PlanDelete(Snapshot{})
	if err != nil || len(operations) != 0 {
		t.Fatalf("empty operations=%+v err=%v", operations, err)
	}
	conflict := CompleteSnapshot()
	conflict.Tables[0].Rules = append(conflict.Tables[0].Rules, RuleState{Name: "foreign", Comment: "foreign", Expression: "drop"})
	if operations, err = PlanDelete(conflict); !errors.Is(err, ErrSchemaConflict) || len(operations) != 0 {
		t.Fatalf("conflict operations=%+v err=%v", operations, err)
	}
}
