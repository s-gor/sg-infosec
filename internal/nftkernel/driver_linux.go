//go:build linux

package nftkernel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/s-gor/sg-infosec/internal/nftbackend"
	"github.com/s-gor/sg-infosec/internal/nftentries"
	"github.com/s-gor/sg-infosec/internal/nftnetlink"
	"github.com/s-gor/sg-infosec/internal/nftschema"
)

const (
	nlaNested  uint16 = 1 << 15
	familyINet uint8  = 1

	nftaTableName         = 1
	nftaTableUserdata     = 6
	nftaChainTable        = 1
	nftaChainName         = 3
	nftaChainHook         = 4
	nftaChainType         = 7
	nftaChainUserdata     = 12
	nftaHookHooknum       = 1
	nftaHookPriority      = 2
	nftaSetTable          = 1
	nftaSetName           = 2
	nftaSetFlags          = 3
	nftaSetKeyType        = 4
	nftaSetKeyLen         = 5
	nftaSetDesc           = 9
	nftaSetID             = 10
	nftaSetUserdata       = 13
	nftaSetDescConcat     = 2
	nftaSetFieldLen       = 1
	nftaRuleTable         = 1
	nftaRuleChain         = 2
	nftaRuleExpressions   = 4
	nftaRuleUserdata      = 7
	nftaListElem          = 1
	nftaExprName          = 1
	nftaExprData          = 2
	nftaPayloadDreg       = 1
	nftaPayloadBase       = 2
	nftaPayloadOffset     = 3
	nftaPayloadLen        = 4
	nftaMetaDreg          = 1
	nftaMetaKey           = 2
	nftaCmpSreg           = 1
	nftaCmpOp             = 2
	nftaCmpData           = 3
	nftaLookupSet         = 1
	nftaLookupSreg        = 2
	nftaLookupSetID       = 4
	nftaImmediateDreg     = 1
	nftaImmediateData     = 2
	nftaDataValue         = 1
	nftaDataVerdict       = 2
	nftaVerdictCode       = 1
	nftaElemListTable     = 1
	nftaElemListSet       = 2
	nftaElemListElements  = 3
	nftaSetElemKey        = 1
	nftaSetElemTimeout    = 4
	nftaSetElemExpiration = 5

	nftSetTimeout = 0x10
	nftSetConcat  = 0x80

	nftTypeBits         uint32 = 6
	nftTypeIPv4Addr     uint32 = 7
	nftTypeIPv6Addr     uint32 = 8
	nftTypeInetService  uint32 = 13
	nftPayloadNetwork          = 1
	nftPayloadTransport        = 2
	nftMetaL4Proto             = 16
	nftCmpEQ                   = 0
	nfDrop                     = 0
)

type Driver struct {
	client   *nftnetlink.Client
	sequence atomic.Uint32
}

func New(raw nftnetlink.RawTransport) *Driver { return &Driver{client: nftnetlink.NewClient(raw)} }
func NewSocketDriver() *Driver                { return New(nftnetlink.NewSocketTransport()) }
func (d *Driver) next() uint32 {
	value := d.sequence.Add(1)
	if value == 0 {
		value = d.sequence.Add(1)
	}
	return value
}

func (d *Driver) Inspect(ctx context.Context) (nftschema.Snapshot, error) {
	if d == nil || d.client == nil {
		return nftschema.Snapshot{}, fmt.Errorf("nftables driver is not initialized")
	}
	tables, err := d.dump(ctx, nftnetlink.MessageGetTable, nil)
	if err != nil {
		return nftschema.Snapshot{}, fmt.Errorf("dump tables: %w", err)
	}
	owned := false
	tableState := nftschema.TableState{}
	for _, m := range tables {
		name := stringAttr(m.Attributes, nftaTableName)
		if name != "sg_infosec" {
			continue
		}
		if owned {
			return nftschema.Snapshot{}, fmt.Errorf("duplicate owned table")
		}
		owned = true
		tableState = nftschema.TableState{Family: nftschema.FamilyINET, Name: name, Comment: stringAttr(m.Attributes, nftaTableUserdata)}
	}
	if !owned {
		return nftschema.Snapshot{}, nil
	}
	chains, err := d.dump(ctx, nftnetlink.MessageGetChain, []nftnetlink.Attribute{strAttr(nftaChainTable, "sg_infosec")})
	if err != nil {
		return nftschema.Snapshot{}, err
	}
	for _, m := range chains {
		if stringAttr(m.Attributes, nftaChainTable) != "sg_infosec" {
			continue
		}
		hook, priority, err := decodeHook(findAttr(m.Attributes, nftaChainHook))
		if err != nil {
			return nftschema.Snapshot{}, err
		}
		tableState.Chains = append(tableState.Chains, nftschema.ChainState{Name: stringAttr(m.Attributes, nftaChainName), Comment: stringAttr(m.Attributes, nftaChainUserdata), Hook: hook, Priority: priority})
	}
	sets, err := d.dump(ctx, nftnetlink.MessageGetSet, []nftnetlink.Attribute{strAttr(nftaSetTable, "sg_infosec")})
	if err != nil {
		return nftschema.Snapshot{}, err
	}
	for _, m := range sets {
		if stringAttr(m.Attributes, nftaSetTable) != "sg_infosec" {
			continue
		}
		state, err := decodeSet(m.Attributes)
		if err != nil {
			return nftschema.Snapshot{}, err
		}
		tableState.Sets = append(tableState.Sets, state)
	}
	rules, err := d.dump(ctx, nftnetlink.MessageGetRule, []nftnetlink.Attribute{strAttr(nftaRuleTable, "sg_infosec")})
	if err != nil {
		return nftschema.Snapshot{}, err
	}
	for _, m := range rules {
		if stringAttr(m.Attributes, nftaRuleTable) != "sg_infosec" {
			continue
		}
		comment := stringAttr(m.Attributes, nftaRuleUserdata)
		name, expected, ok := ruleByComment(comment)
		if !ok {
			tableState.Rules = append(tableState.Rules, nftschema.RuleState{Name: "unknown", Comment: comment})
			continue
		}
		expression, port, err := decodeRuleExpressions(findAttr(m.Attributes, nftaRuleExpressions))
		if err != nil {
			return nftschema.Snapshot{}, fmt.Errorf("decode rule %s: %w", name, err)
		}
		if expression != expected.Expression || port != expected.Port {
			return nftschema.Snapshot{}, fmt.Errorf("rule %s semantic mismatch: %s", name, expression)
		}
		tableState.Rules = append(tableState.Rules, nftschema.RuleState{Name: name, Comment: comment, Expression: expression, Port: port})
	}
	return nftschema.Snapshot{Tables: []nftschema.TableState{tableState}}, nil
}

func (d *Driver) ApplySchema(ctx context.Context, operations []nftschema.Operation) error {
	if len(operations) == 0 {
		return nil
	}
	setIDs := map[string]uint32{}
	nextID := uint32(1)
	for _, op := range operations {
		if op.Kind == nftschema.CreateSet {
			setIDs[op.Name] = nextID
			nextID++
		}
	}
	messages := []nftnetlink.Message{nftnetlink.BatchBegin(d.next())}
	for _, op := range operations {
		seq := d.next()
		var m nftnetlink.Message
		var err error
		switch op.Kind {
		case nftschema.CreateTable:
			m = newTable(seq)
		case nftschema.DeleteTable:
			m = deleteTable(seq)
		case nftschema.CreateChain:
			m = newChain(seq, *op.Chain)
		case nftschema.CreateSet:
			m, err = newSet(seq, *op.Set, setIDs[op.Name])
		case nftschema.CreateRule:
			m, err = newRule(seq, *op.Rule, setIDs)
		default:
			err = fmt.Errorf("unsupported schema operation %q", op.Kind)
		}
		if err != nil {
			return err
		}
		messages = append(messages, m)
	}
	messages = append(messages, nftnetlink.BatchEnd(d.next()))
	_, err := d.client.Exchange(ctx, messages)
	return err
}

func (d *Driver) ListElements(ctx context.Context) ([]nftentries.Element, error) {
	var result []nftentries.Element
	for _, setName := range []string{"panel_v4", "panel_v6", "ssh_v4", "ssh_v6"} {
		messages, err := d.dump(ctx, nftnetlink.MessageGetSetElement, []nftnetlink.Attribute{strAttr(nftaElemListTable, "sg_infosec"), strAttr(nftaElemListSet, setName)})
		if err != nil {
			return nil, err
		}
		for _, m := range messages {
			elements, err := decodeElements(m.Attributes, setName)
			if err != nil {
				return nil, err
			}
			result = append(result, elements...)
		}
	}
	return result, nil
}
func (d *Driver) AddElement(ctx context.Context, element nftentries.Element) error {
	return d.applyElements(ctx, nil, []nftentries.Element{element})
}
func (d *Driver) RemoveElement(ctx context.Context, key nftentries.ElementKey) error {
	return d.applyElements(ctx, []nftentries.ElementKey{key}, nil)
}
func (d *Driver) ApplyElementPlan(ctx context.Context, plan nftentries.Plan) error {
	removes := make([]nftentries.ElementKey, 0, len(plan.Remove)+len(plan.Update))
	for _, e := range append(append([]nftentries.Element(nil), plan.Remove...), plan.Update...) {
		removes = append(removes, e.ElementKey())
	}
	adds := append(append([]nftentries.Element(nil), plan.Add...), plan.Update...)
	return d.applyElements(ctx, removes, adds)
}
func (d *Driver) applyElements(ctx context.Context, removes []nftentries.ElementKey, adds []nftentries.Element) error {
	messages := []nftnetlink.Message{nftnetlink.BatchBegin(d.next())}
	for _, key := range removes {
		messages = append(messages, elementMessage(d.next(), nftnetlink.MessageDeleteSetElement, key.SetName, key.Key, 0))
	}
	for _, element := range adds {
		messages = append(messages, elementMessage(d.next(), nftnetlink.MessageNewSetElement, element.SetName, element.Key, element.Timeout))
	}
	messages = append(messages, nftnetlink.BatchEnd(d.next()))
	_, err := d.client.Exchange(ctx, messages)
	return err
}
func (d *Driver) PurgeOwnedTable(ctx context.Context) error {
	snapshot, err := d.Inspect(ctx)
	if err != nil {
		return err
	}
	ops, err := nftschema.PlanDelete(snapshot)
	if err != nil {
		return err
	}
	return d.ApplySchema(ctx, ops)
}

func (d *Driver) dump(ctx context.Context, operation nftnetlink.MessageOperation, attrs []nftnetlink.Attribute) ([]nftnetlink.Message, error) {
	seq := d.next()
	return d.client.Exchange(ctx, []nftnetlink.Message{{Header: nftnetlink.Header{Type: nftnetlink.NFTablesType(operation), Flags: nftnetlink.FlagRequest | nftnetlink.FlagDump, Seq: seq}, Family: familyINet, Attributes: attrs}})
}

func newTable(seq uint32) nftnetlink.Message {
	return mutation(seq, nftnetlink.MessageNewTable, []nftnetlink.Attribute{strAttr(nftaTableName, "sg_infosec"), rawAttr(nftaTableUserdata, []byte("sg-infosec:schema-v1"))})
}
func deleteTable(seq uint32) nftnetlink.Message {
	return mutationType(seq, nftnetlink.MessageDeleteTable, nftnetlink.FlagRequest|nftnetlink.FlagAck, []nftnetlink.Attribute{strAttr(nftaTableName, "sg_infosec")})
}
func newChain(seq uint32, chain nftschema.Chain) nftnetlink.Message {
	hook := nested(nftaChainHook, []nftnetlink.Attribute{u32Attr(nftaHookHooknum, 1), u32AttrSigned(nftaHookPriority, chain.Priority)})
	return mutation(seq, nftnetlink.MessageNewChain, []nftnetlink.Attribute{strAttr(nftaChainTable, "sg_infosec"), strAttr(nftaChainName, chain.Name), strAttr(nftaChainType, "filter"), hook, rawAttr(nftaChainUserdata, []byte(chain.Comment))})
}
func newSet(seq uint32, set nftschema.Set, id uint32) (nftnetlink.Message, error) {
	keyLen, keyType, fields, err := setLayout(set.Name)
	if err != nil {
		return nftnetlink.Message{}, err
	}
	flags := uint32(nftSetTimeout)
	attrs := []nftnetlink.Attribute{strAttr(nftaSetTable, "sg_infosec"), strAttr(nftaSetName, set.Name), u32Attr(nftaSetFlags, flags), u32Attr(nftaSetKeyType, keyType), u32Attr(nftaSetKeyLen, uint32(keyLen)), u32Attr(nftaSetID, id), rawAttr(nftaSetUserdata, []byte(set.Comment))}
	if len(fields) > 1 {
		flags |= nftSetConcat
		attrs[2] = u32Attr(nftaSetFlags, flags)
		list := []nftnetlink.Attribute{}
		for _, bits := range fields {
			list = append(list, nested(nftaListElem, []nftnetlink.Attribute{u32Attr(nftaSetFieldLen, uint32(bits))}))
		}
		attrs = append(attrs, nested(nftaSetDesc, []nftnetlink.Attribute{nested(nftaSetDescConcat, list)}))
	}
	return mutation(seq, nftnetlink.MessageNewSet, attrs), nil
}
func newRule(seq uint32, rule nftschema.Rule, setIDs map[string]uint32) (nftnetlink.Message, error) {
	expressions, err := encodeRule(rule, setIDs)
	if err != nil {
		return nftnetlink.Message{}, err
	}
	return mutation(seq, nftnetlink.MessageNewRule, []nftnetlink.Attribute{strAttr(nftaRuleTable, "sg_infosec"), strAttr(nftaRuleChain, "input"), nested(nftaRuleExpressions, expressions), rawAttr(nftaRuleUserdata, []byte(rule.Comment))}), nil
}
func mutation(seq uint32, op nftnetlink.MessageOperation, attrs []nftnetlink.Attribute) nftnetlink.Message {
	return mutationType(seq, op, nftnetlink.FlagRequest|nftnetlink.FlagAck|nftnetlink.FlagCreate|nftnetlink.FlagExclusive, attrs)
}
func mutationType(seq uint32, op nftnetlink.MessageOperation, flags uint16, attrs []nftnetlink.Attribute) nftnetlink.Message {
	return nftnetlink.Message{Header: nftnetlink.Header{Type: nftnetlink.NFTablesType(op), Flags: flags, Seq: seq}, Family: familyINet, Attributes: attrs}
}

func encodeRule(rule nftschema.Rule, setIDs map[string]uint32) ([]nftnetlink.Attribute, error) {
	ipv6 := strings.Contains(rule.Name, "v6")
	panel := strings.HasPrefix(rule.Name, "panel")
	addrLen := uint32(4)
	addrOffset := uint32(12)
	setName := "ssh_v4"
	if ipv6 {
		addrLen = 16
		addrOffset = 8
		setName = "ssh_v6"
	}
	if panel {
		if ipv6 {
			setName = "panel_v6"
		} else {
			setName = "panel_v4"
		}
	}
	exprs := []nftnetlink.Attribute{expr("meta", []nftnetlink.Attribute{u32Attr(nftaMetaDreg, 8), u32Attr(nftaMetaKey, nftMetaL4Proto)}), expr("cmp", []nftnetlink.Attribute{u32Attr(nftaCmpSreg, 8), u32Attr(nftaCmpOp, nftCmpEQ), dataValue(nftaCmpData, []byte{6})})}
	if panel {
		portReg := uint32(9)
		if ipv6 {
			portReg = 12
		}
		exprs = append(exprs, expr("payload", []nftnetlink.Attribute{u32Attr(nftaPayloadDreg, 8), u32Attr(nftaPayloadBase, nftPayloadNetwork), u32Attr(nftaPayloadOffset, addrOffset), u32Attr(nftaPayloadLen, addrLen)}), expr("payload", []nftnetlink.Attribute{u32Attr(nftaPayloadDreg, portReg), u32Attr(nftaPayloadBase, nftPayloadTransport), u32Attr(nftaPayloadOffset, 2), u32Attr(nftaPayloadLen, 2)}), lookupExpr(setName, 8, setIDs[setName]))
	} else {
		exprs = append(exprs, expr("payload", []nftnetlink.Attribute{u32Attr(nftaPayloadDreg, 8), u32Attr(nftaPayloadBase, nftPayloadNetwork), u32Attr(nftaPayloadOffset, addrOffset), u32Attr(nftaPayloadLen, addrLen)}), lookupExpr(setName, 8, setIDs[setName]), expr("payload", []nftnetlink.Attribute{u32Attr(nftaPayloadDreg, 8), u32Attr(nftaPayloadBase, nftPayloadTransport), u32Attr(nftaPayloadOffset, 2), u32Attr(nftaPayloadLen, 2)}), expr("cmp", []nftnetlink.Attribute{u32Attr(nftaCmpSreg, 8), u32Attr(nftaCmpOp, nftCmpEQ), dataValue(nftaCmpData, []byte{0, 22})}))
	}
	exprs = append(exprs, expr("immediate", []nftnetlink.Attribute{u32Attr(nftaImmediateDreg, 0), nested(nftaImmediateData, []nftnetlink.Attribute{nested(nftaDataVerdict, []nftnetlink.Attribute{u32Attr(nftaVerdictCode, nfDrop)})})}))
	return exprs, nil
}
func lookupExpr(set string, sreg, id uint32) nftnetlink.Attribute {
	attrs := []nftnetlink.Attribute{strAttr(nftaLookupSet, set), u32Attr(nftaLookupSreg, sreg)}
	if id != 0 {
		attrs = append(attrs, u32Attr(nftaLookupSetID, id))
	}
	return expr("lookup", attrs)
}
func expr(name string, data []nftnetlink.Attribute) nftnetlink.Attribute {
	return nested(nftaListElem, []nftnetlink.Attribute{strAttr(nftaExprName, name), nested(nftaExprData, data)})
}

func elementMessage(seq uint32, op nftnetlink.MessageOperation, set string, key []byte, timeout time.Duration) nftnetlink.Message {
	elementAttrs := []nftnetlink.Attribute{nested(nftaSetElemKey, []nftnetlink.Attribute{rawAttr(nftaDataValue, key)})}
	if timeout > 0 {
		elementAttrs = append(elementAttrs, u64Attr(nftaSetElemTimeout, uint64(timeout/time.Millisecond)))
	}
	element := nested(nftaListElem, elementAttrs)
	flags := nftnetlink.FlagRequest | nftnetlink.FlagAck
	if op == nftnetlink.MessageNewSetElement {
		flags |= nftnetlink.FlagCreate | nftnetlink.FlagReplace
	}
	return mutationType(seq, op, flags, []nftnetlink.Attribute{strAttr(nftaElemListTable, "sg_infosec"), strAttr(nftaElemListSet, set), nested(nftaElemListElements, []nftnetlink.Attribute{element})})
}

func decodeSet(attrs []nftnetlink.Attribute) (nftschema.SetState, error) {
	name := stringAttr(attrs, nftaSetName)
	comment := stringAttr(attrs, nftaSetUserdata)
	flags := u32(findAttr(attrs, nftaSetFlags))
	keyLen := int(u32(findAttr(attrs, nftaSetKeyLen)))
	wantLen, wantType, fields, err := setLayout(name)
	if err != nil {
		return nftschema.SetState{Name: name, Comment: comment}, nil
	}
	if keyLen != wantLen || u32(findAttr(attrs, nftaSetKeyType)) != wantType || flags&nftSetTimeout == 0 {
		return nftschema.SetState{Name: name, Comment: comment}, nil
	}
	if len(fields) > 1 {
		if flags&nftSetConcat == 0 || !concatMatches(findAttr(attrs, nftaSetDesc), fields) {
			return nftschema.SetState{Name: name, Comment: comment}, nil
		}
	}
	keyType := map[string]string{"panel_v4": "ipv4_addr . inet_service", "panel_v6": "ipv6_addr . inet_service", "ssh_v4": "ipv4_addr", "ssh_v6": "ipv6_addr"}[name]
	return nftschema.SetState{Name: name, Comment: comment, KeyType: keyType, Timeout: true}, nil
}
func concatMatches(attr nftnetlink.Attribute, fields []int) bool {
	desc, err := decodeNested(attr)
	if err != nil {
		return false
	}
	concat := findAttr(desc, nftaSetDescConcat)
	items, err := decodeNested(concat)
	if err != nil || len(items) != len(fields) {
		return false
	}
	for i, item := range items {
		sub, err := decodeNested(item)
		if err != nil || int(u32(findAttr(sub, nftaSetFieldLen))) != fields[i] {
			return false
		}
	}
	return true
}
func decodeHook(attr nftnetlink.Attribute) (string, int32, error) {
	attrs, err := decodeNested(attr)
	if err != nil {
		return "", 0, err
	}
	if u32(findAttr(attrs, nftaHookHooknum)) != 1 {
		return "unknown", 0, nil
	}
	return "input", int32(u32(findAttr(attrs, nftaHookPriority))), nil
}

type decodedRuleExpression struct {
	kind                 string
	register             int
	base, offset, length uint32
	value                []byte
	set                  string
}

func decodeRuleExpressions(attr nftnetlink.Attribute) (string, uint16, error) {
	items, err := decodeNested(attr)
	if err != nil {
		return "", 0, err
	}
	expressions := make([]decodedRuleExpression, 0, len(items))
	for _, item := range items {
		sub, err := decodeNested(item)
		if err != nil {
			return "", 0, err
		}
		name := stringAttr(sub, nftaExprName)
		data, err := decodeNested(findAttr(sub, nftaExprData))
		if err != nil {
			return "", 0, err
		}
		switch name {
		case "meta":
			if key := u32(findAttr(data, nftaMetaKey)); key != nftMetaL4Proto {
				return "", 0, fmt.Errorf("unsupported meta key %d", key)
			}
			register := regOffset(u32(findAttr(data, nftaMetaDreg)))
			if register < 0 {
				return "", 0, fmt.Errorf("invalid meta destination register")
			}
			expressions = append(expressions, decodedRuleExpression{kind: "meta-l4proto", register: register})
		case "payload":
			register := regOffset(u32(findAttr(data, nftaPayloadDreg)))
			if register < 0 {
				return "", 0, fmt.Errorf("invalid payload destination register")
			}
			expressions = append(expressions, decodedRuleExpression{
				kind: "payload", register: register,
				base:   u32(findAttr(data, nftaPayloadBase)),
				offset: u32(findAttr(data, nftaPayloadOffset)),
				length: u32(findAttr(data, nftaPayloadLen)),
			})
		case "cmp":
			if operation := u32(findAttr(data, nftaCmpOp)); operation != nftCmpEQ {
				return "", 0, fmt.Errorf("unsupported comparison operation %d", operation)
			}
			register := regOffset(u32(findAttr(data, nftaCmpSreg)))
			if register < 0 {
				return "", 0, fmt.Errorf("invalid comparison source register")
			}
			value, err := nestedValue(findAttr(data, nftaCmpData))
			if err != nil {
				return "", 0, err
			}
			expressions = append(expressions, decodedRuleExpression{kind: "compare", register: register, value: value})
		case "lookup":
			register := regOffset(u32(findAttr(data, nftaLookupSreg)))
			set := stringAttr(data, nftaLookupSet)
			if register < 0 || set == "" {
				return "", 0, fmt.Errorf("invalid lookup expression")
			}
			expressions = append(expressions, decodedRuleExpression{kind: "lookup", register: register, set: set})
		case "immediate":
			if u32(findAttr(data, nftaImmediateDreg)) != 0 {
				return "", 0, fmt.Errorf("immediate expression does not target verdict register")
			}
			verdictAttrs, err := decodeNested(findAttr(data, nftaImmediateData))
			if err != nil {
				return "", 0, err
			}
			verdict, err := decodeNested(findAttr(verdictAttrs, nftaDataVerdict))
			if err != nil {
				return "", 0, err
			}
			if u32(findAttr(verdict, nftaVerdictCode)) != nfDrop {
				return "", 0, fmt.Errorf("immediate verdict is not drop")
			}
			expressions = append(expressions, decodedRuleExpression{kind: "drop"})
		default:
			return "", 0, fmt.Errorf("unknown expression %q", name)
		}
	}

	if len(expressions) < 4 || !matchMetaTCP(expressions[0], expressions[1]) {
		return "", 0, fmt.Errorf("missing canonical TCP prefix")
	}
	lookupSet := ""
	for _, expression := range expressions {
		if expression.kind == "lookup" {
			if lookupSet != "" {
				return "", 0, fmt.Errorf("multiple lookup expressions")
			}
			lookupSet = expression.set
		}
	}
	switch lookupSet {
	case "panel_v4":
		if !matchPanelRule(expressions, 4, 12, "panel_v4") {
			return "", 0, fmt.Errorf("panel_v4 rule semantic mismatch")
		}
		return "ip saddr . tcp dport @panel_v4 drop", 0, nil
	case "panel_v6":
		if !matchPanelRule(expressions, 16, 8, "panel_v6") {
			return "", 0, fmt.Errorf("panel_v6 rule semantic mismatch")
		}
		return "ip6 saddr . tcp dport @panel_v6 drop", 0, nil
	case "ssh_v4":
		if !matchSSHRule(expressions, 4, 12, "ssh_v4") {
			return "", 0, fmt.Errorf("ssh_v4 rule semantic mismatch")
		}
		return "ip saddr @ssh_v4 tcp dport 22 drop", 22, nil
	case "ssh_v6":
		if !matchSSHRule(expressions, 16, 8, "ssh_v6") {
			return "", 0, fmt.Errorf("ssh_v6 rule semantic mismatch")
		}
		return "ip6 saddr @ssh_v6 tcp dport 22 drop", 22, nil
	default:
		return "", 0, fmt.Errorf("unknown lookup set %q", lookupSet)
	}
}

func matchMetaTCP(meta, comparison decodedRuleExpression) bool {
	return meta.kind == "meta-l4proto" && meta.register == 0 &&
		comparison.kind == "compare" && comparison.register == 0 &&
		len(comparison.value) == 1 && comparison.value[0] == 6
}

func matchPanelRule(expressions []decodedRuleExpression, addressLength, addressOffset int, set string) bool {
	if len(expressions) != 6 {
		return false
	}
	address := expressions[2]
	port := expressions[3]
	lookup := expressions[4]
	return address.kind == "payload" && address.register == 0 &&
		address.base == nftPayloadNetwork && address.offset == uint32(addressOffset) && address.length == uint32(addressLength) &&
		port.kind == "payload" && port.register == addressLength &&
		port.base == nftPayloadTransport && port.offset == 2 && port.length == 2 &&
		lookup.kind == "lookup" && lookup.register == 0 && lookup.set == set &&
		expressions[5].kind == "drop"
}

func matchSSHRule(expressions []decodedRuleExpression, addressLength, addressOffset int, set string) bool {
	if len(expressions) != 7 {
		return false
	}
	address := expressions[2]
	lookup := expressions[3]
	port := expressions[4]
	comparison := expressions[5]
	return address.kind == "payload" && address.register == 0 &&
		address.base == nftPayloadNetwork && address.offset == uint32(addressOffset) && address.length == uint32(addressLength) &&
		lookup.kind == "lookup" && lookup.register == 0 && lookup.set == set &&
		port.kind == "payload" && port.register == 0 &&
		port.base == nftPayloadTransport && port.offset == 2 && port.length == 2 &&
		comparison.kind == "compare" && comparison.register == 0 &&
		len(comparison.value) == 2 && binary.BigEndian.Uint16(comparison.value) == 22 &&
		expressions[6].kind == "drop"
}

func regOffset(reg uint32) int {
	if reg >= 8 {
		return int(reg-8) * 4
	}
	if reg >= 1 && reg <= 4 {
		return int(reg-1) * 16
	}
	return -1
}
func ruleByComment(comment string) (string, nftschema.Rule, bool) {
	for _, r := range nftschema.Expected().Rules {
		if r.Comment == comment {
			return r.Name, r, true
		}
	}
	return "", nftschema.Rule{}, false
}

func decodeElements(attrs []nftnetlink.Attribute, set string) ([]nftentries.Element, error) {
	outer := findAttr(attrs, nftaElemListElements)
	if len(outer.Data) == 0 {
		return nil, nil
	}
	items, err := decodeNested(outer)
	if err != nil {
		return nil, err
	}
	result := make([]nftentries.Element, 0, len(items))
	for _, item := range items {
		sub, err := decodeNested(item)
		if err != nil {
			return nil, err
		}
		key, err := nestedValue(findAttr(sub, nftaSetElemKey))
		if err != nil {
			return nil, err
		}
		millis := u64(findAttr(sub, nftaSetElemExpiration))
		if millis == 0 {
			millis = u64(findAttr(sub, nftaSetElemTimeout))
		}
		if millis == 0 {
			return nil, fmt.Errorf("set element without timeout")
		}
		result = append(result, nftentries.Element{SetName: set, Key: key, Timeout: time.Duration(millis) * time.Millisecond})
	}
	return result, nil
}
func setLayout(name string) (int, uint32, []int, error) {
	switch name {
	case "ssh_v4":
		return 4, nftTypeIPv4Addr, []int{4}, nil
	case "ssh_v6":
		return 16, nftTypeIPv6Addr, []int{16}, nil
	case "panel_v4":
		return 8, concatType(nftTypeIPv4Addr, nftTypeInetService), []int{4, 2}, nil
	case "panel_v6":
		return 20, concatType(nftTypeIPv6Addr, nftTypeInetService), []int{16, 2}, nil
	}
	return 0, 0, nil, fmt.Errorf("unknown set %q", name)
}

func concatType(left, right uint32) uint32 {
	return left<<nftTypeBits | right
}

func rawAttr(t uint16, data []byte) nftnetlink.Attribute {
	return nftnetlink.Attribute{Type: t, Data: append([]byte(nil), data...)}
}
func strAttr(t uint16, value string) nftnetlink.Attribute {
	return rawAttr(t, append([]byte(value), 0))
}
func u32Attr(t uint16, value uint32) nftnetlink.Attribute {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return rawAttr(t, data)
}
func u32AttrSigned(t uint16, value int32) nftnetlink.Attribute { return u32Attr(t, uint32(value)) }
func u64Attr(t uint16, value uint64) nftnetlink.Attribute {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, value)
	return rawAttr(t, data)
}
func nested(t uint16, attrs []nftnetlink.Attribute) nftnetlink.Attribute {
	data, _ := encodeAttrs(attrs)
	return rawAttr(t|nlaNested, data)
}
func dataValue(t uint16, value []byte) nftnetlink.Attribute {
	return nested(t, []nftnetlink.Attribute{rawAttr(nftaDataValue, value)})
}
func encodeAttrs(attrs []nftnetlink.Attribute) ([]byte, error) {
	m := nftnetlink.Message{Header: nftnetlink.Header{Type: 1}, Attributes: attrs}
	encoded, err := nftnetlink.Encode(m)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), encoded[nftnetlink.HeaderLength+nftnetlink.NFGenLength:]...), nil
}
func decodeNested(attr nftnetlink.Attribute) ([]nftnetlink.Attribute, error) {
	if len(attr.Data) == 0 {
		return nil, fmt.Errorf("missing nested attribute %d", attr.Type&^nlaNested)
	}
	padding := (4 - len(attr.Data)%4) % 4
	frame := make([]byte, nftnetlink.HeaderLength+nftnetlink.NFGenLength+len(attr.Data)+padding)
	binary.NativeEndian.PutUint32(frame[:4], uint32(nftnetlink.HeaderLength+nftnetlink.NFGenLength+len(attr.Data)))
	binary.NativeEndian.PutUint16(frame[4:6], 1)
	copy(frame[nftnetlink.HeaderLength+nftnetlink.NFGenLength:], attr.Data)
	message, err := nftnetlink.Decode(frame)
	if err != nil {
		return nil, err
	}
	return message.Attributes, nil
}
func findAttr(attrs []nftnetlink.Attribute, t uint16) nftnetlink.Attribute {
	for _, a := range attrs {
		if a.Type&^nlaNested == t {
			return a
		}
	}
	return nftnetlink.Attribute{}
}
func stringAttr(attrs []nftnetlink.Attribute, t uint16) string {
	return strings.TrimRight(string(findAttr(attrs, t).Data), "\x00")
}
func u32(attr nftnetlink.Attribute) uint32 {
	if len(attr.Data) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(attr.Data[:4])
}
func u64(attr nftnetlink.Attribute) uint64 {
	if len(attr.Data) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(attr.Data[:8])
}
func nestedValue(attr nftnetlink.Attribute) ([]byte, error) {
	attrs, err := decodeNested(attr)
	if err != nil {
		return nil, err
	}
	value := findAttr(attrs, nftaDataValue)
	if len(value.Data) == 0 {
		return nil, errors.New("missing data value")
	}
	return append([]byte(nil), value.Data...), nil
}

var _ nftbackend.Driver = (*Driver)(nil)
