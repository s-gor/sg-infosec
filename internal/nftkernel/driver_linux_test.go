//go:build linux

package nftkernel

import (
	"context"
	"testing"

	"github.com/s-gor/sg-infosec/internal/nftnetlink"
	"github.com/s-gor/sg-infosec/internal/nftschema"
)

type captureTransport struct{ request []byte }

func (c *captureTransport) Exchange(_ context.Context, request []byte) ([]byte, error) {
	c.request = append([]byte(nil), request...)
	return nil, nil
}

func TestPanelSetUsesConcatFlagDescriptionAndOneDatagram(t *testing.T) {
	capture := &captureTransport{}
	driver := New(capture)
	set := nftschema.Expected().Sets[0]
	if err := driver.ApplySchema(context.Background(), []nftschema.Operation{{Kind: nftschema.CreateSet, Name: set.Name, Set: &set}}); err != nil {
		t.Fatal(err)
	}
	messages, err := nftnetlink.DecodeMany(capture.request)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 3 {
		t.Fatalf("messages=%d", len(messages))
	}
	attrs := messages[1].Attributes
	if flags := u32(findAttr(attrs, nftaSetFlags)); flags&(nftSetTimeout|nftSetConcat) != (nftSetTimeout | nftSetConcat) {
		t.Fatalf("flags=%#x", flags)
	}
	if !concatMatches(findAttr(attrs, nftaSetDesc), []int{4, 2}) {
		t.Fatal("concat description mismatch")
	}
	if keyType := u32(findAttr(attrs, nftaSetKeyType)); keyType != uint32(7<<6|13) {
		t.Fatalf("key type=%d, want ipv4_addr . inet_service", keyType)
	}
	if keyLen := u32(findAttr(attrs, nftaSetKeyLen)); keyLen != 8 {
		t.Fatalf("key length=%d, want aligned concat length 8", keyLen)
	}
	desc, err := decodeNested(findAttr(attrs, nftaSetDesc))
	if err != nil {
		t.Fatal(err)
	}
	items, err := decodeNested(findAttr(desc, nftaSetDescConcat))
	if err != nil {
		t.Fatal(err)
	}
	for index, item := range items {
		if item.Type != nftaListElem|nlaNested {
			t.Fatalf("concat field %d type=%#x, want NFTA_LIST_ELEM|NLA_F_NESTED", index, item.Type)
		}
	}
}

func TestSetKeyLengthsIncludeConcatAlignment(t *testing.T) {
	tests := []struct {
		name string
		want uint32
	}{
		{name: "panel_v4", want: 8},
		{name: "panel_v6", want: 20},
		{name: "ssh_v4", want: 4},
		{name: "ssh_v6", want: 16},
	}
	sets := nftschema.Expected().Sets
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var set nftschema.Set
			for _, candidate := range sets {
				if candidate.Name == tc.name {
					set = candidate
					break
				}
			}
			message, err := newSet(1, set, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got := u32(findAttr(message.Attributes, nftaSetKeyLen)); got != tc.want {
				t.Fatalf("key length=%d, want %d", got, tc.want)
			}
		})
	}
}

func TestSetKeyTypesMatchNftablesDatatypes(t *testing.T) {
	tests := []struct {
		name string
		want uint32
	}{
		{name: "panel_v4", want: uint32(7<<6 | 13)},
		{name: "panel_v6", want: uint32(8<<6 | 13)},
		{name: "ssh_v4", want: uint32(7)},
		{name: "ssh_v6", want: uint32(8)},
	}
	sets := nftschema.Expected().Sets
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var set nftschema.Set
			for _, candidate := range sets {
				if candidate.Name == tc.name {
					set = candidate
					break
				}
			}
			message, err := newSet(1, set, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got := u32(findAttr(message.Attributes, nftaSetKeyType)); got != tc.want {
				t.Fatalf("key type=%d, want %d", got, tc.want)
			}
		})
	}
}

func TestSemanticDecoderAcceptsKernelRegisterNormalization(t *testing.T) {
	rule := nftschema.Expected().Rules[2]
	expressions, err := encodeRule(rule, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded := nested(nftaRuleExpressions, expressions)
	got, port, err := decodeRuleExpressions(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != rule.Expression || port != 22 {
		t.Fatalf("got=%q port=%d", got, port)
	}
	// The kernel may rewrite NFT_REG32_00 (8) to legacy NFT_REG_1 (1).
	rewriteRegisters(expressions, 8, 1)
	encoded = nested(nftaRuleExpressions, expressions)
	got, port, err = decodeRuleExpressions(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != rule.Expression || port != 22 {
		t.Fatalf("normalized got=%q port=%d", got, port)
	}
}

func rewriteRegisters(items []nftnetlink.Attribute, from, to uint32) {
	for i := range items {
		sub, _ := decodeNested(items[i])
		dataAttr := findAttr(sub, nftaExprData)
		data, _ := decodeNested(dataAttr)
		changed := false
		for j := range data {
			base := data[j].Type &^ nlaNested
			if base == nftaPayloadDreg || base == nftaMetaDreg || base == nftaCmpSreg || base == nftaLookupSreg {
				if u32(data[j]) == from {
					data[j] = u32Attr(data[j].Type, to)
					changed = true
				}
			}
		}
		if changed {
			for j := range sub {
				if sub[j].Type&^nlaNested == nftaExprData {
					sub[j] = nested(nftaExprData, data)
				}
			}
			items[i] = nested(nftaListElem, sub)
		}
	}
}

func TestSemanticDecoderRejectsPanelRuleWithoutPortPayload(t *testing.T) {
	rule := nftschema.Expected().Rules[0]
	expressions, err := encodeRule(rule, nil)
	if err != nil {
		t.Fatal(err)
	}
	// meta, cmp, address payload, PORT payload, lookup, verdict
	expressions = append(expressions[:3], expressions[4:]...)
	if _, _, err := decodeRuleExpressions(nested(nftaRuleExpressions, expressions)); err == nil {
		t.Fatal("decoder accepted panel lookup without concatenated port payload")
	}
}

func TestSemanticDecoderRejectsSSHRuleWithWrongAddressPayload(t *testing.T) {
	rule := nftschema.Expected().Rules[2]
	expressions, err := encodeRule(rule, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Replace IPv4 source offset 12 with destination offset 16.
	sub, err := decodeNested(expressions[2])
	if err != nil {
		t.Fatal(err)
	}
	data, err := decodeNested(findAttr(sub, nftaExprData))
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		if data[i].Type&^nlaNested == nftaPayloadOffset {
			data[i] = u32Attr(nftaPayloadOffset, 16)
		}
	}
	for i := range sub {
		if sub[i].Type&^nlaNested == nftaExprData {
			sub[i] = nested(nftaExprData, data)
		}
	}
	expressions[2] = nested(nftaListElem, sub)
	if _, _, err := decodeRuleExpressions(nested(nftaRuleExpressions, expressions)); err == nil {
		t.Fatal("decoder accepted SSH rule matching destination instead of source")
	}
}
