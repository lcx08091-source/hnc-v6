// Package leakguard implements real-time cleartext privacy leak detection for
// HNC v6.0.0 Vector.
//
// jsonscan.go uses Go 1.27's standard encoding/json/jsontext streaming token
// state machine (pooled via sync.Pool, bounded to MaxJSONDepth=12) to extract
// nested key-value pairs and [{"k":"...","v":"..."}] style KV arrays with zero
// map[string]any reflection allocations.
package leakguard

import (
	"bytes"
	"encoding/json/jsontext"
	"strings"
	"sync"
)

const (
	// MaxJSONDepth caps structural nesting depth to defeat deeply nested JSON bombs.
	MaxJSONDepth  = 12
	maxJSONTokens = 2048
)

type pooledJSONDecoder struct {
	reader bytes.Reader
	dec    *jsontext.Decoder
}

var jsonDecoderPool = sync.Pool{
	New: func() any {
		p := &pooledJSONDecoder{}
		p.dec = jsontext.NewDecoder(
			&p.reader,
			jsontext.AllowDuplicateNames(true),
			jsontext.AllowInvalidUTF8(true),
		)
		return p
	},
}

type jsonFrame struct {
	isObj      bool
	expectName bool
	curKey     string
	kvKey      string
	kvVal      string
	hasKVKey   bool
	hasKVVal   bool
}

// ScanJSON streams tokens from a JSON request body (even if truncated at 4KB)
// and invokes visit(key, value) for every scalar member and KV-pair object.
// Strings have \uXXXX escapes decoded automatically by jsontext.Token.String().
func ScanJSON(data []byte, visit func(key, val string)) {
	if visit == nil || len(data) == 0 {
		return
	}
	scanJSONAtDepth(data, 0, visit)
}

func scanJSONAtDepth(data []byte, baseDepth int, visit func(key, val string)) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 2 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return
	}
	if baseDepth >= MaxJSONDepth {
		return
	}

	p := jsonDecoderPool.Get().(*pooledJSONDecoder)
	p.reader.Reset(trimmed)
	p.dec.Reset(
		&p.reader,
		jsontext.AllowDuplicateNames(true),
		jsontext.AllowInvalidUTF8(true),
	)
	defer func() {
		p.reader.Reset(nil)
		jsonDecoderPool.Put(p)
	}()

	var stack [MaxJSONDepth + 2]jsonFrame
	sp := 0

	for steps := 0; steps < maxJSONTokens; steps++ {
		inValuePos := sp == 0 || !stack[sp].isObj || !stack[sp].expectName
		if inValuePos && sp > 0 && baseDepth+sp >= MaxJSONDepth {
			pk := p.dec.PeekKind()
			if pk == jsontext.Kind('{') || pk == jsontext.Kind('[') {
				if stack[sp].isObj {
					stack[sp].expectName = true
				}
				if err := p.dec.SkipValue(); err != nil {
					break
				}
				continue
			}
		}

		tok, err := p.dec.ReadToken()
		if err != nil {
			// If truncated mid-object after a complete {"k":"...","v":"..."} pair,
			// flush any pending KV pair accumulated on the stack before exiting.
			for d := sp; d >= 1; d-- {
				if stack[d].isObj && stack[d].hasKVKey && stack[d].hasKVVal && stack[d].kvKey != "" {
					visit(stack[d].kvKey, stack[d].kvVal)
				}
			}
			break
		}

		kind := tok.Kind()

		if sp > 0 && stack[sp].isObj {
			if kind == jsontext.Kind('}') {
				if stack[sp].hasKVKey && stack[sp].hasKVVal && stack[sp].kvKey != "" {
					visit(stack[sp].kvKey, stack[sp].kvVal)
				}
				sp--
				if sp == 0 {
					break
				}
				continue
			}
			if stack[sp].expectName {
				if kind != jsontext.Kind('"') {
					break
				}
				stack[sp].curKey = strings.Clone(tok.String())
				stack[sp].expectName = false
				continue
			}
		} else if sp > 0 && !stack[sp].isObj && kind == jsontext.Kind(']') {
			sp--
			if sp == 0 {
				break
			}
			continue
		}

		// Value position (root, array element, or object member value).
		memberKey := ""
		if sp > 0 && stack[sp].isObj {
			memberKey = stack[sp].curKey
			stack[sp].expectName = true
		}

		switch kind {
		case jsontext.Kind('{'):
			if baseDepth+sp >= MaxJSONDepth {
				break
			}
			sp++
			stack[sp] = jsonFrame{isObj: true, expectName: true}

		case jsontext.Kind('['):
			if baseDepth+sp >= MaxJSONDepth {
				break
			}
			sp++
			stack[sp] = jsonFrame{isObj: false}

		case jsontext.Kind('"'), jsontext.Kind('0'), jsontext.Kind('t'), jsontext.Kind('f'):
			val := strings.Clone(tok.String())
			if memberKey != "" {
				visit(memberKey, val)
				if kind == jsontext.Kind('"') && isKVKeyDescriptor(memberKey) {
					stack[sp].kvKey = val
					stack[sp].hasKVKey = true
				} else if isKVValueDescriptor(memberKey) {
					stack[sp].kvVal = val
					stack[sp].hasKVVal = true
				}
			} else if kind == jsontext.Kind('"') {
				visit("", val)
			}

			// Handle double-serialized JSON string payloads (e.g. {"data":"{\"imei\":\"...\"}"}).
			if kind == jsontext.Kind('"') && len(val) >= 2 && baseDepth+sp < MaxJSONDepth {
				inner := strings.TrimSpace(val)
				if len(inner) >= 2 && (inner[0] == '{' || inner[0] == '[') {
					scanJSONAtDepth([]byte(inner), baseDepth+sp, visit)
				}
			}
		}
	}
}

func isKVKeyDescriptor(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "k", "key", "name", "field", "param", "attr":
		return true
	default:
		return false
	}
}

func isKVValueDescriptor(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "v", "val", "value", "data", "content":
		return true
	default:
		return false
	}
}
