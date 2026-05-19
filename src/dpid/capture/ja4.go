// Package capture - ja4.go: extract JA4 inputs from a TLS ClientHello.
//
// parse.go's parseTLSClientHello returns just SNI/ALPN. JA4 needs the full
// list of cipher suites, extensions, signature algorithms, and the
// negotiated TLS version (derived from supported_versions extension when
// present, otherwise legacy_version).
//
// We parse the same ClientHello a second time here rather than make
// parseTLSClientHello return more — the second parse is cheap (the bytes
// are still in the same buffer) and keeps the rc20.1 hot path stable.

package capture

import (
	"encoding/binary"

	"hnc.io/dpid/output"
)

// extractJA4Inputs walks a TLS ClientHello byte slice and populates
// output.JA4Inputs. Returns ok=false if the record is malformed.
//
// b must start with the TLS record header (0x16 ... 0x01 ... handshake).
func extractJA4Inputs(b []byte) (output.JA4Inputs, bool) {
	if len(b) < 5 || b[0] != 0x16 {
		return output.JA4Inputs{}, false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 4 || len(b) < 5+recLen {
		return output.JA4Inputs{}, false
	}
	hs := b[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 {
		return output.JA4Inputs{}, false
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+bodyLen {
		return output.JA4Inputs{}, false
	}
	body := hs[4 : 4+bodyLen]

	// legacy_version (2) + random (32) + session_id_len (1)
	if len(body) < 2+32+1 {
		return output.JA4Inputs{}, false
	}
	in := output.JA4Inputs{
		TLSVersion: binary.BigEndian.Uint16(body[0:2]),
	}
	p := 2 + 32
	sidLen := int(body[p])
	p++
	if len(body) < p+sidLen+2 {
		return output.JA4Inputs{}, false
	}
	p += sidLen

	// cipher suites
	csLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if csLen <= 0 || csLen%2 != 0 || len(body) < p+csLen+1 {
		return output.JA4Inputs{}, false
	}
	ciphers := make([]uint16, 0, csLen/2)
	for i := 0; i < csLen; i += 2 {
		ciphers = append(ciphers, binary.BigEndian.Uint16(body[p+i:p+i+2]))
	}
	in.Ciphers = ciphers
	p += csLen

	// compression_methods
	cmLen := int(body[p])
	p++
	if len(body) < p+cmLen+2 {
		return output.JA4Inputs{}, false
	}
	p += cmLen

	// extensions
	extLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if len(body) < p+extLen {
		return output.JA4Inputs{}, false
	}
	ext := body[p : p+extLen]

	exts := make([]uint16, 0, 16)
	for len(ext) >= 4 {
		etype := binary.BigEndian.Uint16(ext[0:2])
		elen := int(binary.BigEndian.Uint16(ext[2:4]))
		ext = ext[4:]
		if len(ext) < elen {
			break
		}
		data := ext[:elen]
		ext = ext[elen:]

		exts = append(exts, etype)

		switch etype {
		case 0x0000: // server_name
			in.HasSNI = true
		case 0x0010: // ALPN
			if len(data) >= 2 {
				list := data[2:]
				for len(list) >= 1 {
					n := int(list[0])
					if len(list) < 1+n {
						break
					}
					in.ALPNs = append(in.ALPNs, string(list[1:1+n]))
					list = list[1+n:]
				}
			}
		case 0x000d: // signature_algorithms
			if len(data) >= 2 {
				saLen := int(binary.BigEndian.Uint16(data[0:2]))
				if saLen > 0 && saLen%2 == 0 && len(data) >= 2+saLen {
					sa := make([]uint16, 0, saLen/2)
					for i := 0; i < saLen; i += 2 {
						sa = append(sa, binary.BigEndian.Uint16(data[2+i:2+i+2]))
					}
					in.SigAlgs = sa
				}
			}
		case 0x002b: // supported_versions
			// Take the lowest non-GREASE value here as the negotiated version.
			// Strictly the highest TLS 1.x value present should win.
			if len(data) >= 1 {
				svLen := int(data[0])
				if svLen >= 2 && svLen%2 == 0 && len(data) >= 1+svLen {
					best := uint16(0)
					for i := 0; i < svLen; i += 2 {
						v := binary.BigEndian.Uint16(data[1+i : 1+i+2])
						if output.IsGREASE(v) {
							continue
						}
						if v > best {
							best = v
						}
					}
					if best != 0 {
						in.TLSVersion = best
					}
				}
			}
		}
	}
	in.Extensions = exts
	return in, true
}
