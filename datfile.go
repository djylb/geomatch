package geomatch

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"strings"
)

// datFile is the index of one version of a file and the entries compiled
// from it, which every Matcher compiled with the GeoData shares.
type datFile struct {
	info     fs.FileInfo
	data     []byte               // the contents of a file without ReadAt
	index    map[string]span      // by upper-case code
	kinds    map[string]recKind   // of the codes read so far
	ipSets   weakCache[geoIPSet]  // by code
	siteSets weakCache[domainSet] // by code and attributes
}

type span struct{ off, n int64 }

// read returns the raw record of code, read from handle, which was checked
// against, or produced, the index, so that a file replaced meanwhile cannot
// mix them up.
func (f *datFile) read(handle geoFile, name, code string) ([]byte, error) {
	if code == "" {
		return nil, errors.New("empty geodata code")
	}
	sp, ok := f.index[code]
	if !ok {
		return nil, fmt.Errorf("%w: %s in %s", ErrCodeNotFound, code, name)
	}
	rec := make([]byte, sp.n)
	if err := readFull(handle, rec, sp.off); err != nil {
		return nil, err
	}
	return rec, nil
}

// readFull fills p from r at off. io.ReaderAt may report io.EOF along with
// the last bytes; only a short read is an error, as the file was indexed at
// a size it no longer has.
func readFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	switch {
	case n == len(p):
		return nil
	case err == nil || err == io.EOF:
		return withClass(io.ErrUnexpectedEOF, ErrGeoData)
	default:
		return err
	}
}

// recKind is what a record holds: a geoip entry, or a geosite one, which
// is known for certain unless the record has no entries.
type recKind struct {
	isIP, certain bool
}

// resolveKind decides how to read a record of kind k for a rule of kind:
// as a geoip entry or a geosite one, or not at all if the rule names the
// other kind.
func resolveKind(name, code string, k recKind, kind int) (isIP bool, err error) {
	switch {
	case kind == kindIP && k.certain && !k.isIP:
		return false, fmt.Errorf("%s in %s is a geosite entry", code, name)
	case kind == kindSite && k.certain && k.isIP:
		return false, fmt.Errorf("%s in %s is a geoip entry", code, name)
	case kind == kindAny:
		return k.isIP, nil
	default:
		return kind == kindIP, nil
	}
}

func decodeRecord(name, code string, rec []byte, isIP bool) (geo GeoIP, domains []Domain, err error) {
	if isIP {
		geo, err = decodeGeoIP(rec)
	} else {
		domains, err = decodeGeoSite(rec)
	}
	if err != nil {
		return GeoIP{}, nil, fmt.Errorf("%w: %s in %s", err, code, name)
	}
	return geo, domains, nil
}

// geoFile is an open geodata file.
type geoFile interface {
	io.ReaderAt
	io.Closer
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

// sameVersion reports whether two stats describe the same version of a
// file: the same size and time and, for stats of the operating system,
// including those of an os.DirFS, the same file, so that one renamed over it
// counts as new. os.SameFile reports a stat it cannot compare as different
// even from itself.
func sameVersion(a, b fs.FileInfo) bool {
	return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && (!os.SameFile(a, a) || os.SameFile(a, b))
}

// indexDat indexes a GeoIPList or GeoSiteList: a sequence of field 1
// messages, each holding its code in field 1. Other fields are skipped, and
// the first of several entries with one code wins. It reads the
// start of every entry, and the whole entry only when its code is not there.
func indexDat(r io.ReaderAt, size int64) (map[string]span, error) {
	index := make(map[string]span)
	buf := make([]byte, 512)
	for off := int64(0); off < size; {
		n, err := r.ReadAt(buf, off)
		if n == 0 {
			if err == nil || err == io.EOF {
				err = errProto
			}
			return nil, err
		}
		head := protoReader{b: buf[:n]}
		num, typ, ok := head.next()
		if !ok {
			return nil, errProto
		}
		if typ != wireBytes {
			head.skip(typ)
			if head.err != nil {
				return nil, errProto
			}
			off += int64(n - len(head.b))
			continue
		}
		length := head.varint()
		if head.err != nil || length > maxRecord {
			return nil, errProto
		}
		body := off + int64(n-len(head.b))
		if body+int64(length) > size {
			return nil, errProto
		}
		if num == 1 {
			code, err := recordCode(r, body, int64(length), head.b)
			if err != nil {
				return nil, err
			}
			if key := upperASCII(code); key != "" {
				if _, dup := index[key]; !dup {
					index[key] = span{body, int64(length)}
				}
			}
		}
		off = body + int64(length)
	}
	return index, nil
}

// recordCode returns the code of the n-byte record at off, whose first bytes
// are in head.
func recordCode(r io.ReaderAt, off, n int64, head []byte) (string, error) {
	head = head[:min(int64(len(head)), n)]
	if code, ok := fieldBytes(head, 1); ok {
		return string(code), nil
	}
	if int64(len(head)) == n {
		return "", nil // a record without a code
	}
	rec := make([]byte, n)
	if err := readFull(r, rec, off); err != nil {
		return "", err
	}
	code, _ := fieldBytes(rec, 1)
	return string(code), nil
}

// decodeGeoIP decodes a GeoIP message: code (1), CIDRs (2) and reverse_match
// (3). Each CIDR holds the address bytes (1) and the prefix length (2);
// invalid ones are left out.
func decodeGeoIP(rec []byte) (GeoIP, error) {
	var geo GeoIP
	r := protoReader{b: rec}
	for {
		num, typ, ok := r.next()
		if !ok {
			break
		}
		switch {
		case num == 2 && typ == wireBytes:
			if p, ok := decodeCIDR(r.bytes()); ok {
				geo.Prefixes = append(geo.Prefixes, p)
			}
		case num == 3 && typ == wireVarint:
			geo.Inverse = r.varint() != 0
		default:
			r.skip(typ)
		}
	}
	return geo, r.err
}

func decodeCIDR(msg []byte) (netip.Prefix, bool) {
	var ip []byte
	var bits uint64
	r := protoReader{b: msg}
	for {
		num, typ, ok := r.next()
		if !ok {
			break
		}
		switch {
		case num == 1 && typ == wireBytes:
			ip = r.bytes()
		case num == 2 && typ == wireVarint:
			bits = r.varint()
		default:
			r.skip(typ)
		}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if r.err != nil || !ok || bits > uint64(addr.BitLen()) {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, int(bits)).Masked(), true
}

// decodeGeoSite decodes a GeoSite message: code (1) and domains (2). Each
// domain holds its type (1), value (2) and attributes (3), whose key is
// field 1; unknown types and empty values are left out.
func decodeGeoSite(rec []byte) ([]Domain, error) {
	var domains []Domain
	r := protoReader{b: rec}
	for {
		num, typ, ok := r.next()
		if !ok {
			break
		}
		if num != 2 || typ != wireBytes {
			r.skip(typ)
			continue
		}
		if d, ok := decodeDomain(r.bytes()); ok {
			domains = append(domains, d)
		}
	}
	return domains, r.err
}

func decodeDomain(msg []byte) (Domain, bool) {
	var d Domain
	var value []byte
	r := protoReader{b: msg}
	for {
		num, typ, ok := r.next()
		if !ok {
			break
		}
		switch {
		case num == 1 && typ == wireVarint:
			t := r.varint()
			if t > uint64(DomainFull) {
				return Domain{}, false
			}
			d.Type = DomainType(t)
		case num == 2 && typ == wireBytes:
			value = r.bytes()
		case num == 3 && typ == wireBytes:
			if key, ok := fieldBytes(r.bytes(), 1); ok && len(key) > 0 {
				d.Attrs = append(d.Attrs, lowerASCII(string(key)))
			}
		default:
			r.skip(typ)
		}
	}
	d.Value = strings.TrimSpace(string(value))
	if r.err != nil || d.Value == "" {
		return Domain{}, false
	}
	switch d.Type {
	case DomainRoot, DomainFull:
		d.Value = strings.TrimSuffix(strings.ToLower(d.Value), ".")
	case DomainKeyword:
		// A keyword is text, whose trailing dot, as in "google.", matters.
		d.Value = strings.ToLower(d.Value)
	}
	if d.Value == "" {
		return Domain{}, false
	}
	return d, true
}

// recordKind tells which format a record has: geoip if it has reverse_match
// (field 3) or its first entry in field 2 is a CIDR, starting with its
// address bytes, rather than a domain, starting with its type (a varint) or,
// when the type is zero and omitted, its value in field 2. A record without
// entries is taken for geoip, where it can match through !, but uncertainly.
func recordKind(rec []byte) recKind {
	r := protoReader{b: rec}
	for {
		num, typ, ok := r.next()
		if !ok {
			return recKind{isIP: true}
		}
		switch {
		case num == 3 && typ == wireVarint:
			return recKind{isIP: true, certain: true}
		case num == 2 && typ == wireBytes:
			inner := protoReader{b: r.bytes()}
			n, t, ok := inner.next()
			if !ok {
				continue
			}
			return recKind{isIP: n == 1 && t == wireBytes || n == 2 && t == wireVarint, certain: true}
		default:
			r.skip(typ)
		}
	}
}

// privatePrefixes are the private and special-use ranges that the PRIVATE
// code stands for, used when no geoip file provides it.
