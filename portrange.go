package myssh

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// SelectorMode controls how PortSelector.Next distributes destination ports.
type SelectorMode int

const (
	// SelectorRandom picks an independent uniformly-random port for every packet.
	SelectorRandom SelectorMode = iota
	// SelectorRoundRobin steps through the port list in sorted order, wrapping around.
	SelectorRoundRobin
)

// ParseServerAddrWithRange parses a server address that may carry a UDP
// destination-port range, e.g.:
//
//	"1.1.1.1:36712,25000-26000"
//
// It returns the host, the PRIMARY port (the one before the first comma),
// and the sorted list of all ports.
func ParseServerAddrWithRange(raw string) (host string, primary int, ports []int, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, nil, fmt.Errorf("empty server address")
	}
	h, portSpec, splitErr := net.SplitHostPort(raw)
	if splitErr != nil {
		return "", 0, nil, fmt.Errorf("invalid address %q: %w", raw, splitErr)
	}

	// Identify primary port (first segment in comma-separated list)
	firstSeg := portSpec
	if i := strings.Index(portSpec, ","); i >= 0 {
		firstSeg = portSpec[:i]
	}
	if i := strings.Index(firstSeg, "-"); i >= 0 {
		firstSeg = firstSeg[:i]
	}
	primary, err = strconv.Atoi(strings.TrimSpace(firstSeg))
	if err != nil {
		return "", 0, nil, fmt.Errorf("invalid primary port %q: %w", firstSeg, err)
	}

	ports, err = ParsePortRangeSpec(portSpec)
	if err != nil {
		return "", 0, nil, fmt.Errorf("invalid port spec in %q: %w", raw, err)
	}
	return h, primary, ports, nil
}

// ParsePortRangeSpec expands a comma-separated port spec into a sorted,
// de-duplicated list of ports. Each segment is either a single port ("36712")
// or an inclusive range ("1024-23000"). Example: "1024-23000,25000-30000".
func ParsePortRangeSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port spec")
	}
	seen := make(map[int]struct{})
	var ports []int
	for _, seg := range strings.Split(spec, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			return nil, fmt.Errorf("empty segment in port spec %q", spec)
		}
		if i := strings.Index(seg, "-"); i >= 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(seg[:i]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(seg[i+1:]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port range %q", seg)
			}
			if lo < 1 || hi > 65535 {
				return nil, fmt.Errorf("port out of range [1,65535] in %q", seg)
			}
			if lo > hi {
				return nil, fmt.Errorf("range start %d greater than end %d in %q", lo, hi, seg)
			}
			for p := lo; p <= hi; p++ {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(seg)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", seg)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port %d out of range [1,65535]", p)
			}
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", spec)
	}
	sort.Ints(ports)
	return ports, nil
}

// FormatPortList renders an expanded port list back into a compact,
// adjacent-merged, comma-separated spec, e.g. "1024-23000,25000-30000".
func FormatPortList(ports []int) string {
	pr, err := NewPortRange(ports)
	if err != nil {
		return ""
	}
	return pr.String()
}

// portInterval is a [lo,hi] inclusive range of ports.
type portInterval struct {
	lo, hi int
}

// PortRange is a parsed, de-duplicated, sorted, adjacent-merged set of UDP
// destination ports. It is the compact representation backing PortSelector.
type PortRange struct {
	intervals []portInterval
	total     int
}

// NewPortRange builds a PortRange from an expanded port list, merging adjacent
// ports into intervals.
func NewPortRange(ports []int) (*PortRange, error) {
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports provided")
	}
	sorted := make([]int, len(ports))
	copy(sorted, ports)
	sort.Ints(sorted)
	var ivs []portInterval
	lo, hi := sorted[0], sorted[0]
	for _, p := range sorted[1:] {
		if p == hi+1 {
			hi = p
			continue
		}
		ivs = append(ivs, portInterval{lo, hi})
		lo, hi = p, p
	}
	ivs = append(ivs, portInterval{lo, hi})
	pr := &PortRange{intervals: ivs}
	for _, iv := range ivs {
		pr.total += iv.hi - iv.lo + 1
	}
	return pr, nil
}

// Total returns how many ports are in the range.
func (pr *PortRange) Total() int { return pr.total }

// Contains reports whether port falls inside the range.
//
// Used to validate the SOURCE port of an inbound reply: a server that mirrors
// the original destination port always answers from a port inside the client's
// configured range, so a reply whose source port is outside it is direct
// evidence that mirroring is not happening.
func (pr *PortRange) Contains(port int) bool {
	for _, iv := range pr.intervals {
		if port >= iv.lo && port <= iv.hi {
			return true
		}
	}
	return false
}

// PortAt returns the i-th port in flattened sorted order (0 <= i < Total()).
func (pr *PortRange) PortAt(i int) int {
	if pr.total == 0 {
		return 0
	}
	if i < 0 {
		i = 0
	}
	if i >= pr.total {
		i = pr.total - 1
	}
	for _, iv := range pr.intervals {
		n := iv.hi - iv.lo + 1
		if i < n {
			return iv.lo + i
		}
		i -= n
	}
	return pr.intervals[len(pr.intervals)-1].hi
}

// String renders the range back as a comma-separated, colon-ranged spec,
// e.g. "1024-23000,25000-30000".
func (pr *PortRange) String() string {
	if len(pr.intervals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(pr.intervals))
	for _, iv := range pr.intervals {
		if iv.lo == iv.hi {
			parts = append(parts, strconv.Itoa(iv.lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", iv.lo, iv.hi))
		}
	}
	return strings.Join(parts, ",")
}

// PortSelector spreads outgoing packets across the port range. It is intended
// to be used on the CLIENT: call Next() once per packet to obtain the
// destination port, then WriteTo the server using that port. This is the
// "any port per packet" contract that defeats per-destination-port UDP
// rate limiting.
type PortSelector struct {
	rr   atomic.Uint64
	pr   *PortRange
	mode SelectorMode
	rng  *rand.Rand
	mu   sync.Mutex
}

// NewPortSelector creates a selector over pr. The RNG seed is drawn from
// crypto/rand so the random spread does not start from a predictable sequence.
func NewPortSelector(pr *PortRange, mode SelectorMode) *PortSelector {
	var seed [8]byte
	_, _ = crand.Read(seed[:])
	return &PortSelector{
		pr:   pr,
		mode: mode,
		rng:  rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seed[:])))),
	}
}

// Next returns the destination port for the next outgoing packet. It is cheap
// and safe for concurrent use. Random mode gives an independent port each call;
// RoundRobin mode cycles through all ports in order.
//
// IMPORTANT: this must be called per packet, NOT once at connect time. The whole
// point is to vary the destination port on every datagram so the path's
// per-(dst-IP,dst-port) rate limiter sees many distinct tuples.
func (s *PortSelector) Next() int {
	if s.pr == nil || s.pr.total == 0 {
		return 0
	}
	if s.mode == SelectorRoundRobin {
		i := s.rr.Add(1) - 1
		return s.pr.PortAt(int(i % uint64(s.pr.total)))
	}
	s.mu.Lock()
	idx := s.rng.Intn(s.pr.total)
	s.mu.Unlock()
	return s.pr.PortAt(idx)
}
