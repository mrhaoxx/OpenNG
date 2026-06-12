package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dlclark/regexp2"
	mdns "github.com/miekg/dns"
	"github.com/mrhaoxx/OpenNG/pkg/lookup"
	"github.com/mrhaoxx/OpenNG/pkg/ngdns"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"

	zlog "github.com/rs/zerolog/log"
)

type record struct {
	rtype  uint16
	rvalue string
	ttl    uint32
	name   *regexp2.Regexp
}
type filter struct {
	name      *regexp2.Regexp
	allowance bool
}

type server struct {
	records                  []*record
	filters                  []*filter
	bufferedLookupForFilters *lookup.BufferedLookup[bool]

	domain string

	count uint64

	muServers sync.Mutex
	servers   []*mdns.Server
}

func joinNames(questions []mdns.Question) string {
	var names []string
	for _, q := range questions {
		names = append(names, q.Name)
	}
	return strings.Join(names, " ")
}

func joinTypes(questions []mdns.Question) string {
	var types []string
	for _, q := range questions {
		types = append(types, mdns.TypeToString[q.Qtype])
	}
	return strings.Join(types, " ")
}

func (s *server) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	m := new(mdns.Msg).SetReply(req)
	m.RecursionAvailable = false

	id := atomic.AddUint64(&s.count, 1)
	startTime := time.Now()
	defer func() {
		zlog.Info().
			Str("type", "dns/request").
			Uint64("id", id).
			Str("remote", w.RemoteAddr().String()).
			Dur("duration", time.Since(startTime)).
			Str("rcode", ngdns.RcodeTypeMap[m.Rcode]).
			Str("types", joinTypes(req.Question)).
			Str("names", joinNames(req.Question)).
			Msg("")
	}()

	for _, q := range req.Question {
		if s.bufferedLookupForFilters.Lookup(strings.ToLower(q.Name)) {
			goto allowed
		} else {
			m.Rcode = mdns.RcodeRefused
			goto _end
		}
	}
	m.Rcode = mdns.RcodeRefused
	goto _end
allowed:
	for _, q := range req.Question {
		for _, r := range s.records {
			if q.Qtype == r.rtype {
				if ok, _ := r.name.MatchString(strings.ToLower(q.Name)); ok {
					var ret mdns.RR
					switch r.rtype {
					case mdns.TypeA:
						ret = &mdns.A{
							Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: r.ttl},
							A:   net.ParseIP(r.rvalue)}
					case mdns.TypePTR:
						ret = &mdns.PTR{
							Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypePTR, Class: mdns.ClassINET, Ttl: r.ttl},
							Ptr: r.rvalue}
					case mdns.TypeNS:
						ret = &mdns.NS{
							Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: r.ttl},
							Ns:  r.rvalue}
					case mdns.TypeCNAME:
						ret = &mdns.CNAME{
							Hdr:    mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: r.ttl},
							Target: r.rvalue}
					case mdns.TypeAAAA:
						ret = &mdns.AAAA{
							Hdr:  mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: r.ttl},
							AAAA: net.ParseIP(r.rvalue)}
					case mdns.TypeTXT:
						ret = &mdns.TXT{
							Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: r.ttl},
							Txt: []string{r.rvalue}}
					default:
						m.Rcode = mdns.RcodeNotImplemented
						goto _end
					}
					m.Answer = append(m.Answer, ret)
				}
			}
		}
	}
	if len(m.Answer) == 0 {
		m.Rcode = mdns.RcodeNameError
	}
_end:
	w.WriteMsg(m)
}

// Listen binds address with SO_REUSEPORT, so a newer generation can bind
// alongside this one and the kernel hands traffic over when either side
// closes its socket — no rebind gap, and a failed reload's half-built
// generation gives the address straight back to the running one.
func (s *server) Listen(address string) error {
	lc := ngnet.ReusePortListenConfig()
	pc, err := lc.ListenPacket(context.Background(), "udp", address)
	if err != nil {
		zlog.Error().Str("type", "dns/listen").Str("addr", address).Err(err).Msg("dns bind failed")
		return err
	}

	srv := &mdns.Server{PacketConn: pc, Handler: s}

	s.muServers.Lock()
	s.servers = append(s.servers, srv)
	s.muServers.Unlock()

	return srv.ActivateAndServe()
}

// Stop shuts down all DNS listeners owned by this server instance and closes
// their sockets (Shutdown only unblocks reads on a caller-provided conn).
func (s *server) Stop() {
	s.muServers.Lock()
	owned := s.servers
	s.servers = nil
	s.muServers.Unlock()

	for _, srv := range owned {
		srv.Shutdown()
		if srv.PacketConn != nil {
			srv.PacketConn.Close()
		}
	}
}

func (s *server) AddFilter(name *regexp2.Regexp, allowance bool) error {
	s.filters = append(s.filters, &filter{name: name, allowance: allowance})
	return nil
}
func (s *server) AddRecord(name *regexp2.Regexp, rtype uint16, rvalue string, ttl uint32) {
	s.records = append(s.records, &record{name: name, rtype: rtype, rvalue: rvalue, ttl: ttl})
}

func (s *server) AddRecordWithIP(name string, ip string) error {
	real_subdomain := name + "." + s.domain + "."
	real_ptr := reverseIP(ip) + ".in-addr.arpa." + s.domain + "."

	s.AddRecord(regexp2.MustCompile(ngdns.Dnsname2Regexp(real_subdomain), 0), mdns.TypeA, ip, 60)
	s.AddRecord(regexp2.MustCompile(ngdns.Dnsname2Regexp(real_ptr), 0), mdns.TypePTR, real_subdomain, 60)

	return nil
}
func (s *server) SetDomain(domain string) *server {
	s.domain = domain
	return s
}

func NewServer() (ret *server) {
	ret = &server{
		records: []*record{},
		filters: []*filter{},
		count:   0,
	}
	ret.bufferedLookupForFilters = lookup.NewBufferedLookup(func(s string) bool {
		for _, r := range ret.filters {
			if ok, _ := r.name.MatchString(s); ok {
				if r.allowance {
					return true
				} else {
					return false
				}
			}
		}
		return false
	})

	return
}

func reverseIP(ipAddr string) string {
	segments := strings.Split(ipAddr, ".")

	for i, j := 0, len(segments)-1; i < j; i, j = i+1, j-1 {
		segments[i], segments[j] = segments[j], segments[i]
	}

	return strings.Join(segments, ".")
}
