package dns

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/utils"

	"github.com/dlclark/regexp2"
	"github.com/miekg/dns"
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
	bufferedLookupForFilters *utils.BufferedLookup
	// bufferedLookupForRecords *utils.BufferedLookup

	domain string

	count uint64
}

func joinNames(questions []dns.Question) string {
	var names []string
	for _, q := range questions {
		names = append(names, q.Name)
	}
	return strings.Join(names, " ")
}

func joinTypes(questions []dns.Question) string {
	var types []string
	for _, q := range questions {
		types = append(types, dns.TypeToString[q.Qtype])
	}
	return strings.Join(types, " ")
}

func (s *server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg).SetReply(req)
	m.RecursionAvailable = false

	id := atomic.AddUint64(&s.count, 1)
	startTime := time.Now()
	defer func() {
		log.Println("d"+strconv.FormatUint(id, 10), w.RemoteAddr().String(), time.Since(startTime).Round(1*time.Microsecond), RcodeTypeMap[m.Rcode], joinTypes(req.Question), joinNames(req.Question))
	}()

	for _, q := range req.Question {
		if s.bufferedLookupForFilters.Lookup(strings.ToLower(q.Name)).(bool) {
			goto allowed
		} else {
			m.Rcode = dns.RcodeRefused
			goto _end
		}
	}
	m.Rcode = dns.RcodeRefused
	goto _end
allowed:
	for _, q := range req.Question {
		for _, r := range s.records {
			if q.Qtype == r.rtype {
				if ok, _ := r.name.MatchString(strings.ToLower(q.Name)); ok {
					var ret dns.RR
					switch r.rtype {
					case dns.TypeA:
						ret = &dns.A{
							Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: r.ttl},
							A:   net.ParseIP(r.rvalue)}
					case dns.TypePTR:
						ret = &dns.PTR{
							Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: r.ttl},
							Ptr: r.rvalue}
					case dns.TypeNS:
						ret = &dns.NS{
							Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: r.ttl},
							Ns:  r.rvalue}
					case dns.TypeCNAME:
						ret = &dns.CNAME{
							Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: r.ttl},
							Target: r.rvalue}
					case dns.TypeAAAA:
						ret = &dns.AAAA{
							Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: r.ttl},
							AAAA: net.ParseIP(r.rvalue)}
					case dns.TypeTXT:
						ret = &dns.TXT{
							Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: r.ttl},
							Txt: []string{r.rvalue}}
					default:
						m.Rcode = dns.RcodeNotImplemented
						goto _end
					}
					m.Answer = append(m.Answer, ret)
				}
			}
		}
	}
	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
	}
_end:
	w.WriteMsg(m)
}

func (s *server) Listen(address string) error {
	server := &dns.Server{Addr: address, Net: "udp"}
	server.Handler = s
	return server.ListenAndServe()
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

	s.AddRecord(regexp2.MustCompile(Dnsname2Regexp(real_subdomain), 0), dns.TypeA, ip, 60)
	s.AddRecord(regexp2.MustCompile(Dnsname2Regexp(real_ptr), 0), dns.TypePTR, real_subdomain, 60)

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
	ret.bufferedLookupForFilters = utils.NewBufferedLookup(func(s string) interface{} {
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
