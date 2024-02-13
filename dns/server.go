package dns

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrhaoxx/OpenNG/log"

	"github.com/dlclark/regexp2"
	"github.com/miekg/dns"
)

type record struct {
	rr   dns.RR
	name *regexp2.Regexp
}
type filter struct {
	name      *regexp2.Regexp
	allowance bool
}

type server struct {
	records      []*record
	records_lock sync.RWMutex
	filters      []*filter
	upstreamDNS  string

	count uint64
}

func (s *server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	id := atomic.AddUint64(&s.count, 1)
	startTime := time.Now()
	defer func() {
		log.Println("d"+strconv.FormatUint(id, 10), w.RemoteAddr().String(), time.Since(startTime).Round(1*time.Microsecond), m.Rcode, m.Question[0].Name, m.Answer)
	}()

	for _, q := range req.Question {
		for _, r := range s.filters {
			if ok, _ := r.name.MatchString(q.Name); ok {
				if r.allowance {
					m.Rcode = dns.RcodeSuccess
					break
				} else {
					m.Rcode = dns.RcodeRefused
					goto _end
				}
			}
		}
	}
	{
		c := new(dns.Client)
		in, _, _ := c.Exchange(req, s.upstreamDNS)
		w.WriteMsg(in)
		return
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

// func (s *server) AddRecord(domain string, rr dns.RR) error {
// 	r, err := regexp2.Compile(domain, 0)
// 	if err != nil {
// 		return err
// 	}
// 	s.records_lock.Lock()
// 	s.records = append(s.records, &record{rr: rr, domain: r})
// 	s.records_lock.Unlock()
// 	return nil
// }

func NewServer(upstreamDNS string) *server {
	return &server{
		records:     []*record{},
		filters:     []*filter{},
		upstreamDNS: upstreamDNS,
	}
}
