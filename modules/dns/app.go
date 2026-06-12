package dns

import (
	"github.com/dlclark/regexp2"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/ngdns"
)

func init() {
	ng.RegisterFunc("dns::server", NewDnsServerFromConfig)
}

type RecordConfig struct {
	Name  string `ng:"Name,required" type:"hostname"`
	Type  string `ng:"Type,required"`
	Value string `ng:"Value,required"`
	TTL   int    `ng:"TTL" default:"300"`
}

type FilterConfig struct {
	Name      string `ng:"Name,required" type:"hostname"`
	Allowance bool   `ng:"Allowance" default:"true"`
}

type BindConfig struct {
	Name string `ng:"Name,required"`
	Addr string `ng:"Addr,required"`
}

type DnsServerConfig struct {
	AddressBindings []string       `ng:"AddressBindings"`
	Domain          string         `ng:"Domain" default:"local"`
	Records         []RecordConfig `ng:"Records"`
	Filters         []FilterConfig `ng:"Filters"`
	Binds           []BindConfig   `ng:"Binds"`
}

func NewDnsServerFromConfig(cfg DnsServerConfig) (any, error) {
	srv := NewServer()
	srv.SetDomain(cfg.Domain)

	for _, record := range cfg.Records {
		name := regexp2.MustCompile(ngdns.Dnsname2Regexp(record.Name), regexp2.RE2)
		srv.AddRecord(name, ngdns.DnsStringTypeToInt(record.Type), record.Value, uint32(record.TTL))
	}

	for _, filter := range cfg.Filters {
		name := regexp2.MustCompile(ngdns.Dnsname2Regexp(filter.Name), regexp2.RE2)
		if err := srv.AddFilter(name, filter.Allowance); err != nil {
			return nil, err
		}
	}

	for _, bind := range cfg.Binds {
		if err := srv.AddRecordWithIP(bind.Name, bind.Addr); err != nil {
			return nil, err
		}
	}

	for _, listen := range cfg.AddressBindings {
		go srv.Listen(listen)
	}

	return srv, nil
}

var _ ng.Stopper = (*server)(nil)
