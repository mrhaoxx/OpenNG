package dns

import (
	"github.com/dlclark/regexp2"
	ngmodules "github.com/mrhaoxx/OpenNG/modules"
	"github.com/rs/zerolog/log"
)

func init() {
	registerServer()
}

func registerServer() {
	ngmodules.Register("dns::server",
		func(spec *ngmodules.ArgNode) (any, error) {
			records := spec.MustGet("Records").ToList()
			filters := spec.MustGet("Filters").ToList()
			binds := spec.MustGet("Binds").ToList()

			listens := spec.MustGet("AddressBindings").ToStringList()

			server := NewServer()
			server.SetDomain(spec.MustGet("Domain").ToString())

			for _, record := range records {
				name := record.MustGet("Name").ToString()
				typ := record.MustGet("Type").ToString()
				value := record.MustGet("Value").ToString()
				ttl := record.MustGet("TTL").ToInt()

				server.AddRecord(regexp2.MustCompile(Dnsname2Regexp(name), 0), DnsStringTypeToInt(typ), value, uint32(ttl))

				log.Debug().
					Str("name", name).
					Str("type", typ).
					Str("value", value).
					Int("ttl", ttl).
					Msg("new dns record")
			}

			for _, filter := range filters {
				name := filter.MustGet("Name").ToString()
				allowance := filter.MustGet("Allowance").ToBool()

				if err := server.AddFilter(regexp2.MustCompile(Dnsname2Regexp(name), 0), allowance); err != nil {
					return nil, err
				}

				log.Debug().
					Str("name", name).
					Bool("allowance", allowance).
					Msg("new dns filter")
			}

			for _, bind := range binds {
				name := bind.MustGet("Name").ToString()
				addr := bind.MustGet("Addr").ToString()

				if err := server.AddRecordWithIP(name, addr); err != nil {
					return nil, err
				}

				log.Debug().
					Str("name", name).
					Str("addr", addr).
					Msg("new dns bind")
			}

			for _, listen := range listens {
				go server.Listen(listen)
				log.Debug().Str("addr", listen).Msg("dns listen")
			}

			return server, nil
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"AddressBindings": {
					Type: "list",
					Sub: ngmodules.AssertMap{
						"_": {Type: "string"},
					},
				},
				"Domain": {
					Type:    "string",
					Default: "local",
				},
				"Records": {
					Type: "list",
					Sub: ngmodules.AssertMap{
						"_": {
							Type: "map",
							Sub: ngmodules.AssertMap{
								"Name": {
									Type:     "string",
									Required: true,
								},
								"Type": {
									Type:     "string",
									Required: true,
								},
								"Value": {
									Type:     "string",
									Required: true,
								},
								"TTL": {
									Type:    "int",
									Default: 300,
								},
							},
						},
					},
				},
				"Filters": {
					Type: "list",
					Sub: ngmodules.AssertMap{
						"_": {
							Type: "map",
							Sub: ngmodules.AssertMap{
								"Name": {
									Type:     "string",
									Required: true,
								},
								"Allowance": {
									Type:    "bool",
									Default: true,
								},
							},
						},
					},
				},
				"Binds": {
					Type: "list",
					Sub: ngmodules.AssertMap{
						"_": {
							Type: "map",
							Sub: ngmodules.AssertMap{
								"Name": {
									Type:     "string",
									Required: true,
								},
								"Addr": {
									Type:     "string",
									Required: true,
								},
							},
						},
					},
				},
			},
		},
	)
}
