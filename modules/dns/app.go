package dns

import (
	ng "github.com/mrhaoxx/OpenNG"
	ngdns "github.com/mrhaoxx/OpenNG/pkg/dns"
)

func init() {
	registerServer()
}

func registerServer() {
	ng.Register("dns::server",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"AddressBindings": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {Type: "string"},
					},
				},
				"Domain": {
					Type:    "string",
					Default: "local",
				},
				"Records": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"Name": {
									Type:     "hostmatch",
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
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"Name": {
									Type:     "hostmatch",
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
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
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
		ng.Assert{
			Type: "ptr",
		},
		func(spec *ng.ArgNode) (any, error) {
			records := spec.MustGet("Records").ToList()
			filters := spec.MustGet("Filters").ToList()
			binds := spec.MustGet("Binds").ToList()

			listens := spec.MustGet("AddressBindings").ToStringList()

			server := NewServer()
			server.SetDomain(spec.MustGet("Domain").ToString())

			for _, record := range records {
				name := record.MustGet("Name").ToRegexp()
				typ := record.MustGet("Type").ToString()
				value := record.MustGet("Value").ToString()
				ttl := record.MustGet("TTL").ToInt()

				server.AddRecord(name, ngdns.DnsStringTypeToInt(typ), value, uint32(ttl))
			}

			for _, filter := range filters {
				name := filter.MustGet("Name").ToRegexp()
				allowance := filter.MustGet("Allowance").ToBool()

				if err := server.AddFilter(name, allowance); err != nil {
					return nil, err
				}
			}

			for _, bind := range binds {
				name := bind.MustGet("Name").ToString()
				addr := bind.MustGet("Addr").ToString()

				if err := server.AddRecordWithIP(name, addr); err != nil {
					return nil, err
				}
			}

			for _, listen := range listens {
				go server.Listen(listen)
			}

			return server, nil
		},
	)
}
