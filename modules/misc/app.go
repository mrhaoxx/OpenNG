package misc

import (
	"errors"
	"fmt"
	"time"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/auth"
	"github.com/mrhaoxx/OpenNG/modules/tcp"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/rs/zerolog/log"
)

func init() {
	registerAcmeFileProvider()
	registerIpFilter()
	registerHostFilter()
	registerGitlabAuth()
}

func registerAcmeFileProvider() {
	ng.Register("http::acme::fileprovider",
		func(spec *ng.ArgNode) (any, error) {
			hosts := spec.MustGet("Hosts").ToStringList()
			wwwroot := spec.MustGet("WWWRoot").ToString()
			provider := &AcmeWebRoot{
				AllowedHosts: hosts,
				WWWRoot:      wwwroot,
			}

			log.Debug().Strs("hosts", hosts).Str("wwwroot", wwwroot).Msg("new acme file provider")
			return provider, nil
		}, ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"Hosts": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {Type: "hostname"},
					},
				},
				"WWWRoot": {Type: "string", Required: true},
			},
		},
	)
}

func registerIpFilter() {
	ng.Register("ipfilter",
		func(spec *ng.ArgNode) (any, error) {
			allowed := spec.MustGet("allowedcidrs").ToStringList()
			blocked := spec.MustGet("blockedcidrs").ToStringList()
			next := spec.MustGet("next")

			filter := NewIPFilter(allowed, blocked)

			if next != nil {
				nextHandler, ok := next.Value.(tcp.Service)
				if !ok {
					return nil, errors.New("ptr is not a http.HttpHandler")
				}
				filter.next = nextHandler
			}

			log.Debug().Strs("allowedcidrs", allowed).Msg("new ip filter")

			return filter, nil
		}, ng.Assert{
			Type:     "map",
			Required: true,
			Desc:     "filter connections based on source IP CIDR ranges",
			Sub: ng.AssertMap{
				"blockedcidrs": {
					Type: "list",
					Desc: "list of CIDR ranges to block",
					Sub: ng.AssertMap{
						"_": {Type: "string", Desc: "CIDR notation (e.g. 192.168.1.0/24)"},
					},
				},
				"allowedcidrs": {
					Type: "list",
					Desc: "list of CIDR ranges to allow",
					Sub: ng.AssertMap{
						"_": {Type: "string", Desc: "CIDR notation (e.g. 192.168.1.0/24)"},
					},
				},
				"next": {
					Type:    "ptr",
					Default: nil,
					Desc:    "next service handler if no CIDR match is found",
				},
			},
		},
	)
}

func registerHostFilter() {
	ng.Register("hostfilter",
		func(spec *ng.ArgNode) (any, error) {
			allowedHosts := spec.MustGet("allowedhosts").ToStringList()
			next := spec.MustGet("next")

			filter := &HostFilter{AllowedHosts: allowedHosts}

			if next != nil {
				nextHandler, ok := next.Value.(tcp.Service)
				if !ok {
					return nil, errors.New("ptr is not a http.HttpHandler")
				}
				filter.next = nextHandler
			}

			log.Debug().Strs("allowedhosts", allowedHosts).Msg("new host filter")

			return filter, nil
		}, ng.Assert{
			Type:     "map",
			Required: true,
			Desc:     "filter connections based on HTTP Host header or TLS SNI",
			Sub: ng.AssertMap{
				"allowedhosts": {
					Type: "list",
					Desc: "list of allowed hostnames",
					Sub: ng.AssertMap{
						"_": {Type: "string", Desc: "hostname to allow"},
					},
				},
				"next": {
					Type:    "ptr",
					Default: nil,
					Desc:    "next service handler if hostname is not allowed",
				},
			},
		},
	)
}

func registerGitlabAuth() {
	ng.Register("gitlabauth",
		func(spec *ng.ArgNode) (any, error) {
			gitlabURL := spec.MustGet("gitlab_url").ToURL()
			cacheTTL := spec.MustGet("cache_ttl").ToDuration()
			matchUsernames := spec.MustGet("matchusernames").ToStringList()
			prefix := spec.MustGet("prefix").ToString()
			next := spec.MustGet("next")

			backend := &GitlabEnhancedPolicydBackend{
				gitlabUrl:     gitlabURL.String(),
				ttl:           cacheTTL,
				matchUsername: groupexp.MustCompileRegexp(matchUsernames),
				cache:         make(map[string]*SSHKeyCache),
				prefix:        prefix,
			}

			if next != nil {
				nextBackend, ok := next.Value.(auth.PolicyBackend)
				if !ok {
					return nil, errors.New("ptr is not a auth.PolicyBackend" + fmt.Sprintf("%T", next.Value))
				}
				backend.PolicyBackend = nextBackend
			}

			log.Debug().
				Str("gitlaburl", gitlabURL.String()).
				Dur("cachettl", backend.ttl).
				Strs("matchusernames", backend.matchUsername.String()).
				Bool("has_next", next != nil).
				Str("prefix", prefix).
				Msg("new gitlab auth")
			return backend, nil
		}, ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"gitlab_url": {Type: "url", Required: true},
				"cache_ttl":  {Type: "duration", Default: time.Duration(10 * time.Second)},
				"matchusernames": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {Type: "string"},
					},
				},
				"prefix": {
					Type:    "string",
					Default: "",
				},
				"next": {
					Type:    "ptr",
					Default: nil,
				},
			},
		},
	)
}
