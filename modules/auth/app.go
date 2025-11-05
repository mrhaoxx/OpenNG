package auth

import (
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	authbackend "github.com/mrhaoxx/OpenNG/modules/auth/backend"
	"github.com/mrhaoxx/OpenNG/modules/dns"
	http "github.com/mrhaoxx/OpenNG/modules/http"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/rs/zerolog/log"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	ng.Register("auth::manager",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"backends": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {Type: "ptr", Impls: []reflect.Type{
							ng.TypeOf[AuthHandle](),
						}},
					},
				},
				"allowhosts": {
					Type:    "list",
					Default: []*ng.ArgNode{{Type: "hostname", Value: "*"}},
					Sub: ng.AssertMap{
						"_": {Type: "hostname"},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[http.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			backends := spec.MustGet("backends").ToList()
			var authmethods []AuthHandle

			for _, backend := range backends {
				authmethods = append(authmethods, backend.Value.(AuthHandle))
			}

			log.Debug().Int("backend_count", len(authmethods)).Msg("new auth manager")

			manager := NewAuthMgr(authmethods,
				groupexp.MustCompileRegexp(dns.Dnsnames2Regexps(spec.MustGet("allowhosts").ToStringList())))

			return manager, nil
		},
	)

	ng.Register("auth::backend::file",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"users": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"name": {
									Type:     "string",
									Required: true,
									Desc:     "Username",
								},
								"PasswordHash": {
									Type:    "string",
									Default: "",
									Desc:    "Password hash using bcrypt",
								},
								"AllowForwardProxy": {
									Type:    "bool",
									Default: false,
									Desc:    "Allow user to use forward proxy",
								},
								"SSHAuthorizedKeys": {
									Type: "list",
									Desc: "SSH authorized keys",
									Sub: ng.AssertMap{
										"_": {Type: "string"},
									},
								},
							},
						},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[PolicyBackend](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			users := spec.MustGet("users").ToList()
			backend := authbackend.NewFileBackend()

			for _, user := range users {
				name := user.MustGet("name").ToString()
				pw := user.MustGet("PasswordHash").ToString()
				allowfp := user.MustGet("AllowForwardProxy").ToBool()
				sshkeys := user.MustGet("SSHAuthorizedKeys").ToStringList()

				var parsedKeys []gossh.PublicKey
				for _, key := range sshkeys {
					pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key))
					if err != nil {
						return nil, err
					}
					parsedKeys = append(parsedKeys, pk)
				}

				backend.SetUser(name, pw, allowfp, parsedKeys, false)

				log.Debug().
					Str("name", name).
					Bool("allow_forward_proxy", allowfp).
					Int("ssh_authorized_keys", len(sshkeys)).
					Msg("new auth file user")
			}

			return backend, nil
		},
	)

	ng.Register("auth::backend::ldap",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"Url":        {Type: "url", Required: true},
				"SearchBase": {Type: "string", Required: true},
				"BindDN":     {Type: "string", Required: true},
				"BindPW":     {Type: "string", Required: true},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[PolicyBackend](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			url := spec.MustGet("Url").ToURL()
			searchBase := spec.MustGet("SearchBase").ToString()
			bindDN := spec.MustGet("BindDN").ToString()
			bindPW := spec.MustGet("BindPW").ToString()

			log.Debug().
				Str("searchbase", searchBase).
				Str("binddn", bindDN).
				Msg("new auth ldap backend")

			return authbackend.NewLDAPBackend(url, searchBase, bindDN, bindPW), nil
		},
	)

	ng.Register("auth::policyd",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"Policies": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"name":      {Type: "string", Required: true},
								"Allowance": {Type: "bool", Required: true},
								"Users": {
									Type: "list",
									Desc: "matching users,empty STRING means ALL, empty LIST means NONE",
									Sub: ng.AssertMap{
										"_": {Type: "string"},
									},
								},
								"Hosts": {
									Type: "list",
									Desc: "matching Hosts, empty means none",
									Sub: ng.AssertMap{
										"_": {Type: "hostname"},
									},
								},
								"Paths": {
									Type: "list",
									Desc: "matching Paths, empty means all",
									Sub: ng.AssertMap{
										"_": {Type: "string"},
									},
								},
							},
						},
					},
				},
				"backends": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {Type: "ptr", Impls: []reflect.Type{
							ng.TypeOf[PolicyBackend](),
						}},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[AuthHandle](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			policies := spec.MustGet("Policies").ToList()
			backends := spec.MustGet("backends").ToList()

			policyd := NewPBAuth()

			for _, policy := range policies {
				name := policy.MustGet("name").ToString()
				allowance := policy.MustGet("Allowance").ToBool()
				users := policy.MustGet("Users").ToStringList()
				hosts := policy.MustGet("Hosts").ToStringList()
				paths := policy.MustGet("Paths").ToStringList()

				if err := policyd.AddPolicy(name, allowance, users, hosts, paths); err != nil {
					return nil, err
				}

				log.Debug().
					Str("name", name).
					Bool("allowance", allowance).
					Strs("users", users).
					Strs("hosts", hosts).
					Strs("paths", paths).
					Msg("new auth policy")
			}

			var policyBackends []PolicyBackend
			for _, backend := range backends {
				policyBackends = append(policyBackends, backend.Value.(PolicyBackend))
				log.Debug().
					Type("backend", backend.Value).
					Msg("new auth policy backend")
			}

			policyd.AddBackends(policyBackends)

			return policyd, nil
		},
	)

}
