package auth

import (
	"errors"

	netgate "github.com/mrhaoxx/OpenNG"
	authbackend "github.com/mrhaoxx/OpenNG/modules/auth/backend"
	"github.com/mrhaoxx/OpenNG/modules/dns"
	"github.com/rs/zerolog/log"
	gossh "golang.org/x/crypto/ssh"
)

// "builtin::auth::manager":

//	"builtin::auth::backend::file": {
//		Type: "map",
//		Sub: AssertMap{
//			"users": {
//				Type: "list",
//				Sub: AssertMap{
//					"_": {
//						Type: "map",
//						Sub: AssertMap{
//							"name": {
//								Type:     "string",
//								Required: true,
//								Desc:     "Username",
//							},
//							"PasswordHash": {
//								Type:    "string",
//								Default: "",
//								Desc:    "Password hash using bcrypt",
//							},
//							"AllowForwardProxy": {
//								Type:    "bool",
//								Default: false,
//								Desc:    "Allow user to use forward proxy",
//							},
//							"SSHAuthorizedKeys": {
//								Type: "list",
//								Sub: AssertMap{
//									"_": {Type: "string"},
//								},
//								Desc: "SSH authorized keys",
//							},
//						},
//					},
//				},
//			},
//		},
//	},
//
//	"builtin::auth::backend::ldap": {
//		Type: "map",
//		Sub: AssertMap{
//			"Url":        {Type: "url", Required: true},
//			"SearchBase": {Type: "string", Required: true},
//			"BindDN":     {Type: "string", Required: true},
//			"BindPW":     {Type: "string", Required: true},
//		},
//	},
//
//	"builtin::auth::policyd": {
//		Type: "map",
//		Sub: AssertMap{
//			"Policies": {
//				Type: "list",
//				Sub: AssertMap{
//					"_": {
//						Type: "map",
//						Sub: AssertMap{
//							"name":      {Type: "string", Required: true},
//							"Allowance": {Type: "bool", Required: true},
//							"Users": {
//								Type: "list",
//								Desc: "matching users,empty STRING means ALL, empty LIST means NONE",
//								Sub: AssertMap{
//									"_": {Type: "string"},
//								},
//							},
//							"Hosts": {
//								Type: "list",
//								Desc: "matching Hosts, empty means none",
//								Sub: AssertMap{
//									"_": {Type: "hostname", Desc: DescHostnameFormat},
//								},
//							},
//							"Paths": {
//								Type: "list",
//								Desc: "matching Paths, empty means all",
//								Sub: AssertMap{
//									"_": {Type: "string"},
//								},
//							},
//						},
//					},
//				},
//			},
//			"backends": {
//				Type: "list",
//				Sub: AssertMap{
//					"_": {Type: "ptr"},
//				},
//			},
//		},
//	},
//
//	"builtin::auth::knocked": {
//		Type: "map",
//		Sub: AssertMap{
//			"timeout": {
//				Type:    "duration",
//				Default: time.Duration(3 * time.Second),
//			},
//		},
//	},

func init() {
	netgate.Register("auth::manager",
		func(spec *netgate.ArgNode) (any, error) {
			backends := spec.MustGet("backends").ToList()
			var authmethods []AuthHandle

			for _, backend := range backends {
				b, ok := backend.Value.(AuthHandle)
				if !ok {
					return nil, errors.New("ptr is not a auth.AuthHandle")
				}
				authmethods = append(authmethods, b)
			}

			log.Debug().Int("backend_count", len(authmethods)).Msg("new auth manager")

			manager := NewAuthMgr(authmethods,
				netgate.MustCompileRegexp(dns.Dnsnames2Regexps(spec.MustGet("allowhosts").ToStringList())))

			return manager, nil
		}, netgate.Assert{
			Type: "map",
			Sub: netgate.AssertMap{
				"backends": {
					Type: "list",
					Sub: netgate.AssertMap{
						"_": {Type: "ptr"},
					},
				},
				"allowhosts": {
					Type:    "list",
					Default: []*netgate.ArgNode{{Type: "hostname", Value: "*"}},
					Sub: netgate.AssertMap{
						"_": {Type: "hostname"},
					},
				},
			},
		},
	)

	netgate.Register("auth::backend::file",
		func(spec *netgate.ArgNode) (any, error) {
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
		}, netgate.Assert{
			Type: "map",
			Sub: netgate.AssertMap{
				"users": {
					Type: "list",
					Sub: netgate.AssertMap{
						"_": {
							Type: "map",
							Sub: netgate.AssertMap{
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
									Sub: netgate.AssertMap{
										"_": {Type: "string"},
									},
								},
							},
						},
					},
				},
			},
		},
	)

	netgate.Register("auth::backend::ldap",
		func(spec *netgate.ArgNode) (any, error) {
			url := spec.MustGet("Url").ToURL()
			searchBase := spec.MustGet("SearchBase").ToString()
			bindDN := spec.MustGet("BindDN").ToString()
			bindPW := spec.MustGet("BindPW").ToString()

			log.Debug().
				Str("searchbase", searchBase).
				Str("binddn", bindDN).
				Msg("new auth ldap backend")

			return authbackend.NewLDAPBackend(url, searchBase, bindDN, bindPW), nil
		}, netgate.Assert{
			Type: "map",
			Sub: netgate.AssertMap{
				"Url":        {Type: "url", Required: true},
				"SearchBase": {Type: "string", Required: true},
				"BindDN":     {Type: "string", Required: true},
				"BindPW":     {Type: "string", Required: true},
			},
		},
	)

	netgate.Register("auth::policyd",
		func(spec *netgate.ArgNode) (any, error) {
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
				b, ok := backend.Value.(PolicyBackend)
				if !ok {
					return nil, errors.New("ptr is not a auth.PolicyBackend")
				}
				policyBackends = append(policyBackends, b)

				log.Debug().
					Type("backend", backend.Value).
					Msg("new auth policy backend")
			}

			policyd.AddBackends(policyBackends)

			return policyd, nil
		}, netgate.Assert{
			Type: "map",
			Sub: netgate.AssertMap{
				"Policies": {
					Type: "list",
					Sub: netgate.AssertMap{
						"_": {
							Type: "map",
							Sub: netgate.AssertMap{
								"name":      {Type: "string", Required: true},
								"Allowance": {Type: "bool", Required: true},
								"Users": {
									Type: "list",
									Desc: "matching users,empty STRING means ALL, empty LIST means NONE",
									Sub: netgate.AssertMap{
										"_": {Type: "string"},
									},
								},
								"Hosts": {
									Type: "list",
									Desc: "matching Hosts, empty means none",
									Sub: netgate.AssertMap{
										"_": {Type: "hostname", Desc: netgate.DescHostnameFormat},
									},
								},
								"Paths": {
									Type: "list",
									Desc: "matching Paths, empty means all",
									Sub: netgate.AssertMap{
										"_": {Type: "string"},
									},
								},
							},
						},
					},
				},
				"backends": {
					Type: "list",
					Sub: netgate.AssertMap{
						"_": {Type: "ptr"},
					},
				},
			},
		},
	)

}
